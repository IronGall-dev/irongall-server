// Command irongalld is the irongall.dev server.
//
//	irongalld serve -boxes-table T -msgs-table T -accounts-table T -bucket B -names NAMES [-listen addr] [options] [limits]
//	irongalld serve --dev [-listen addr] [limits]
//	irongalld account create -accounts-table T [-id NAME] [-unmetered]
//	irongalld account key -accounts-table T -account ID -uses N -ttl D
//	irongalld account drop -boxes-table T -accounts-table T -account ID -box ADDR
//	irongalld limits clear -socket PATH -ip ADDR
//
// The first keeps state in three DynamoDB tables, boxes, messages and
// accounts, and an S3 Express One Zone directory bucket (PROTOCOL-SERVER.md §7),
// with AWS credentials from the usual chain; it answers 503 until its stream
// followers are positioned, loads each box into memory on its first use, and
// exits if a stream follower loses its place, since a restart rebuilds
// memory.
//
// --dev keeps everything in memory, with no AWS: the honest server every
// client tests against. Nothing survives a restart.
// It takes a pass made for any name, unless -names is given.
//
// account is the operator's hand on accounts (PROTOCOL.md §6.5) until
// accounts have users who log in: create one, mint an adopt key for it, or
// drop a box from it.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/IronGall-dev/irongall-client/protocol"
	"github.com/IronGall-dev/irongall-server/internal/server"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func main() {
	log.SetOutput(server.Redacting(os.Stderr)) // so net/http's own lines, and the last error's, are redacted as the server's are
	var err error
	switch {
	case len(os.Args) >= 2 && os.Args[1] == "serve":
		err = serve(os.Args[2:])
	case len(os.Args) >= 3 && os.Args[1] == "account":
		err = account(os.Args[2], os.Args[3:])
	case len(os.Args) >= 3 && os.Args[1] == "limits":
		err = limits(os.Args[2], os.Args[3:])
	default:
		fmt.Fprintln(os.Stderr, "usage: irongalld serve (-boxes-table T -msgs-table T -accounts-table T -bucket B -names NAMES | --dev) [-listen addr] [options] [limits]")
		fmt.Fprintln(os.Stderr, "       irongalld account (create | key | drop) [flags]")
		fmt.Fprintln(os.Stderr, "       irongalld limits clear -socket PATH -ip ADDR")
		fmt.Fprintln(os.Stderr, "       irongalld limits top -socket PATH -limit NAME [-n COUNT]")
		os.Exit(2)
	}
	if err != nil {
		log.Fatal(err)
	}
}

func serve(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	dev := fs.Bool("dev", false, "keep everything in memory, with no AWS")
	listen := fs.String("listen", "127.0.0.1:8080", "address to listen on")
	boxes := fs.String("boxes-table", "", "the DynamoDB table of boxes")
	msgs := fs.String("msgs-table", "", "the DynamoDB table of messages")
	accts := fs.String("accounts-table", "", "the DynamoDB table of accounts")
	bucket := fs.String("bucket", "", "the S3 Express One Zone directory bucket")
	names := fs.String("names", "", "comma-separated names clients call this server by: the host of its URL, lowercase, with its port only when that is not the scheme's default; a pass is taken only for one of them")
	idTypes := fs.String("identity-types", strings.Join(protocol.IdentityTypes(), ","), "comma-separated identity key types a box may register with, of those this build verifies; "+protocol.IdentityEd25519+" is always one of them")
	region := fs.String("region", "us-east-1", "the AWS region")
	boxCache := fs.Int("box-cache", 10000, "box records held in memory, for sends and reads of a box")
	streamEvery := fs.Duration("stream-interval", time.Second, "how often each stream shard is read")
	proxies := fs.String("trusted-proxy", "", "comma-separated CIDRs whose CF-Connecting-IP names the client: the proxy in front, if any")
	l := server.DefaultLimits()
	fs.IntVar(&l.MaxSize, "max-size", l.MaxSize, "cap on a ciphertext, bytes: a send reads its body to it")
	fs.IntVar(&l.AccountMaxSize, "account-max-size", l.AccountMaxSize, "the most an account can lift -max-size to, bytes (up to -max-size: nothing)")
	fs.IntVar(&l.PairCap, "pair-cap", l.PairCap, "unacked messages per sender and box (0: off)")
	fs.IntVar(&l.BoxCap, "box-cap", l.BoxCap, "messages per box (0: off)")
	fs.IntVar(&l.SendsPerDay, "sends-per-day", l.SendsPerDay, "sends per sender a day: that many at once, then one back each day divided by it (0: off)")
	fs.IntVar(&l.RenewalsPerDay, "renewals-per-day", l.RenewalsPerDay, "prekey renewals per box a day, as -sends-per-day (0: off)")
	fs.IntVar(&l.RetiredKept, "retired-kept", l.RetiredKept, "retired prekeys a box record keeps, newest first (0: all live ones)")
	fs.IntVar(&l.PollBurst, "poll-burst", l.PollBurst, "polls a box may make at once (0: off)")
	fs.DurationVar(&l.PollRefill, "poll-refill", l.PollRefill, "one more poll each")
	fs.IntVar(&l.PollAfter, "poll-after", l.PollAfter, "poll interval told to clients, seconds")
	fs.IntVar(&l.RegistrationsPerHour, "registrations-per-hour", l.RegistrationsPerHour, "registrations per IPv4 address or IPv6 /64 (0: off)")
	fs.IntVar(&l.RangeRegistrationsPerHour, "range-registrations-per-hour", l.RangeRegistrationsPerHour, "registrations per IPv6 /48, beside -registrations-per-hour (0: off)")
	fs.IntVar(&l.SendsPerMinutePerIP, "sends-per-minute-per-ip", l.SendsPerMinutePerIP, "pre-auth sends per IP (0: off)")
	fs.IntVar(&l.MissesPerMinute, "misses-per-minute", l.MissesPerMinute, "calls per IP that named no box or carried nothing that verified (0: off)")
	fs.IntVar(&l.RequestBurst, "request-burst", l.RequestBurst, "per IP, at once: every call with no pass, and every request no route matches, the link page and the site's pages among them; a budget for floods alone (0: off)")
	fs.DurationVar(&l.RequestRefill, "request-refill", l.RequestRefill, "one more such request each")
	fs.IntVar(&l.ReceiveBurst, "receive-burst", l.ReceiveBurst, "new messages a box takes at once, from all senders together (0: off)")
	fs.DurationVar(&l.ReceiveRefill, "receive-refill", l.ReceiveRefill, "one more new message each")
	fs.IntVar(&l.DrainBurst, "drain-burst", l.DrainBurst, "a box's first fetches of held messages, at once: the new mail it takes out (0: off)")
	fs.DurationVar(&l.DrainRefill, "drain-refill", l.DrainRefill, "one more first fetch each")
	fs.IntVar(&l.CallBurst, "call-burst", l.CallBurst, "a box's calls with its pass that no other budget counts, at once (0: off)")
	fs.DurationVar(&l.CallRefill, "call-refill", l.CallRefill, "one more such call each")
	fs.IntVar(&l.CertificatesPerDay, "certificates-per-day", l.CertificatesPerDay, "per box a day, as -sends-per-day: renewals under a later certificate, but for one that replaces a revoked certificate (0: off)")
	fs.IntVar(&l.CertificateRevocationsPerDay, "certificate-revocations-per-day", l.CertificateRevocationsPerDay, "per box a day, as -sends-per-day: raises of its revocation of certificates (0: off)")
	fs.IntVar(&l.ACLEntries, "acl-entries", l.ACLEntries, "the most entries a box's ACL holds, its two lists together (0: off)")
	fs.DurationVar(&l.BodyTimeout, "body-timeout", l.BodyTimeout, "how long a request body, or a response, may take before one more second for each -body-min-rate bytes moved; also the longest wait for the one large read (0: off)")
	fs.IntVar(&l.BodyMinRate, "body-min-rate", l.BodyMinRate, "bytes a second a body must keep up, as Apache's RequestReadTimeout MinRate (0: off)")
	fs.IntVar(&l.HeadBytes, "max-header-bytes", l.HeadBytes, "the most of a request's head, its request line and headers, the server reads: what the longest call needs, its pass at the longest a pass can be, and no more; net/http answers a longer one 431 (0: net/http's default)")
	adminSocket := fs.String("admin-socket", "", "a Unix socket for the operator's commands (irongalld limits): 0600 from the moment this process makes it, never on the API's listener (empty: none)")
	idle := fs.Duration("idle-timeout", 75*time.Second, "how long an idle keep-alive connection stays open (nginx's default as a server): above the idle timeout of a proxy in front, which may otherwise reuse a connection this one has just closed")
	metricsListen := fs.String("metrics-listen", "", "address to serve the operator's metrics on, at /metrics in Prometheus' text format: a listener of its own, never the API's (empty: none)")
	siteDir := fs.String("site", "", "a directory of pages to serve at every path outside /v1/ and /to/, each at its own path and an index at its directory's, read once at start (empty: none; those paths are 404)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	logger := log.New(server.Redacting(os.Stderr), "", log.LstdFlags|log.LUTC)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cfg := server.Config{Limits: l, Log: logger}
	var reg *prometheus.Registry
	if *metricsListen != "" {
		reg = prometheus.NewRegistry()
		reg.MustRegister(collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
		cfg.Metrics = server.NewMetrics(reg)
	}
	for _, n := range strings.Split(*names, ",") {
		if n = strings.TrimSpace(n); n == "" {
			continue
		}
		if err := protocol.CheckServerName(n); err != nil {
			return fmt.Errorf("-names: %q: %w", n, err)
		}
		cfg.Names = append(cfg.Names, n)
	}
	for _, t := range strings.Split(*idTypes, ",") {
		if t = strings.TrimSpace(t); t == "" {
			continue
		}
		if !slices.Contains(protocol.IdentityTypes(), t) {
			return fmt.Errorf("-identity-types: %q is not a key type this build verifies: %s", t, strings.Join(protocol.IdentityTypes(), ", "))
		}
		cfg.IdentityTypes = append(cfg.IdentityTypes, t)
	}
	if !slices.Contains(cfg.IdentityTypes, protocol.IdentityEd25519) {
		return fmt.Errorf("-identity-types: %s must be one of them: it is the type every client makes and verifies", protocol.IdentityEd25519)
	}
	for _, c := range strings.Split(*proxies, ",") {
		if c = strings.TrimSpace(c); c == "" {
			continue
		}
		p, err := netip.ParsePrefix(c)
		if err != nil {
			return fmt.Errorf("-trusted-proxy: %w", err)
		}
		cfg.TrustedProxies = append(cfg.TrustedProxies, p)
	}
	if *siteDir != "" {
		site, err := server.LoadSite(*siteDir)
		if err != nil {
			return fmt.Errorf("-site: %w", err)
		}
		cfg.Site = site
	}
	var start func() error
	switch {
	case *dev:
		if *boxes != "" || *msgs != "" || *accts != "" || *bucket != "" {
			return errors.New("--dev takes no tables or -bucket")
		}
		cfg.Store = server.NewMemStore(time.Now)
		logger.Printf("irongalld --dev on %s (in memory: nothing survives a restart)", *listen)
	case *boxes == "" || *msgs == "" || *accts == "" || *bucket == "" || len(cfg.Names) == 0:
		return errors.New("name -boxes-table, -msgs-table, -accounts-table, -bucket and -names, or run --dev")
	default:
		awsCfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(*region))
		if err != nil {
			return err
		}
		cfg.Metrics.InstrumentAWS(&awsCfg)
		fatal := make(chan error, 1)
		store := server.NewDynamoStore(server.DynamoConfig{
			AWS:            awsCfg,
			BoxesTable:     *boxes,
			MsgsTable:      *msgs,
			AccountsTable:  *accts,
			Bucket:         *bucket,
			BoxCache:       *boxCache,
			StreamInterval: *streamEvery,
			Log:            logger,
			Fatal:          func(err error) { fatal <- err },
			Metrics:        cfg.Metrics,
		})
		cfg.Store, cfg.Ready = store, store.Ready
		start = func() error {
			t := time.Now()
			if err := store.Start(ctx); err != nil {
				return fmt.Errorf("following %s, %s and %s: %w", *boxes, *msgs, *accts, err)
			}
			logger.Printf("following the streams of %s, %s and %s (ready in %s); boxes load on first use", *boxes, *msgs, *accts, time.Since(t).Round(time.Millisecond))
			go func() {
				if err := <-fatal; err != nil {
					logger.Printf("%v: exiting, so a restart rebuilds memory", err)
					stop()
				}
			}()
			return nil
		}
		logger.Printf("irongalld on %s: tables %s, %s and %s, bucket %s", *listen, *boxes, *msgs, *accts, *bucket)
	}

	api := server.New(cfg)
	if *adminSocket != "" {
		l, err := listenAdmin(*adminSocket)
		if err != nil {
			return err
		}
		admin := &http.Server{Handler: api.AdminHandler(), ReadHeaderTimeout: 10 * time.Second}
		go func() { _ = admin.Serve(l) }()
		defer admin.Close() //nolint:errcheck // the process is ending
		logger.Printf("operator commands on %s", *adminSocket)
	}
	if reg != nil {
		mux := http.NewServeMux()
		mux.Handle("GET /metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
		metrics := &http.Server{Addr: *metricsListen, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
		l, err := net.Listen("tcp", *metricsListen)
		if err != nil {
			return fmt.Errorf("-metrics-listen: %w", err)
		}
		go func() { _ = metrics.Serve(l) }()
		defer metrics.Close() //nolint:errcheck // the process is ending
		logger.Printf("metrics on %s", *metricsListen)
	}
	srv := apiServer(*listen, api.Handler(), l, *idle)
	srv.ConnState = cfg.Metrics.ConnState
	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServe() }()
	if start != nil {
		if err := start(); err != nil {
			return err
		}
	}
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	shut, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(shut); err != nil {
		return err
	}
	if start != nil && !cfg.Ready() {
		return errors.New("stopped: memory could not be shown current")
	}
	return nil
}

// apiServer is the API's HTTP server, at addr: it reads a request's head in
// at most ten seconds and to l.HeadBytes, no further, before any handler,
// and so before any count, sees it (LIMITS.md, rule 1).
func apiServer(addr string, h http.Handler, l server.Limits, idle time.Duration) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: 10 * time.Second,
		MaxHeaderBytes:    l.HeadBytes,
		IdleTimeout:       idle,
	}
}

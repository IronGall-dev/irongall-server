// Command irongalld is the irongall.dev server.
//
//	irongalld serve -boxes-table T -msgs-table T -accounts-table T -bucket B -keys FILE -names NAMES [-listen addr] [options] [limits]
//	irongalld serve --dev [-listen addr] [limits]
//	irongalld account create -accounts-table T [-id NAME] [-unmetered]
//	irongalld account key -accounts-table T -keys FILE -account ID -uses N -ttl D
//	irongalld account drop -boxes-table T -accounts-table T -account ID -box ADDR
//
// The first keeps state in three DynamoDB tables, boxes, messages and
// accounts, and an S3 Express One Zone directory bucket (PROTOCOL-SERVER.md §7),
// with AWS credentials from the usual chain; it answers 503 until its stream
// followers are positioned, loads each box into memory on its first use, and
// exits if a stream follower loses its place, since a restart rebuilds
// memory.
//
// --dev keeps everything in memory, with no AWS: the honest server every
// client tests against. Nothing survives a restart, the server key included.
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
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/IronGall-dev/irongall-client/protocol"
	"github.com/IronGall-dev/irongall-server/internal/server"
	"github.com/aws/aws-sdk-go-v2/config"
)

func main() {
	var err error
	switch {
	case len(os.Args) >= 2 && os.Args[1] == "serve":
		err = serve(os.Args[2:])
	case len(os.Args) >= 3 && os.Args[1] == "account":
		err = account(os.Args[2], os.Args[3:])
	default:
		fmt.Fprintln(os.Stderr, "usage: irongalld serve (-boxes-table T -msgs-table T -accounts-table T -bucket B -keys FILE -names NAMES | --dev) [-listen addr] [options] [limits]")
		fmt.Fprintln(os.Stderr, "       irongalld account (create | key | drop) [flags]")
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
	keysFile := fs.String("keys", "", "the server keys file (they make adopt keys), mode 0600: lines of \"<kid> <base64 of 32 bytes>\"")
	names := fs.String("names", "", "comma-separated names clients call this server by: the host of its URL, lowercase, with its port if it has one; a pass is taken only for one of them")
	region := fs.String("region", "us-east-1", "the AWS region")
	boxCache := fs.Int("box-cache", 10000, "box records held in memory, for sends and /identity")
	streamEvery := fs.Duration("stream-interval", time.Second, "how often each stream shard is read")
	proxies := fs.String("trusted-proxy", "", "comma-separated CIDRs whose CF-Connecting-IP names the client: the proxy in front, if any")
	l := server.DefaultLimits()
	fs.IntVar(&l.MaxSize, "max-size", l.MaxSize, "cap on the decoded ciphertext, bytes")
	fs.IntVar(&l.AccountMaxSize, "account-max-size", l.AccountMaxSize, "the most an account can lift -max-size to, bytes (up to -max-size: nothing)")
	fs.IntVar(&l.PairCap, "pair-cap", l.PairCap, "unacked messages per sender and box (0: off)")
	fs.IntVar(&l.BoxCap, "box-cap", l.BoxCap, "messages per box (0: off)")
	fs.IntVar(&l.SendsPerDay, "sends-per-day", l.SendsPerDay, "sends per sender per UTC day (0: off)")
	fs.IntVar(&l.RenewalsPerDay, "renewals-per-day", l.RenewalsPerDay, "prekey renewals per box per UTC day (0: off)")
	fs.IntVar(&l.RetiredKept, "retired-kept", l.RetiredKept, "retired prekeys a box record keeps, newest first (0: all live ones)")
	fs.IntVar(&l.PollBurst, "poll-burst", l.PollBurst, "polls a box may make at once (0: off)")
	fs.DurationVar(&l.PollRefill, "poll-refill", l.PollRefill, "one more poll each")
	fs.IntVar(&l.PollAfter, "poll-after", l.PollAfter, "poll interval told to clients, seconds")
	fs.IntVar(&l.RegistrationsPerHour, "registrations-per-hour", l.RegistrationsPerHour, "registrations per IPv4 address or IPv6 /64 (0: off)")
	fs.IntVar(&l.SendsPerMinutePerIP, "sends-per-minute-per-ip", l.SendsPerMinutePerIP, "pre-auth sends per IP (0: off)")
	fs.IntVar(&l.MissesPerMinute, "misses-per-minute", l.MissesPerMinute, "reads of the boxes table that find no box, per IP (0: off)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	logger := log.New(os.Stderr, "", log.LstdFlags|log.LUTC)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cfg := server.Config{Limits: l, Log: logger}
	for _, n := range strings.Split(*names, ",") {
		if n = strings.TrimSpace(n); n == "" {
			continue
		}
		if err := protocol.CheckServerName(n); err != nil {
			return fmt.Errorf("-names: %q: %w", n, err)
		}
		cfg.Names = append(cfg.Names, n)
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
	var start func() error
	switch {
	case *dev:
		if *boxes != "" || *msgs != "" || *accts != "" || *bucket != "" || *keysFile != "" {
			return errors.New("--dev takes no tables, -bucket or -keys")
		}
		keys, err := server.NewDevKeys()
		if err != nil {
			return err
		}
		cfg.Store, cfg.Keys = server.NewMemStore(time.Now), keys
		logger.Printf("irongalld --dev on %s (in memory: nothing survives a restart)", *listen)
	case *boxes == "" || *msgs == "" || *accts == "" || *bucket == "" || *keysFile == "" || len(cfg.Names) == 0:
		return errors.New("name -boxes-table, -msgs-table, -accounts-table, -bucket, -keys and -names, or run --dev")
	default:
		keys, err := server.LoadKeys(*keysFile)
		if err != nil {
			return err
		}
		awsCfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(*region))
		if err != nil {
			return err
		}
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
		})
		cfg.Store, cfg.Keys, cfg.Ready = store, keys, store.Ready
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

	srv := &http.Server{
		Addr:              *listen,
		Handler:           server.New(cfg).Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
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

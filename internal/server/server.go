// Package server is irongalld's HTTP API (PROTOCOL.md §3–§6, the status map
// in §13) over a Store.
package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/IronGall-dev/irongall-client/protocol"
)

// Config configures a Server.
type Config struct {
	Store  Store
	Limits Limits
	Now    func() time.Time // time.Now if nil
	Log    *log.Logger      // no access log if nil
	// Ready, when set, reports whether the store has loaded its memory; until
	// it has, every call is answered 503 rather than wrong (ARCHITECTURE.md
	// § Startup).
	Ready func() bool
	// TrustedProxies are the peers whose CF-Connecting-IP header names the
	// client: behind a proxy every request arrives from the proxy's
	// address. From any other peer the header is ignored. None: the
	// peer is always the client.
	TrustedProxies []netip.Prefix
	// Names are the names clients call this server by: the host of its URL,
	// lowercase, with its port only when that is not the scheme's default. A
	// pass is taken only on a request whose Host, written so, is one of them
	// (PROTOCOL.md §6.1b). None: any Host
	// is taken, which is for the dev server and tests only, since a pass
	// made for another server would then pass here.
	Names []string
	// IdentityTypes are the identity key types this server registers: some
	// of protocol.IdentityTypes, ssh-ed25519 among them, since that is the
	// one every client makes and verifies (PROTOCOL.md §2). None: every type
	// this build verifies.
	IdentityTypes []string
	// Site, when set, is served at every path outside /v1/ and /to/, the
	// API's and the link page's (LoadSite). None: those paths are 404.
	Site *Site
	// Metrics, when set, count what the server does and refuses
	// (NewMetrics). None: nothing is counted.
	Metrics *Metrics
}

// Server is the API.
type Server struct {
	store   Store
	limits  Limits
	now     func() time.Time
	log     *log.Logger
	ready   func() bool
	proxies []netip.Prefix
	names   []string
	// identityTypes are the identity key types a box may register with.
	identityTypes []string
	site          *Site
	metrics       *Metrics
	// longestPath is the longest path this server serves (served): the
	// access log writes a method or a path any longer as its length alone.
	longestPath int

	polls     *buckets // per box
	pages     *buckets // per box: list pages after the first
	repeats   *buckets // per box: fetches of a message already fetched
	regs      *buckets // per IP
	rangeRegs *buckets // per IPv6 /48: registrations, beside regs
	sendIPs   *buckets // per IP
	misses    *buckets // per IP: reads of the boxes table that found no box, and checks that failed
	requests  *buckets // per IP: every call with no pass this process has checked, and every request no route matches
	calls     *buckets // per box: its calls with its pass that no other budget counts
	receives  *buckets // per box: new messages it takes
	drained   *buckets // per box: its first fetches of held messages
	sends     *buckets // per sender, a number a day
	renewals  *buckets // per box, a number a day: renewals under its current certificate
	certs     *buckets // per box, a number a day: renewals under a later certificate, which only its identity can make
	raises    *buckets // per box, a number a day: raises of its revocation of certificates, which only its identity can make
	// inFlight counts the sends let past the pair and box caps and not yet
	// stored, by the recipient's first byte (reserveCaps).
	inFlight [256]inFlight
	// drains is the cursor each box was handed last (list).
	drains drains
	// reads are the reads of box records in flight (lookup).
	reads reads
	// largeRead is the one allowance for reading a send past the free
	// cap's size, held until the send is answered. Only a sender whose own
	// cap is larger ever asks for it.
	largeRead chan struct{}

	// passes remembers the pass each box showed last (pass.go).
	passes *passes
}

// New returns a Server.
func New(c Config) *Server {
	s := &Server{
		store:         c.Store,
		limits:        c.Limits,
		now:           c.Now,
		log:           redacting(c.Log),
		ready:         c.Ready,
		proxies:       c.TrustedProxies,
		names:         c.Names,
		identityTypes: c.IdentityTypes,
		site:          c.Site,
		metrics:       c.Metrics,
		polls:         newBuckets(string(protocol.QuotaPolls), c.Limits.PollBurst, c.Limits.PollRefill),
		pages:         c.Limits.continuations(),
		repeats:       newBuckets(string(protocol.CodeRefetchSpent), c.Limits.PollBurst, c.Limits.PollRefill),
		regs:          perPeriod(string(protocol.QuotaRegistrations), c.Limits.RegistrationsPerHour, time.Hour),
		rangeRegs:     perPeriod(string(protocol.QuotaRegistrationsRange), c.Limits.RangeRegistrationsPerHour, time.Hour),
		sendIPs:       perPeriod(string(protocol.QuotaSendsBeforePass), c.Limits.SendsPerMinutePerIP, time.Minute),
		misses:        perPeriod(string(protocol.QuotaMisses), c.Limits.MissesPerMinute, time.Minute),
		requests:      newBuckets(string(protocol.QuotaRequests), c.Limits.RequestBurst, c.Limits.RequestRefill),
		calls:         newBuckets(string(protocol.QuotaCalls), c.Limits.CallBurst, c.Limits.CallRefill),
		receives:      newBuckets(string(protocol.CodeMailboxBusy), c.Limits.ReceiveBurst, c.Limits.ReceiveRefill),
		drained:       newBuckets(string(protocol.CodeFetchPaced), c.Limits.DrainBurst, c.Limits.DrainRefill),
		sends:         perPeriod(string(protocol.QuotaSends), c.Limits.SendsPerDay, day),
		renewals:      perPeriod(string(protocol.QuotaRenewals), c.Limits.RenewalsPerDay, day),
		certs:         perPeriod(string(protocol.QuotaCertificates), c.Limits.CertificatesPerDay, day),
		raises:        perPeriod(string(protocol.QuotaCertificateRevocations), c.Limits.CertificateRevocationsPerDay, day),
		largeRead:     make(chan struct{}, 1),
		passes:        newPasses(),
	}
	if s.now == nil {
		s.now = time.Now
	}
	if len(s.identityTypes) == 0 {
		s.identityTypes = protocol.IdentityTypes()
	}
	s.longestPath = s.served()
	s.metrics.watch(s)
	return s
}

// served is the length of the longest path this server serves: a route's or
// the link page's, each wildcard an address or a message id of 64 hex
// characters, or a site's page.
func (s *Server) served() int {
	n := s.site.longestPath()
	patterns := []string{linkRoute}
	for _, r := range s.routes() {
		patterns = append(patterns, r.pattern)
	}
	for _, p := range patterns {
		_, path, _ := strings.Cut(p, " ")
		n = max(n, len(wildcard.ReplaceAllString(path, strings.Repeat("0", 64))))
	}
	return n
}

// wildcard is a wildcard in a route's pattern.
var wildcard = regexp.MustCompile(`\{[^}]*\}`)

// route is one of the API's routes: its pattern, its handler, and whose pass
// this process has checked makes a call on it its box's at the gate.
type route struct {
	pattern string
	h       func(http.ResponseWriter, *http.Request) error
	pass    passRule
}

// passRule is whose checked pass makes a call its box's at the gate, on a
// route that checks the pass before it does anything else.
type passRule int

const (
	// passNone: none. The route reads its pass, if it takes one, after its
	// body, or takes none.
	passNone passRule = iota
	// passAnyBox: the pass's own box's, whichever box the path names: the
	// read of a box and a send, which a box makes to another.
	passAnyBox
	// passPathBox: only the pass of the box the path names: the calls a box
	// makes about itself, which answer that box's state before they look at
	// a pass (IronGall-dev/irongall-server#74).
	passPathBox
)

// routes are the API's, each the client repo's api/openapi.yaml gives
// (TestTheRoutesAreTheDescriptions).
func (s *Server) routes() []route {
	return []route{
		{"GET /v1/{addr}", s.getBox, passAnyBox},
		{"PUT /v1/{addr}", s.register, passNone}, // its pass is read after its body
		{"DELETE /v1/{addr}", s.deleteBox, passPathBox},
		{"PUT /v1/{addr}/prekey", s.prekey, passNone}, // its pass is read after its body
		{"PUT /v1/{addr}/revocations", s.revoke, passNone},
		{"GET /v1/{addr}/revocations", s.getRevocations, passNone},
		{"PUT /v1/{addr}/acl", s.putACL, passPathBox},
		{"GET /v1/{addr}/acl", s.getACL, passPathBox},
		{"PUT /v1/{addr}/account", s.adopt, passPathBox},
		{"DELETE /v1/{addr}/account", s.leave, passPathBox},
		{"POST /v1/{addr}/messages", s.send, passAnyBox},
		{"GET /v1/{addr}/messages", s.list, passPathBox},
		{"GET /v1/{addr}/messages/{id}", s.fetch, passPathBox},
		{"DELETE /v1/{addr}/messages/{id}", s.ack, passPathBox},
	}
}

// linkRoute is the page a box's link opens, the server's one route outside
// /v1/; a site, when there is one, answers the rest.
const linkRoute = "GET " + protocol.LinkPath + "{addr}"

// Handler returns the API's routes, the page a box's link opens, and the
// site, if there is one. Every answer is paced, and every request is counted
// before anything is done for it (LIMITS.md, rule 1): each handler is put on
// its router by mount, through the gate, and a request no route answers is
// counted instead by unrouted. Both pages are answered before the API is
// ready, since neither reads a store.
func (s *Server) Handler() http.Handler {
	api := http.NewServeMux()
	for _, r := range s.routes() {
		s.mount(api, r.pattern, r.pass, s.whenReady(s.handle(r.h)))
	}
	mux := http.NewServeMux()
	s.mount(mux, linkRoute, passNone, s.linkPage())
	s.subtree(mux, "/v1/", api, notStored)
	if s.site != nil {
		s.mount(mux, "/", passNone, s.site)
	}
	return s.paced(s.observed(s.dated(s.unrouted(mux))))
}

// mount puts h on mux at pattern behind the gate, so the request is counted
// before h does anything for it. It is how every handler reaches a router:
// unrouted takes a request as routed only to a handler mount or subtree put
// there.
func (s *Server) mount(mux *http.ServeMux, pattern string, pass passRule, h http.Handler) {
	mux.Handle(pattern, registered{s.gate(pass, h)})
}

// subtree puts the router inner on mux at prefix, wrapped by wrap: its
// routes are mounted on it, and it counts a request none of them answers
// itself (unrouted).
func (s *Server) subtree(mux *http.ServeMux, prefix string, inner *http.ServeMux, wrap func(http.Handler) http.Handler) {
	mux.Handle(prefix, registered{wrap(s.unrouted(inner))})
}

// gate counts a request its route answers, before the route does anything
// for it (LIMITS.md, rule 1). A call that is its box's (boxsCall) goes on to
// spend the box's budgets. Every other spends one of its address's flood
// budget first (spendRequest): a call with no pass, and one with a pass the
// process has not checked, which costs a parse and up to two signature
// checks to find out whose it is (IronGall-dev/irongall-server#67,
// IronGall-dev/irongall-client#269). Until its pass is checked, a call is
// its address's.
func (s *Server) gate(pass passRule, h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.boxsCall(pass, r) {
			if p := s.spendRequest(r); p != nil {
				writeProblem(w, p)
				return
			}
		}
		h.ServeHTTP(w, r)
	})
}

// boxsCall reports whether a call is its box's at the gate: it carries a
// pass this process has checked, to a route that takes that box's pass
// (pass), and the box is live in this process's memory (live). All this
// reads is the Authorization line, its hash, and lookups in memory, which
// cost what reading its bytes does. Whether the pass is under the box's
// current certificate, the route's own check of it says (checkPass).
func (s *Server) boxsCall(pass passRule, r *http.Request) bool {
	if pass == passNone {
		return false
	}
	a, ok := s.checked(r)
	if !ok || pass == passPathBox && r.PathValue("addr") != a.String() {
		return false
	}
	return s.live(a)
}

// live reports whether this process's memory holds box a as live, with no
// read of a store: loaded (Held), or its record in the cache (Known), and
// not deleted, not revoked, its current certificate not one its identity
// revoked. Memory is what the stream keeps current, so a change made through
// another process counts as one made here. A box memory does not hold is
// not live here: its call spends its address's flood budget, and its route
// reads it.
func (s *Server) live(a protocol.Address) bool {
	if st, ok := s.store.Held(a); ok {
		return st.State == Active && !st.Listed
	}
	b, ok := s.store.Known(a)
	if !ok || b == nil || b.State != Active {
		return false
	}
	listed, err := b.listed(b.CertSerial)
	return err == nil && !listed
}

// checked returns the box whose pass the call carries, on one Authorization
// line, if this process has checked that pass and it has not run out: a
// lookup in memory by the value's hash, with nothing parsed.
func (s *Server) checked(r *http.Request) (protocol.Address, bool) {
	auth, one := authorization(r)
	if !one || auth == "" || len(auth) > protocol.MaxPassAuthorization {
		return protocol.Address{}, false
	}
	return s.passes.known(sha256.Sum256([]byte(auth)), s.now())
}

// unrouted spends the caller's flood budget for a request no route of mux
// answers, before mux answers it itself: 404, 405, a redirect, or a 400 to a
// request for *, which reaches the handler (HTTPServer)
// (spendRequest).
func (s *Server) unrouted(mux *http.ServeMux) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !routed(mux, r) {
			if p := s.spendRequest(r); p != nil {
				writeProblem(w, p)
				return
			}
		}
		mux.ServeHTTP(w, r)
	})
}

// routed reports whether one of mux's routes answers r: whether the handler
// ServeMux.Handler finds for it, the one ServeHTTP calls, is one mount or
// subtree put there, not one the router makes itself (a redirect, a 404 or
// a 405). So nothing here copies how ServeMux matches, cleans or redirects a
// path.
func routed(mux *http.ServeMux, r *http.Request) bool {
	h, _ := mux.Handler(r)
	_, ok := h.(registered)
	return ok
}

// registered marks each handler mount or subtree puts on a router, and only
// those.
type registered struct{ http.Handler }

// HTTPServer is the API's HTTP server, at addr, with h as its handler. It
// reads a request's head in at most l.HeadTimeout and to l.HeadBytes, no
// further, before any handler sees it, and so before any count (LIMITS.md,
// rule 1); every request after its head reaches h, OPTIONS * among them,
// which net/http would otherwise answer itself, uncounted
// (IronGall-dev/irongall-server#75). An idle keep-alive connection is closed
// after idle.
func HTTPServer(addr string, h http.Handler, l Limits, idle time.Duration) *http.Server {
	return &http.Server{
		Addr:                         addr,
		Handler:                      h,
		ReadHeaderTimeout:            l.HeadTimeout,
		MaxHeaderBytes:               l.HeadBytes,
		IdleTimeout:                  idle,
		DisableGeneralOptionsHandler: true,
	}
}

// notStored marks every answer of the API as one no cache may keep. What a
// box's identity, prekey or revocation is can change at any moment, and an
// answer served again from a cache would be this server's word outliving the
// fact: a prekey that was replaced, or a box that has since been revoked. A
// 410 is cacheable by default (RFC 9110 §15.5.11), so this is said outright.
func notStored(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		h.ServeHTTP(w, r)
	})
}

// dated dates every answer by the server's own clock, the one its checks
// read. A client whose pass or statement is refused for its time compares
// that date with its own clock (PROTOCOL.md §0): it is how a refusal for a
// time says what this clock reads. Every check here is exact at this clock,
// and a client makes what it sends with an hour of room, so a refusal for a
// time is nearly always a clock that is off.
func (s *Server) dated(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Date", s.now().UTC().Format(http.TimeFormat))
		h.ServeHTTP(w, r)
	})
}

// whenReady answers 503 until the store's memory is loaded: a poll answered
// before then could read a count of zero that is not true.
func (s *Server) whenReady(h http.Handler) http.Handler {
	if s.ready == nil {
		return h
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.ready() {
			p := fail(protocol.CodeUnavailable, "retry later", "the server is starting")
			p.retryAfter = retryLater
			writeProblem(w, p)
			return
		}
		h.ServeHTTP(w, r)
	})
}

// clientIP is the address per-IP limits key on: the CF-Connecting-IP of a
// request from a trusted proxy, otherwise the peer's own address.
func (s *Server) clientIP(r *http.Request) string {
	if s.fromProxy(r) {
		if ip, err := netip.ParseAddr(strings.TrimSpace(r.Header.Get("CF-Connecting-IP"))); err == nil {
			return ip.String()
		}
	}
	return peerHost(r)
}

// fromProxy reports whether the request's peer is one of the trusted
// proxies, whose headers about the client are believed: read as the limits
// read an address (hostAddr), since a prefix contains no address with a zone.
func (s *Server) fromProxy(r *http.Request) bool {
	peer, ok := hostAddr(peerHost(r))
	return ok && slices.ContainsFunc(s.proxies, func(p netip.Prefix) bool { return p.Contains(peer) })
}

// peerHost is the address of the request's peer, without its port.
func peerHost(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// retryLater is the Retry-After of a 503.
const retryLater = time.Minute

// handle adapts a handler that returns its error as a problem.
func (s *Server) handle(h func(http.ResponseWriter, *http.Request) error) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		err := h(w, r)
		if err == nil {
			return
		}
		var p *problem
		if !errors.As(err, &p) {
			what := "internal error"
			if IsThrottle(err) {
				what = "store throttled" // provisioned capacity, or the SDK's retry quota
			}
			if s.log != nil {
				s.log.Printf("%s: %v", what, err)
			}
			p = fail(protocol.CodeUnavailable, "retry later", "the server could not complete the request")
			p.retryAfter = retryLater
		}
		writeProblem(w, p)
	}
}

// paced holds every request's body and every answer to Limits.BodyTimeout
// and Limits.BodyMinRate (IronGall-dev/irongall-server#7): a deadline that
// starts at BodyTimeout and grows a second for each BodyMinRate bytes
// moved, so a slow link that keeps sending is let through, and a peer that
// stops is cut off. It is the outermost wrapper, so no answer goes without
// it: a refusal at the gate, the router's own, the link page's, a site's
// (IronGall-dev/irongall-server#31, #77). A body the handler leaves unread
// is drained by net/http before the answer, under the read deadline, and an
// answer with no body, or a body's last bytes, is written once the handler
// returns, under a write deadline set then. Off when either is zero.
func (s *Server) paced(h http.Handler) http.Handler {
	if s.limits.BodyTimeout <= 0 || s.limits.BodyMinRate <= 0 {
		return h
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rc := http.NewResponseController(w)
		start := time.Now()
		if r.Body != nil && r.Body != http.NoBody {
			_ = rc.SetReadDeadline(start.Add(s.limits.BodyTimeout))
			r.Body = &pacedBody{ReadCloser: r.Body, rc: rc, start: start, timeout: s.limits.BodyTimeout, rate: int64(s.limits.BodyMinRate), m: s.metrics}
		}
		h.ServeHTTP(&pacedWriter{ResponseWriter: w, rc: rc, timeout: s.limits.BodyTimeout, rate: int64(s.limits.BodyMinRate)}, r)
		_ = rc.SetWriteDeadline(time.Now().Add(s.limits.BodyTimeout))
	})
}

// pacedBody moves the read deadline on as a body's bytes arrive, while the
// body is open. The read that ends it does not: net/http has then begun its
// own read of the connection, for the next request, and a deadline set on it
// would cut that read and with it the context of every request still to
// come on the connection (IronGall-dev/irongall-server#28).
type pacedBody struct {
	io.ReadCloser
	rc      *http.ResponseController
	start   time.Time
	got     int64
	timeout time.Duration
	rate    int64
	m       *Metrics
}

func (p *pacedBody) Read(b []byte) (int, error) {
	n, err := p.ReadCloser.Read(b)
	p.got += int64(n)
	if n > 0 && err == nil {
		_ = p.rc.SetReadDeadline(p.start.Add(p.timeout + time.Duration(p.got/p.rate)*time.Second))
	}
	if errors.Is(err, os.ErrDeadlineExceeded) {
		p.m.bodyCut()
	}
	return n, err
}

// pacedWriter sets the write deadline before each write, for the bytes it
// writes.
type pacedWriter struct {
	http.ResponseWriter
	rc      *http.ResponseController
	timeout time.Duration
	rate    int64
}

func (p *pacedWriter) Write(b []byte) (int, error) {
	_ = p.rc.SetWriteDeadline(time.Now().Add(p.timeout + time.Duration(int64(len(b))/p.rate)*time.Second))
	return p.ResponseWriter.Write(b)
}

// Unwrap lets http.ResponseController reach the connection.
func (p *pacedWriter) Unwrap() http.ResponseWriter { return p.ResponseWriter }

// pathAddr reads the address in the URL path, 64 lowercase hex characters:
// one box has one URL, so any other form, uppercase among them, is no
// address. Then it holds the query to params, the parameters the call takes
// (queryOf).
func pathAddr(r *http.Request, params ...string) (protocol.Address, error) {
	a, err := protocol.ParseAddress(r.PathValue("addr"))
	if err != nil {
		return a, fail(protocol.CodeBadAddress, "an address is 64 lowercase hex characters", "the path does not name an address")
	}
	if _, err := queryOf(r, params...); err != nil {
		return a, err
	}
	return a, nil
}

// queryOf reads the query of a call that takes params: each at most once,
// and no other (PROTOCOL.md §13). A parameter the call does not know, or one
// given twice, is refused as a member a body should not hold is, and named
// in member.
func queryOf(r *http.Request, params ...string) (map[string]string, error) {
	q, err := protocol.ParseQuery(r.URL.RawQuery, params...)
	if err != nil {
		return nil, queryProblem(err, "")
	}
	return q, nil
}

// queryProblem is the answer to a query a call does not take, with hint.
func queryProblem(err error, hint string) error {
	var qe *protocol.QueryError
	if !errors.As(err, &qe) || qe.Param == "" {
		return fail(protocol.CodeBadRequest, hint, "the query does not parse")
	}
	return fail(protocol.CodeBadRequest, hint, "the query parameter %s is not one this call takes, is given twice, or is not of its form", memberValue(qe.Param))
}

// decodeBody reads a JSON request body of at most limit bytes into v: exactly
// one object, no unknown fields.
func decodeBody(w http.ResponseWriter, r *http.Request, limit int64, v any) error {
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, limit))
	if err != nil {
		return readProblem(err, fail(protocol.CodeTooLarge, "send less", "the request body is over %d bytes", limitValue(int(limit))))
	}
	return decodeJSON(data, v)
}

// readProblem is the answer to a body that could not be read whole: past
// its cap, tooLarge; cut off at its deadline (paced), 408 (RFC 9110
// §15.5.9); anything else, a body that could not be read.
func readProblem(err, tooLarge error) error {
	var tooBig *http.MaxBytesError
	switch {
	case errors.As(err, &tooBig):
		return tooLarge
	case errors.Is(err, os.ErrDeadlineExceeded):
		return fail(protocol.CodeRequestTimeout, "send it again", "the request body did not arrive in the time this server waits for one")
	}
	return fail(protocol.CodeBadRequest, "", "the request body could not be read")
}

// decodeJSON reads a JSON body into v as every reader of the protocol reads
// one (protocol.UnmarshalRequest, PROTOCOL.md §0b): one I-JSON object, names
// matched exactly, nested at most protocol.MaxDepth deep, and no member v
// does not name.
func decodeJSON(data []byte, v any) error {
	switch err := protocol.UnmarshalRequest(data, v); {
	case err == nil:
		return nil
	case errors.Is(err, protocol.ErrNotBase64):
		return failErr(protocol.CodeBadEncoding, "base64 of the exact file bytes", err)
	default:
		return failErr(protocol.CodeBadRequest, "", fmt.Errorf("the body is not the JSON object expected: %w", err))
	}
}

// required checks every named byte field is present.
func required(fields ...any) error {
	for i := 0; i+1 < len(fields); i += 2 {
		if fields[i+1].(protocol.Bytes) == nil {
			return fail(protocol.CodeBadRequest, "", "missing field %q", memberValue(fields[i].(string)))
		}
	}
	return nil
}

// box reads a box's record; a box that does not exist is nil, not an error.
func (s *Server) box(ctx context.Context, a protocol.Address) (*Box, error) {
	b, err := s.store.Box(ctx, a)
	if errors.Is(err, ErrNotFound) {
		return nil, nil
	}
	return b, err
}

// lookup reads a box's record for a call that has not shown that box's pass.
// What memory holds is answered at once and is never refused or counted: a
// box's record, or that a read found no such box a moment ago. Anything else
// costs a read of the boxes table, and that read is what
// Limits.MissesPerMinute guards: the caller's address reserves a count before
// it, and keeps it only if the read finds no box (s.miss). Lookups of one
// address made while its read is in flight share that read, and are counted
// for nothing: it costs no more for them.
func (s *Server) lookup(r *http.Request, a protocol.Address) (*Box, error) {
	for {
		if b, ok := s.store.Known(a); ok {
			return b, nil
		}
		f, lead := s.reads.start(a)
		if lead {
			return s.lead(r, a, f)
		}
		b, err := f.wait(r.Context())
		if errors.Is(err, errReadNotMade) {
			continue // its caller was refused before reading: try for ourselves
		}
		return b, err
	}
}

// lead makes read f of a's record for lookup, the read every lookup of a
// meanwhile waits on. It runs apart from its caller's request, bounded by
// loadTimeout, so a caller who hangs up fails none of them
// (IronGall-dev/irongall-server#32), and it finishes f and settles its
// reservation however it ends, a panic included (#36).
func (s *Server) lead(r *http.Request, a protocol.Address, f *read) (*Box, error) {
	defer s.reads.finish(a, f, nil, errReadNotMade) // finished below, but for a refusal or a panic
	m, err := s.miss(r)
	if err != nil {
		return nil, err
	}
	defer func() { m.release(s.now()) }() // settled below, but for a panic
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), loadTimeout)
	defer cancel()
	b, err := s.box(ctx, a)
	s.reads.finish(a, f, b, err)
	if err == nil && b == nil {
		m.keep()
	} else {
		m.release(s.now())
	}
	return b, err
}

// errReadNotMade is what a shared read tells those waiting on it when its
// caller was refused before reading, or its read ended in a panic: each then
// asks for itself.
var errReadNotMade = errors.New("the read was not made")

// reads are the reads of box records in flight, by address, so that lookups
// of one address at once make one read (IronGall-dev/irongall-server#6).
type reads struct {
	mu sync.Mutex
	in map[protocol.Address]*read
}

// read is one read of a box's record, and what it found.
type read struct {
	done chan struct{}
	b    *Box
	err  error
}

// start begins the read of a, or returns the one already in flight with
// lead false.
func (rs *reads) start(a protocol.Address) (f *read, lead bool) {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	if f := rs.in[a]; f != nil {
		return f, false
	}
	if rs.in == nil {
		rs.in = map[protocol.Address]*read{}
	}
	f = &read{done: make(chan struct{})}
	rs.in[a] = f
	return f, true
}

// finish records what the read of a found, for those waiting on it: a copy
// of its own, since the read's caller may change the one it has. A read
// already finished is left as it is, so a finish deferred where the read
// starts finishes it on every path.
func (rs *reads) finish(a protocol.Address, f *read, b *Box, err error) {
	rs.mu.Lock()
	if rs.in[a] != f {
		rs.mu.Unlock()
		return
	}
	delete(rs.in, a)
	rs.mu.Unlock()
	if b != nil {
		b = cloneBox(b)
	}
	f.b, f.err = b, err
	close(f.done)
}

// wait returns what the read found, each waiter a copy of its own, or the
// caller's context's end.
func (f *read) wait(ctx context.Context) (*Box, error) {
	select {
	case <-f.done:
		if f.b == nil {
			return nil, f.err
		}
		return cloneBox(f.b), f.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// miss reserves a count of the caller's address under Limits.MissesPerMinute,
// before work that a caller who named no box, or brought nothing that
// verifies, makes the server do: a read that may find no box, or a
// signature check that may fail. It is kept if the work comes to nothing and
// released if not, so a caller is counted for what failed and never for what
// passed.
func (s *Server) miss(r *http.Request) (*reservation, error) {
	m, ok, wait := s.misses.reserve(r.Context(), ipKey(s.clientIP(r)), s.now)
	if !ok {
		return nil, rateLimited(protocol.QuotaMisses, wait, "too many calls from this address that named no box or carried nothing that verified")
	}
	return m, nil
}

// spendRequest spends one of the flood budget of the caller's address
// (Limits.RequestBurst): every call that carries no pass this process has
// checked (gate), and every request no route matches (unrouted), as Let's
// Encrypt limits every endpoint per address
// (IronGall-dev/irongall-server#58). It is sized far above what an honest
// crowd behind one address makes, the site's pages included: for floods
// alone. A refusal is the problem to answer with.
func (s *Server) spendRequest(r *http.Request) *problem {
	if ok, wait := s.requests.take(ipKey(s.clientIP(r)), s.now()); !ok {
		return rateLimited(protocol.QuotaRequests, wait, "too many calls from this address with no pass this server has checked")
	}
	return nil
}

// spendRegistration spends a registration of the caller's address: of its
// IPv4 address or IPv6 /64, and of its IPv6 /48, as Let's Encrypt counts new
// accounts (IronGall-dev/irongall-server#57). Each is reserved before the
// other is kept, so a refusal by one spends neither; a refusal gives the
// longer wait of the two (longest). why is said after the refusal's words.
func (s *Server) spendRegistration(r *http.Request, why string) error {
	host := s.clientIP(r)
	ip, block := ipKey(host), rangeKey(host)
	byIP, ok, wait := s.regs.reserve(r.Context(), ip, s.now)
	if !ok {
		p := rateLimited(protocol.QuotaRegistrations, wait, "too many registrations from this address"+why)
		if block != "" {
			if ok, w := s.rangeRegs.ready(block, s.now()); !ok && w > wait {
				p = rateLimited(protocol.QuotaRegistrationsRange, w, "too many registrations from this address's IPv6 /48"+why)
			}
		}
		return p
	}
	defer func() { byIP.release(s.now()) }() // settled below, but for a panic
	if block != "" {
		byRange, ok, wait := s.rangeRegs.reserve(r.Context(), block, s.now)
		if !ok {
			byIP.release(s.now())
			return rateLimited(protocol.QuotaRegistrationsRange, wait, "too many registrations from this address's IPv6 /48"+why)
		}
		byRange.keep()
	}
	byIP.keep()
	return nil
}

// perDay is one of a box's numbers a day: its buckets, the number, and the
// words of a refusal, with a %d for the number.
type perDay struct {
	bs    *buckets
	n     int
	words string
}

// refusal is the answer to a call past d, waiting wait.
func (d perDay) refusal(wait time.Duration) *problem {
	return rateLimited(protocol.Quota(d.bs.name), wait, d.words, limitValue(d.n))
}

// The box's numbers a day, as a refusal names them.
func (s *Server) sendsADay(n int) perDay {
	return perDay{s.sends, n, "this box has sent as many messages as %d a day allows"}
}

func (s *Server) renewalsADay() perDay {
	return perDay{s.renewals, s.limits.RenewalsPerDay, "this box has renewed its prekey as often as %d a day allows"}
}

func (s *Server) certificatesADay() perDay {
	return perDay{s.certs, s.limits.CertificatesPerDay, "this box's identity has certified as many new working keys as %d a day allows"}
}

func (s *Server) raisesADay() perDay {
	return perDay{s.raises, s.limits.CertificateRevocationsPerDay, "this box's identity has raised its revocation of certificates as often as %d a day allows"}
}

// longest is p, the refusal of one of box a's counts, or the refusal of one
// of also, the box's other counts in memory that the same call would spend,
// read without taking from them: whichever waits longest, under its own name.
// RFC 8555 §6.6 asks that Retry-After be when every limit lets the same
// request through (IronGall-dev/irongall-server#56). Counts behind work, a
// read of storage or a signature check, are not read ahead of it: the order
// of checks puts them last because they cost.
func (s *Server) longest(p *problem, a protocol.Address, also ...perDay) *problem {
	now := s.now()
	for _, d := range also {
		if ok, wait := d.bs.ready(a.String(), now); !ok && wait > p.retryAfter {
			p = d.refusal(wait)
		}
	}
	return p
}

// spendCall spends one of box a's calls (Limits.CallBurst), the budget of
// every call with its pass that no other budget counts. An account that lifts
// it comes with lim.CallBurst zero. also are the box's other counts the same
// call would spend, which a refusal reads (longest).
func (s *Server) spendCall(a protocol.Address, lim Limits, also ...perDay) error {
	if lim.CallBurst == 0 {
		return nil
	}
	if ok, wait := s.calls.take(a.String(), s.now()); !ok {
		return s.longest(rateLimited(protocol.QuotaCalls, wait, "this box has made as many calls as it may for now"), a, also...)
	}
	return nil
}

// limitsOf returns the limits of box a, which showed its pass: the server's
// for a box this process holds that is in no account, read from nothing;
// otherwise with whatever its account lifts.
func (s *Server) limitsOf(ctx context.Context, a protocol.Address) (Limits, error) {
	if st, ok := s.store.Held(a); ok && !st.InAccount {
		return s.limits, nil
	}
	b, ok := s.store.Known(a)
	if !ok || b == nil {
		var err error
		if b, err = s.box(ctx, a); err != nil || b == nil {
			return s.limits, err
		}
	}
	return s.limitsFor(ctx, b)
}

// spendOwner spends a call by box a, which showed its pass, from its budget,
// with whatever its account lifts. also are as spendCall's.
func (s *Server) spendOwner(ctx context.Context, a protocol.Address, also ...perDay) error {
	lim, err := s.limitsOf(ctx, a)
	if err != nil {
		return err
	}
	return s.spendCall(a, lim, also...)
}

// spendLookup spends a call that may carry its caller's pass, a GET of what
// is public about a box (PROTOCOL.md §4.1): with a pass it is the calling
// box's, once the pass is checked. With none, its address's flood budget is
// all it spends, at the gate, and a read that finds no box counts as a miss
// (lookup).
func (s *Server) spendLookup(r *http.Request) error {
	if auth, one := authorization(r); one && auth == "" {
		return nil
	}
	from, err := s.sender(r)
	if err != nil {
		return err
	}
	return s.spendOwner(r.Context(), from)
}

var noSuchMailbox = fail(protocol.CodeNoSuchMailbox, "check the address", "no box has this address")

func revoked() *problem {
	return fail(protocol.CodeRevoked, "the box you named is revoked, forever: ask its owner for their new address", "this box is revoked")
}

// revokedWith is revoked carrying the record this server holds, as the read
// of a box answers it (getBox).
func revokedWith(rec *protocol.Revocations) *problem {
	p := revoked()
	p.record = rec
	return p
}

// fetchedAlready refuses a fetch of a message the box has fetched before, once
// its allowance for that is spent (fetch in messages.go).
func fetchedAlready(wait time.Duration) *problem {
	p := fail(protocol.CodeRefetchSpent, "keep each message when you fetch it, then ack it (irongall recv does both); to fetch this one again, wait for Retry-After",
		"this message was fetched before, and the box's allowance for fetching again is spent")
	p.retryAfter = wait
	return p
}

// rateLimited is a 429 for a call past limit q, which it names with whom q
// counted the call against (PROTOCOL.md §13), and how long to wait in
// Retry-After.
func rateLimited(q protocol.Quota, wait time.Duration, format string, values ...value) *problem {
	p := spent(protocol.CodeRateLimited, wait, format, values...)
	p.quota = q
	return p
}

// day is the period of a number a day.
const day = 24 * time.Hour

// spent is a 429 of code, with how long to wait in Retry-After: a limit with
// a code of its own (a paced drain, a repeat fetch).
func spent(code protocol.Code, wait time.Duration, format string, values ...value) *problem {
	p := fail(code, "wait for Retry-After, then retry", format, values...)
	p.retryAfter = wait
	return p
}

// retrySeconds is a wait in whole seconds, rounded up, as Retry-After gives it.
func retrySeconds(wait time.Duration) int { return int((wait + time.Second - 1) / time.Second) }

// hex64 matches a message id in a path: 64 lowercase hex characters.
var hex64 = regexp.MustCompile(`\A[0-9a-f]{64}\z`)

func pathID(r *http.Request) ([32]byte, error) {
	var id [32]byte
	s := r.PathValue("id")
	if !hex64.MatchString(s) {
		return id, fail(protocol.CodeNoSuchMessage, "treat it as gone", "no message has this id")
	}
	_, err := hex.Decode(id[:], []byte(s))
	return id, err
}

// hexRun is a run of 64 or more hex characters, in either case: every
// address and message id, wherever a log line holds one.
var hexRun = regexp.MustCompile(`[0-9A-Fa-f]{64,}`)

// redact replaces each run of 64 or more hex characters in a log line with
// "#" and the first 16 hex characters of the SHA-256 of the run in lower
// case, a name only someone already holding the run can match: no log line
// carries an address or a message id, in a path, a store's error or
// anywhere else (IronGall-dev/irongall-server#9).
func redact(line []byte) []byte {
	return hexRun.ReplaceAllFunc(line, func(run []byte) []byte {
		h := sha256.Sum256(bytes.ToLower(run))
		return []byte("#" + hex.EncodeToString(h[:8]))
	})
}

// redactor is a log's writer that redacts each line written to it: a
// log.Logger writes each line whole, in one call.
type redactor struct{ w io.Writer }

func (r redactor) Write(p []byte) (int, error) {
	if _, err := r.w.Write(redact(p)); err != nil {
		return 0, err
	}
	return len(p), nil
}

// Redacting is w, redacting each line written to it (redact): the writer
// under every log irongalld keeps, net/http's own among them.
func Redacting(w io.Writer) io.Writer {
	if _, ok := w.(redactor); ok {
		return w
	}
	return redactor{w}
}

// redacting is l writing through Redacting, so that every line logged
// through a Config's Log is redacted whoever made it; nil if l is.
func redacting(l *log.Logger) *log.Logger {
	if l == nil {
		return nil
	}
	if _, ok := l.Writer().(redactor); ok {
		return l
	}
	return log.New(redactor{l.Writer()}, l.Prefix(), l.Flags())
}

// asSent is what the access log writes of a method or a path as the caller
// sent it: its length alone when it is longer than the longest path this
// server serves, so a caller makes no line longer, and never a part, which
// could hold part of an address the redaction would not find; a path
// otherwise quoted, so that no byte of it ends the line or passes for the
// server's own words (IronGall-dev/irongall-server#11). A method is a token,
// which net/http has checked, and needs no quotes.
func asSent(what, s string, longest int) string {
	switch {
	case len(s) > longest:
		return fmt.Sprintf("(a %s of %d bytes)", what, len(s))
	case what == "path":
		return strconv.Quote(s)
	}
	return s
}

type statusWriter struct {
	http.ResponseWriter
	status int
	code   protocol.Code // the problem's, when the answer is one (noteCode)
}

// noteCode tells the statusWriter beneath w, if there is one, that the answer
// is a problem of code c.
func noteCode(w http.ResponseWriter, c protocol.Code) {
	for {
		switch x := w.(type) {
		case *statusWriter:
			x.code = c
			return
		case interface{ Unwrap() http.ResponseWriter }:
			w = x.Unwrap()
		default:
			return
		}
	}
}

func (w *statusWriter) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

// Unwrap lets http.ResponseController reach the connection through the log.
func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// observed logs each request (method, path, status and duration, as asSent
// and redact write them; never a pass, never a body) and counts it by route,
// status and code (Metrics). The route is the pattern the routers matched,
// which each sets on the request as it routes it: never the path as sent.
func (s *Server) observed(h http.Handler) http.Handler {
	if s.log == nil && s.metrics == nil {
		return h
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		h.ServeHTTP(sw, r)
		took := time.Since(start)
		if s.log != nil {
			s.log.Printf("%s %s %d %s", asSent("method", r.Method, s.longestPath), asSent("path", r.URL.Path, s.longestPath), sw.status, took.Round(time.Microsecond))
		}
		s.metrics.answered(r.Pattern, sw.status, sw.code, took)
	})
}

func formatTime(t time.Time) string { return t.UTC().Format(protocol.TimeLayout) }

func hexID(id [32]byte) string { return hex.EncodeToString(id[:]) }

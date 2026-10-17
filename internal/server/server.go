// Package server is irongalld's HTTP API (PROTOCOL.md §3–§6, the status map
// in §13) over a Store.
package server

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/IronGall-dev/irongall-client/protocol"
)

// Config configures a Server.
type Config struct {
	Store  Store
	Keys   *Keys
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
	// lowercase, with its port if it has one. A pass is taken only on a
	// request whose Host is one of them (PROTOCOL.md §6.1b). None: any Host
	// is taken, which is for the dev server and tests only, since a pass
	// made for another server would then pass here.
	Names []string
	// IdentityTypes are the identity key types this server registers: some
	// of protocol.IdentityTypes, ssh-ed25519 among them, since that is the
	// one every client makes and verifies (PROTOCOL.md §2). None: every type
	// this build verifies.
	IdentityTypes []string
}

// Server is the API.
type Server struct {
	store   Store
	keys    *Keys
	limits  Limits
	now     func() time.Time
	log     *log.Logger
	ready   func() bool
	proxies []netip.Prefix
	names   []string
	// identityTypes are the identity key types a box may register with.
	identityTypes []string

	polls    *buckets // per box
	pages    *buckets // per box: list pages after the first
	repeats  *buckets // per box: fetches of a message already fetched
	regs     *buckets // per IP
	sendIPs  *buckets // per IP
	misses   *buckets // per IP: reads of the boxes table that found no box, and checks that failed
	public   *buckets // per IP: calls with no pass
	calls    *buckets // per box: its calls with its pass that no other budget counts
	receives *buckets // per box: new messages it takes
	drained  *buckets // per box: its first fetches of held messages
	sends    daily    // per sender
	renewals daily    // per box: renewals under its current certificate
	certs    daily    // per box: renewals under a later certificate, which only its identity can make
	raises   daily    // per box: raises of its revocation of certificates, which only its identity can make
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
		keys:          c.Keys,
		limits:        c.Limits,
		now:           c.Now,
		log:           c.Log,
		ready:         c.Ready,
		proxies:       c.TrustedProxies,
		names:         c.Names,
		identityTypes: c.IdentityTypes,
		polls:         newBuckets(c.Limits.PollBurst, c.Limits.PollRefill),
		pages:         c.Limits.continuations(),
		repeats:       newBuckets(c.Limits.PollBurst, c.Limits.PollRefill),
		regs:          perPeriod(c.Limits.RegistrationsPerHour, time.Hour),
		sendIPs:       perPeriod(c.Limits.SendsPerMinutePerIP, time.Minute),
		misses:        perPeriod(c.Limits.MissesPerMinute, time.Minute),
		public:        newBuckets(c.Limits.PublicBurst, c.Limits.PublicRefill),
		calls:         newBuckets(c.Limits.CallBurst, c.Limits.CallRefill),
		receives:      newBuckets(c.Limits.ReceiveBurst, c.Limits.ReceiveRefill),
		drained:       newBuckets(c.Limits.DrainBurst, c.Limits.DrainRefill),
		largeRead:     make(chan struct{}, 1),
		passes:        newPasses(),
	}
	if s.now == nil {
		s.now = time.Now
	}
	// What memory tags each live message with: from the server's keys, so
	// it is the same on every process; with none, random, and this
	// process's alone.
	var mk [32]byte
	if c.Keys != nil {
		mk, _ = c.Keys.markKey()
	} else {
		_, _ = rand.Read(mk[:])
	}
	if c.Store != nil {
		c.Store.UseMarkKey(mk)
	}
	if len(s.identityTypes) == 0 {
		s.identityTypes = protocol.IdentityTypes()
	}
	return s
}

// route is one of the API's routes: its pattern and its handler.
type route struct {
	pattern string
	h       func(http.ResponseWriter, *http.Request) error
}

// routes are the API's, each the client repo's api/openapi.yaml gives
// (TestTheRoutesAreTheDescriptions).
func (s *Server) routes() []route {
	return []route{
		{"GET /v1/{addr}", s.getBox},
		{"PUT /v1/{addr}", s.register},
		{"DELETE /v1/{addr}", s.closeBox},
		{"PUT /v1/{addr}/prekey", s.prekey},
		{"PUT /v1/{addr}/revocations", s.revoke},
		{"PUT /v1/{addr}/acl", s.putACL},
		{"GET /v1/{addr}/acl", s.getACL},
		{"PUT /v1/{addr}/account", s.adopt},
		{"DELETE /v1/{addr}/account", s.leave},
		{"POST /v1/{addr}/messages", s.send},
		{"GET /v1/{addr}/messages", s.list},
		{"GET /v1/{addr}/messages/{id}", s.fetch},
		{"DELETE /v1/{addr}/messages/{id}", s.ack},
	}
}

// linkRoute is the page a box's link opens, the one route outside /v1/.
const linkRoute = "GET " + protocol.LinkPath + "{addr}"

// Handler returns the API's routes and the page a box's link opens.
func (s *Server) Handler() http.Handler {
	api := http.NewServeMux()
	for _, r := range s.routes() {
		api.HandleFunc(r.pattern, s.handle(r.h))
	}
	mux := http.NewServeMux()
	mux.Handle(linkRoute, s.publicPage(linkPage()))
	mux.Handle("/v1/", notStored(s.whenReady(api)))
	return s.accessLog(s.dated(mux))
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
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	peer, err := netip.ParseAddr(host)
	if err != nil || !slices.ContainsFunc(s.proxies, func(p netip.Prefix) bool { return p.Contains(peer.Unmap()) }) {
		return host
	}
	if ip, err := netip.ParseAddr(strings.TrimSpace(r.Header.Get("CF-Connecting-IP"))); err == nil {
		return ip.String()
	}
	return host
}

// retryLater is the Retry-After of a 503.
const retryLater = time.Minute

// handle adapts a handler that returns its error as a problem.
func (s *Server) handle(h func(http.ResponseWriter, *http.Request) error) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w, r = s.paced(w, r)
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

// paced holds a call's body and its response to Limits.BodyTimeout and
// Limits.BodyMinRate (IronGall-dev/irongall-server#7): a deadline that
// starts at BodyTimeout and grows a second for each BodyMinRate bytes
// moved, so a slow link that keeps sending is let through, and a peer that
// stops is cut off. Off when either is zero.
func (s *Server) paced(w http.ResponseWriter, r *http.Request) (http.ResponseWriter, *http.Request) {
	if s.limits.BodyTimeout <= 0 || s.limits.BodyMinRate <= 0 {
		return w, r
	}
	rc := http.NewResponseController(w)
	start := time.Now()
	if r.Body != nil && r.Body != http.NoBody {
		_ = rc.SetReadDeadline(start.Add(s.limits.BodyTimeout))
		r.Body = &pacedBody{ReadCloser: r.Body, rc: rc, start: start, timeout: s.limits.BodyTimeout, rate: int64(s.limits.BodyMinRate)}
	}
	return &pacedWriter{ResponseWriter: w, rc: rc, timeout: s.limits.BodyTimeout, rate: int64(s.limits.BodyMinRate)}, r
}

// pacedBody moves the read deadline on as a body's bytes arrive.
type pacedBody struct {
	io.ReadCloser
	rc      *http.ResponseController
	start   time.Time
	got     int64
	timeout time.Duration
	rate    int64
}

func (p *pacedBody) Read(b []byte) (int, error) {
	n, err := p.ReadCloser.Read(b)
	if n > 0 {
		p.got += int64(n)
		_ = p.rc.SetReadDeadline(p.start.Add(p.timeout + time.Duration(p.got/p.rate)*time.Second))
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

// pathAddr reads the address in the URL path: 64 hex characters, folded to
// lowercase.
func pathAddr(r *http.Request) (protocol.Address, error) {
	a, err := protocol.ParseAddress(strings.ToLower(r.PathValue("addr")))
	if err != nil {
		return a, fail(protocol.CodeBadAddress, "an address is 64 hex characters", "the path does not name an address")
	}
	return a, nil
}

// decodeBody reads a JSON request body of at most limit bytes into v: exactly
// one object, no unknown fields.
func decodeBody(w http.ResponseWriter, r *http.Request, limit int64, v any) error {
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, limit))
	if err != nil {
		return readProblem(err, limit)
	}
	return decodeJSON(data, v)
}

// readProblem is the answer to a body that could not be read whole.
func readProblem(err error, limit int64) error {
	var tooBig *http.MaxBytesError
	if errors.As(err, &tooBig) {
		return fail(protocol.CodeTooLarge, "send less", "the request body is over %d bytes", limitValue(int(limit)))
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
		if !lead {
			b, err := f.wait(r.Context())
			if errors.Is(err, errReadNotMade) {
				continue // its caller was refused before reading: try for ourselves
			}
			return b, err
		}
		m, err := s.miss(r)
		if err != nil {
			s.reads.finish(a, f, nil, errReadNotMade)
			return nil, err
		}
		b, err := s.box(r.Context(), a)
		s.reads.finish(a, f, b, err)
		if err == nil && b == nil {
			m.keep()
		} else {
			m.release(s.now())
		}
		return b, err
	}
}

// errReadNotMade is what a shared read tells those waiting on it when its
// caller was refused before reading: each then asks for itself.
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
// of its own, since the read's caller may change the one it has.
func (rs *reads) finish(a protocol.Address, f *read, b *Box, err error) {
	rs.mu.Lock()
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
		return nil, rateLimited(wait, "too many calls from this address that named no box or carried nothing that verified")
	}
	return m, nil
}

// spendPublic spends one of the calls with no pass that the caller's address
// may make (Limits.PublicBurst). A box's own calls carry its pass, and are
// spent from the box's budgets instead.
func (s *Server) spendPublic(r *http.Request) error {
	if ok, wait := s.public.take(ipKey(s.clientIP(r)), s.now()); !ok {
		return rateLimited(wait, "too many calls with no pass from this address; a box's calls carry its pass, and are counted against the box")
	}
	return nil
}

// publicPage serves h, a page anyone may open, once the caller's address has
// spent a call with no pass on it.
func (s *Server) publicPage(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var p *problem
		if err := s.spendPublic(r); errors.As(err, &p) {
			writeProblem(w, p)
			return
		}
		h.ServeHTTP(w, r)
	})
}

// spendCall spends one of box a's calls (Limits.CallBurst), the budget of
// every call with its pass that no other budget counts. An account that lifts
// it comes with lim.CallBurst zero.
func (s *Server) spendCall(a protocol.Address, lim Limits) error {
	if lim.CallBurst == 0 {
		return nil
	}
	if ok, wait := s.calls.take(a.String(), s.now()); !ok {
		return rateLimited(wait, "this box has made as many calls as it may for now")
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
// with whatever its account lifts.
func (s *Server) spendOwner(ctx context.Context, a protocol.Address) error {
	lim, err := s.limitsOf(ctx, a)
	if err != nil {
		return err
	}
	return s.spendCall(a, lim)
}

// spendLookup spends a call that may carry its caller's pass, a GET of what
// is public about a box (PROTOCOL.md §4.1): with a pass it is the calling
// box's, once the pass is checked; with none, its address's.
func (s *Server) spendLookup(r *http.Request) error {
	if r.Header.Get("Authorization") == "" {
		return s.spendPublic(r)
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

// rateLimited is a 429 for calls beyond a limit, with how long to wait in
// Retry-After.
func rateLimited(wait time.Duration, detail string) *problem {
	return spent(protocol.CodeRateLimited, wait, detail)
}

// spent is a 429 of code, with how long to wait in Retry-After: a limit a
// client meets otherwise than calls beyond one (a day's sends, renewals,
// certificates or raises of a revocation of certificates; a paced drain).
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

// redact replaces every 64-hex path segment (addresses, message ids) with the
// first 16 hex characters of its SHA-256: access logs never carry an address.
func redact(path string) string {
	parts := strings.Split(path, "/")
	for i, p := range parts {
		if len(p) == 64 {
			if _, err := hex.DecodeString(p); err == nil {
				h := sha256.Sum256([]byte(strings.ToLower(p)))
				parts[i] = "#" + hex.EncodeToString(h[:8])
			}
		}
	}
	return strings.Join(parts, "/")
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

// Unwrap lets http.ResponseController reach the connection through the log.
func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// accessLog logs method, redacted path, status and duration. Never a pass,
// never a body.
func (s *Server) accessLog(h http.Handler) http.Handler {
	if s.log == nil {
		return h
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		h.ServeHTTP(sw, r)
		s.log.Printf("%s %s %d %s", r.Method, redact(r.URL.Path), sw.status, time.Since(start).Round(time.Microsecond))
	})
}

func formatTime(t time.Time) string { return t.UTC().Format(protocol.TimeLayout) }

func hexID(id [32]byte) string { return hex.EncodeToString(id[:]) }

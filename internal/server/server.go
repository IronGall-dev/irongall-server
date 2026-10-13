// Package server is irongalld's HTTP API (PROTOCOL.md §3–§6, the status map
// in §13) over a Store.
package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"time"

	"filippo.io/age"
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
	// TokenCache is how many boxes' encrypted tokens memory holds: 0 is
	// defaultTokenCache, and below zero none.
	TokenCache int
}

// defaultTokenCache is Config.TokenCache when it is not set.
const defaultTokenCache = 10000

// Server is the API.
type Server struct {
	store   Store
	keys    *Keys
	limits  Limits
	now     func() time.Time
	log     *log.Logger
	ready   func() bool
	proxies []netip.Prefix

	polls     *buckets // per box
	pages     *buckets // per box: list pages after the first
	repeats   *buckets // per box: fetches of a message already fetched
	regs      *buckets // per IP
	tokenReqs *buckets // per IP
	sendIPs   *buckets // per IP
	misses    *buckets // per IP: reads of the boxes table that found no box
	sends     daily    // per sender
	renewals  daily    // per box
	// largeRead is the one allowance for reading a send past the free
	// cap's size, held until the send is answered: every sender's body is
	// read before the server knows who sent it.
	largeRead chan struct{}

	// tokens holds boxes' current tokens, encrypted: a repeat /token call is
	// a memory lookup. One per box, its newest epoch's, and at most
	// Config.TokenCache boxes, the least recently used going first.
	tokens *recCache[protocol.Address, *sealedToken]
}

// sealedToken is a box's token at an epoch, encrypted to the prekey that
// epoch published.
type sealedToken struct {
	box    protocol.Address
	kid    uint8
	epoch  uint32
	serial uint64
	ct     []byte
}

// New returns a Server.
func New(c Config) *Server {
	tokens := c.TokenCache
	if tokens == 0 {
		tokens = defaultTokenCache
	}
	s := &Server{
		store:     c.Store,
		keys:      c.Keys,
		limits:    c.Limits,
		now:       c.Now,
		log:       c.Log,
		ready:     c.Ready,
		proxies:   c.TrustedProxies,
		polls:     newBuckets(c.Limits.PollBurst, c.Limits.PollRefill),
		pages:     c.Limits.continuations(),
		repeats:   newBuckets(c.Limits.PollBurst, c.Limits.PollRefill),
		regs:      perPeriod(c.Limits.RegistrationsPerHour, time.Hour),
		tokenReqs: perPeriod(c.Limits.TokensPerMinute, time.Minute),
		sendIPs:   perPeriod(c.Limits.SendsPerMinutePerIP, time.Minute),
		misses:    perPeriod(c.Limits.MissesPerMinute, time.Minute),
		largeRead: make(chan struct{}, 1),
		tokens: newRecCache(max(tokens, 0),
			func(t *sealedToken) protocol.Address { return t.box },
			func(t *sealedToken) uint64 { return uint64(t.epoch) },
			func(t *sealedToken) *sealedToken { return t }),
	}
	if s.now == nil {
		s.now = time.Now
	}
	return s
}

// Handler returns the API's routes and the page a box's link opens.
func (s *Server) Handler() http.Handler {
	api := http.NewServeMux()
	api.HandleFunc("PUT /v1/{addr}", s.handle(s.register))
	api.HandleFunc("POST /v1/{addr}", s.handle(s.send))
	api.HandleFunc("DELETE /v1/{addr}", s.handle(s.closeBox))
	api.HandleFunc("GET /v1/{addr}/identity", s.handle(s.identity))
	api.HandleFunc("PUT /v1/{addr}/prekey", s.handle(s.prekey))
	api.HandleFunc("PUT /v1/{addr}/account", s.handle(s.adopt))
	api.HandleFunc("DELETE /v1/{addr}/account", s.handle(s.leave))
	api.HandleFunc("POST /v1/{addr}/token", s.handle(s.token))
	api.HandleFunc("GET /v1/{addr}/messages", s.handle(s.list))
	api.HandleFunc("GET /v1/{addr}/messages/{id}", s.handle(s.fetch))
	api.HandleFunc("DELETE /v1/{addr}/messages/{id}", s.handle(s.ack))
	mux := http.NewServeMux()
	mux.Handle("GET "+protocol.LinkPath+"{addr}", linkPage())
	mux.Handle("/v1/", s.whenReady(api))
	return s.accessLog(mux)
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
		return fail(protocol.CodeTooLarge, "send less", "the request body is over %d bytes", limit)
	}
	return fail(protocol.CodeBadRequest, "", "the request body could not be read")
}

// decodeJSON reads a JSON body into v: exactly one object, no unknown
// fields.
func decodeJSON(data []byte, v any) error {
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		if errors.Is(err, protocol.ErrNotBase64) {
			return fail(protocol.CodeBadEncoding, "base64 of the exact file bytes", "%v", err)
		}
		return fail(protocol.CodeBadRequest, "", "the body is not the JSON object expected: %v", err)
	}
	if d.More() {
		return fail(protocol.CodeBadRequest, "", "the body holds more than one JSON value")
	}
	return nil
}

// required checks every named byte field is present.
func required(fields ...any) error {
	for i := 0; i+1 < len(fields); i += 2 {
		if fields[i+1].(protocol.Bytes) == nil {
			return fail(protocol.CodeBadRequest, "", "missing field %q", fields[i])
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

// lookup reads a box's record for a call that has not shown it owns the box.
// What memory holds is answered at once and is never refused or counted: a
// box's record, or that a read found no such box a moment ago. Anything else
// costs a read of the boxes table, and that read is what
// Limits.MissesPerMinute guards: an address past its count is refused before
// it, and a read that finds no box is counted against the address that
// asked, whoever it is.
func (s *Server) lookup(r *http.Request, a protocol.Address) (*Box, error) {
	if b, ok := s.store.Known(a); ok {
		return b, nil
	}
	ip, now := ipKey(s.clientIP(r)), s.now()
	if ok, wait := s.misses.ready(ip, now); !ok {
		return nil, rateLimited(wait, "too many requests from this address naming boxes that do not exist")
	}
	b, err := s.box(r.Context(), a)
	if err == nil && b == nil {
		s.misses.take(ip, now)
	}
	return b, err
}

var noSuchMailbox = fail(protocol.CodeNoSuchMailbox, "check the address", "no box has this address")

func revoked() *problem {
	return fail(protocol.CodeRevoked, "the box you named is revoked, forever: ask its owner for their new address", "this box is revoked")
}

// owner authenticates an owner call (Bearer) and returns the box's address.
// A token this server minted for the address, at any epoch, proves the box
// was registered; only such a call reads the box into memory, on its first
// use by this process, and every later call is answered from memory
// (ARCHITECTURE.md § Memory). Anything else reads the record: a pending box,
// whose first owner call activates it (using the token proves the registrant
// decrypted it, so it holds the prekey), and a call whose token is missing
// or not ours, which may name no box.
// bearerToken returns the token of an Authorization header that uses the Bearer scheme.
// The scheme name is case-insensitive (RFC 9110 section 11.1, RFC 6750 section 2.1).
func bearerToken(header string) (string, bool) {
	scheme, tok, ok := strings.Cut(header, " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return "", false
	}
	return strings.TrimSpace(tok), true
}

func (s *Server) owner(r *http.Request) (protocol.Address, error) {
	a, err := pathAddr(r)
	if err != nil {
		return a, err
	}
	tok, hasTok := bearerToken(r.Header.Get("Authorization"))
	hasTok = hasTok && tok != ""
	ours := false
	if _, err := s.keys.verify(a, tok); hasTok && err == nil {
		ours = true
		st, err := s.store.Standing(r.Context(), a)
		switch {
		case errors.Is(err, ErrNotFound):
			return a, noSuchMailbox
		case err != nil:
			return a, err
		case st.State == Closed:
			return a, noSuchMailbox
		case st.State == Revoked:
			return a, revoked()
		case st.State == Active:
			return a, s.tokenProblem(a, st.Epoch, tok, true)
		}
	}
	// A token of ours names a box that was registered, so reading its record
	// is no guess at an address: it is not a call lookup would count or refuse.
	read := s.lookup
	if ours {
		read = func(r *http.Request, a protocol.Address) (*Box, error) { return s.box(r.Context(), a) }
	}
	b, err := read(r, a)
	if err != nil {
		return a, err
	}
	switch {
	case b == nil, b.State == Closed:
		return a, noSuchMailbox
	case b.State == Revoked:
		return a, revoked()
	}
	if p := s.tokenProblem(a, b.Epoch, tok, hasTok); p != nil {
		return a, p
	}
	if b.State == Pending {
		b.State = Active
		if err := s.store.UpdateBox(r.Context(), b); err != nil {
			return a, err
		}
	}
	return a, nil
}

// tokenProblem checks an owner token against the box's epoch: nil if it is
// valid, otherwise the problem to answer.
func (s *Server) tokenProblem(a protocol.Address, epoch uint32, tok string, hasTok bool) error {
	if !hasTok {
		return fail(protocol.CodeUnauthorized, "send the box's owner token: Authorization: Bearer <token>", "no owner token")
	}
	switch err := s.keys.Check(a, epoch, tok); {
	case errors.Is(err, errStaleToken):
		p := fail(protocol.CodeTokenStale, "the client refreshes it: POST /v1/<address>/token, decrypt, retry (irongall and ig_owner do this)", "the token's epoch has moved on")
		p.tokenPresented = true
		return p
	case err != nil:
		p := fail(protocol.CodeUnauthorized, "send the box's owner token", "the token is not valid for this box")
		p.tokenPresented = true
		return p
	}
	return nil
}

// encryptedToken returns the box's current token, age-encrypted to its
// current prekey.
func (s *Server) encryptedToken(b *Box) ([]byte, error) {
	if t, ok := s.tokens.get(b.Addr); ok && t.kid == s.keys.Current && t.epoch == b.Epoch && t.serial == b.Prekey.Serial {
		return t.ct, nil
	}
	r, err := b.Prekey.Recipient()
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, r)
	if err != nil {
		return nil, err
	}
	if _, err := io.WriteString(w, s.keys.Mint(b.Addr, b.Epoch)); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	s.tokens.put(&sealedToken{box: b.Addr, kid: s.keys.Current, epoch: b.Epoch, serial: b.Prekey.Serial, ct: buf.Bytes()})
	return buf.Bytes(), nil
}

func (s *Server) writeToken(w http.ResponseWriter, status int, b *Box) error {
	ct, err := s.encryptedToken(b)
	if err != nil {
		return err
	}
	writeJSON(w, status, protocol.TokenResponse{Token: ct})
	return nil
}

// fetchedAlready refuses a fetch of a message the box has fetched before, once
// its allowance for that is spent (fetch in messages.go).
func fetchedAlready(wait time.Duration) *problem {
	p := fail(protocol.CodeRateLimited, "keep each message when you fetch it, then ack it (irongall recv does both); to fetch this one again, wait for Retry-After",
		"this message was fetched before, and the box's allowance for fetching again is spent; retry in %ds", retrySeconds(wait))
	p.retryAfter = wait
	return p
}

// rateLimited is a 429 whose detail also says how long to wait, so a client
// that prints the detail shows it without reading Retry-After.
func rateLimited(wait time.Duration, format string, args ...any) *problem {
	p := fail(protocol.CodeRateLimited, "wait for Retry-After, then retry", format+"; retry in %ds", append(args, retrySeconds(wait))...)
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

// accessLog logs method, redacted path, status and duration. Never a token,
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

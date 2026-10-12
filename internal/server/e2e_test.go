package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/IronGall-dev/irongall-client/client"
	"github.com/IronGall-dev/irongall-client/protocol"
	"golang.org/x/crypto/ssh"
)

// clock is a settable clock shared by the server and the clients.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) Add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// env is a dev server with the clients' view of it. Middleware, when set,
// sits between the clients and the server, to see or change what passes.
type env struct {
	t      *testing.T
	clock  *clock
	keys   *Keys
	store  Store
	srv    *httptest.Server
	mu     sync.Mutex
	middle func(w http.ResponseWriter, r *http.Request, next http.Handler)
}

func relaxed() Limits {
	l := DefaultLimits()
	l.SendsPerDay, l.PollBurst, l.RegistrationsPerHour, l.RenewalsPerDay, l.MissesPerMinute = 0, 0, 0, 0, 0
	return l
}

func newEnv(t *testing.T, l Limits) *env {
	t.Helper()
	keys, err := NewDevKeys()
	if err != nil {
		t.Fatal(err)
	}
	e := &env{t: t, clock: &clock{t: time.Now().UTC().Truncate(time.Second)}, keys: keys}
	var ready func() bool
	e.store, ready = newTestStore(t, e.clock.Now)
	h := New(Config{Store: e.store, Keys: keys, Limits: l, Now: e.clock.Now, Ready: ready}).Handler()
	e.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		e.mu.Lock()
		m := e.middle
		e.mu.Unlock()
		if m != nil {
			m(w, r, h)
			return
		}
		h.ServeHTTP(w, r)
	}))
	t.Cleanup(e.srv.Close)
	return e
}

func (e *env) setMiddle(m func(w http.ResponseWriter, r *http.Request, next http.Handler)) {
	e.mu.Lock()
	e.middle = m
	e.mu.Unlock()
}

func (e *env) opts() client.Options {
	return client.Options{Base: e.srv.URL, Now: e.clock.Now}
}

// box makes, registers and activates a box.
func (e *env) box(kt protocol.KeyType) *client.Box {
	e.t.Helper()
	b, err := client.Init(context.Background(), e.t.TempDir(), e.opts(), kt)
	if err != nil {
		e.t.Fatalf("init: %v", err)
	}
	return b
}

func send(t *testing.T, from, to *client.Box, body string) *protocol.Receipt {
	t.Helper()
	r, err := from.Send(context.Background(), to.Address(), body)
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	return r
}

func receive(t *testing.T, b *client.Box) *client.Result {
	t.Helper()
	res, err := b.Receive(context.Background())
	if err != nil {
		t.Fatalf("receive: %v", err)
	}
	return res
}

func bodyOf(t *testing.T, d client.Delivery) string {
	t.Helper()
	var s string
	if err := json.Unmarshal(d.Envelope.Body, &s); err != nil {
		t.Fatal(err)
	}
	return s
}

// signer loads a box's identity key from its state directory, as an operator
// who stole it, or a test, would.
func signer(t *testing.T, b *client.Box) ssh.Signer {
	t.Helper()
	k, err := os.ReadFile(filepath.Join(b.Dir(), "identity"))
	if err != nil {
		t.Fatal(err)
	}
	s, err := ssh.ParsePrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestEndToEnd(t *testing.T) {
	e := newEnv(t, relaxed())
	a, b := e.box(protocol.PostQuantum), e.box(protocol.Classic)

	body := "hello <b>&é☃ — mail is data"
	r := send(t, a, b, body)
	if len(r.ID) != 64 {
		t.Fatalf("receipt id %q", r.ID)
	}
	res := receive(t, b)
	if len(res.Delivered) != 1 || len(res.Refused) != 0 {
		t.Fatalf("delivered %d, refused %v", len(res.Delivered), res.Refused)
	}
	d := res.Delivered[0]
	if got := bodyOf(t, d); got != body {
		t.Fatalf("body %q", got)
	}
	if d.Envelope.From != a.Address() || d.ID != r.ID {
		t.Fatal("wrong sender or id")
	}
	if in, err := os.ReadFile(filepath.Join(b.Dir(), "inbox", r.ID+".json")); err != nil || !bytes.Equal(in, d.Line) {
		t.Fatalf("inbox copy: %v", err)
	}
	if !bytes.Contains(d.Plaintext, []byte("<b>&")) {
		t.Fatal("the envelope is HTML-escaped")
	}

	// Acked: the box is empty, and an empty box's ETag is kept for a 304.
	if res := receive(t, b); len(res.Delivered) != 0 {
		t.Fatal("delivered twice")
	}
	if _, err := os.Stat(filepath.Join(b.Dir(), "etag")); err != nil {
		t.Fatal("no etag kept for the empty box")
	}
	var polls []int
	e.setMiddle(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
		sw := &statusWriter{ResponseWriter: w, status: 200}
		next.ServeHTTP(sw, r)
		if strings.HasSuffix(r.URL.Path, "/messages") {
			polls = append(polls, sw.status)
		}
	})
	receive(t, b)
	if len(polls) != 1 || polls[0] != http.StatusNotModified {
		t.Fatalf("an empty poll with the ETag got %v, want [304]", polls)
	}
	e.setMiddle(nil)

	// A reply, the other way, PQ this time.
	send(t, b, a, "reply")
	if res := receive(t, a); len(res.Delivered) != 1 || bodyOf(t, res.Delivered[0]) != "reply" {
		t.Fatal("no reply")
	}
	// A message arriving after the ETag was kept is not hidden by it.
	send(t, a, b, "second")
	if res := receive(t, b); len(res.Delivered) != 1 || bodyOf(t, res.Delivered[0]) != "second" {
		t.Fatal("the kept ETag hid new mail")
	}
}

// capture records the JSON body of the next request matching method and
// path suffix.
func capture(e *env, method, suffix string) *[]byte {
	var got []byte
	e.setMiddle(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
		if r.Method == method && strings.HasSuffix(r.URL.Path, suffix) && got == nil {
			got, _ = io.ReadAll(r.Body)
			r.Body = io.NopCloser(bytes.NewReader(got))
		}
		next.ServeHTTP(w, r)
	})
	return &got
}

func post(t *testing.T, url string, body []byte) (int, []byte) {
	t.Helper()
	resp, err := http.Post(url, "application/json", bytes.NewReader(body)) //nolint:gosec // test server
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b
}

func TestRetryGetsOriginalReceipt(t *testing.T) {
	e := newEnv(t, relaxed())
	a, b := e.box(protocol.Classic), e.box(protocol.Classic)
	sent := capture(e, http.MethodPost, "/v1/"+b.Address().String())
	r := send(t, a, b, "once")
	e.setMiddle(nil)

	status, body := post(t, e.srv.URL+"/v1/"+b.Address().String(), *sent)
	var again protocol.Receipt
	if err := json.Unmarshal(body, &again); err != nil || status != http.StatusOK || again != *r {
		t.Fatalf("retry: %d %s, want 200 and %+v", status, body, *r)
	}
	if res := receive(t, b); len(res.Delivered) != 1 {
		t.Fatalf("delivered %d, want 1", len(res.Delivered))
	}
	// Still a retry after the ack: the dedupe record outlives it.
	if status, _ := post(t, e.srv.URL+"/v1/"+b.Address().String(), *sent); status != http.StatusOK {
		t.Fatalf("retry after ack: %d", status)
	}
	if res := receive(t, b); len(res.Delivered) != 0 {
		t.Fatal("a retry after the ack was delivered again")
	}
}

// A new prekey bumps the epoch: the old token gets 401 token_stale.
func TestTokenStaleAfterRekey(t *testing.T) {
	e := newEnv(t, relaxed())
	b := e.box(protocol.Classic)
	old, _ := os.ReadFile(filepath.Join(b.Dir(), "token"))
	if _, err := b.Rekey(context.Background(), ""); err != nil {
		t.Fatal(err)
	}
	cur, _ := os.ReadFile(filepath.Join(b.Dir(), "token"))
	if bytes.Equal(old, cur) {
		t.Fatal("a new prekey did not bring a new token")
	}
	// The old token is dead.
	req, _ := http.NewRequest(http.MethodGet, e.srv.URL+"/v1/"+b.Address().String()+"/messages", nil)
	req.Header.Set("Authorization", "Bearer "+string(old))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var p protocol.Problem
	_ = json.NewDecoder(resp.Body).Decode(&p)
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized || p.Code != protocol.CodeTokenStale ||
		resp.Header.Get("WWW-Authenticate") != `Bearer error="invalid_token"` {
		t.Fatalf("old token: %d %s %q", resp.StatusCode, p.Code, resp.Header.Get("WWW-Authenticate"))
	}
	// The client's refresh on token_stale is tested in irongall-client.
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b := make([]byte, len(s)/2)
	for i := range b {
		var v byte
		for _, c := range s[2*i : 2*i+2] {
			v <<= 4
			switch {
			case c >= '0' && c <= '9':
				v |= byte(c - '0')
			case c >= 'a' && c <= 'f':
				v |= byte(c - 'a' + 10)
			default:
				t.Fatalf("not hex: %q", s)
			}
		}
		b[i] = v
	}
	return b
}

// A box whose prekey expired still works for its owner, and renewing needs
// no token. (Senders refusing the expired prekey is tested in irongall-client.)
func TestRenewalAfterExpiry(t *testing.T) {
	e := newEnv(t, relaxed())
	a, b := e.box(protocol.Classic), e.box(protocol.Classic)
	e.clock.Add(protocol.MaxPrekeyLifetime)
	if _, err := b.Rekey(context.Background(), ""); err != nil {
		t.Fatal(err)
	}
	send(t, a, b, "after renewal")
	if res := receive(t, b); len(res.Delivered) != 1 {
		t.Fatal("no delivery after renewal")
	}
}

func TestRecoveryWithIdentityAlone(t *testing.T) {
	e := newEnv(t, relaxed())
	a, b := e.box(protocol.PostQuantum), e.box(protocol.PostQuantum)
	// A restored machine: the identity, nothing else.
	for _, g := range []string{"prekeys/*", "token"} {
		names, _ := filepath.Glob(filepath.Join(b.Dir(), g))
		for _, n := range names {
			if err := os.Remove(n); err != nil {
				t.Fatal(err)
			}
		}
	}
	if _, err := b.Rekey(context.Background(), ""); err != nil {
		t.Fatal(err)
	}
	send(t, a, b, "after recovery")
	if res := receive(t, b); len(res.Delivered) != 1 {
		t.Fatal("no delivery after recovery")
	}
}

func TestPagination(t *testing.T) {
	l := relaxed()
	l.PairCap = 0
	l.PollBurst = 2 // init activates with one poll; a drain of two pages is one more
	e := newEnv(t, l)
	a, b := e.box(protocol.Classic), e.box(protocol.Classic)
	const n = pageSize + 5
	for i := range n {
		send(t, a, b, strings.Repeat("x", i))
		e.clock.Add(time.Millisecond) // oldest first is by receipt time, then id
	}
	res := receive(t, b)
	if len(res.Delivered) != n {
		t.Fatalf("delivered %d, want %d", len(res.Delivered), n)
	}
	// Oldest first.
	for i, d := range res.Delivered {
		if got := bodyOf(t, d); len(got) != i {
			t.Fatalf("message %d out of order", i)
		}
	}
}

func TestLimits(t *testing.T) {
	ctx := context.Background()
	t.Run("pair_full", func(t *testing.T) {
		l := relaxed()
		l.PairCap = 2
		e := newEnv(t, l)
		a, b := e.box(protocol.Classic), e.box(protocol.Classic)
		send(t, a, b, "1")
		send(t, a, b, "2")
		_, err := a.Send(ctx, b.Address(), "3")
		var ae *client.APIError
		if !errors.As(err, &ae) || ae.Problem.Code != protocol.CodePairFull || ae.Status != 429 ||
			ae.RetryAfter == 0 || ae.Problem.Unacked == nil || *ae.Problem.Unacked != 2 || ae.Problem.OldestExpiresAt == "" {
			t.Fatalf("third send: %v %+v", err, ae)
		}
		// Nothing is dropped to make room; the message waits in the outbox.
		receive(t, b)
		if rs, err := a.Flush(ctx); err != nil || len(rs) != 1 {
			t.Fatalf("flush: %v", err)
		}
	})
	t.Run("mailbox_full", func(t *testing.T) {
		l := relaxed()
		l.BoxCap = 2
		e := newEnv(t, l)
		a, b, c := e.box(protocol.Classic), e.box(protocol.Classic), e.box(protocol.Classic)
		send(t, a, b, "1")
		send(t, c, b, "2")
		_, err := c.Send(ctx, b.Address(), "3")
		var ae *client.APIError
		if !errors.As(err, &ae) || ae.Problem.Code != protocol.CodeMailboxFull || ae.Status != 429 || ae.RetryAfter == 0 {
			t.Fatalf("send to a full box: %v", err)
		}
	})
	t.Run("sends per day", func(t *testing.T) {
		l := relaxed()
		l.SendsPerDay = 2
		e := newEnv(t, l)
		a, b := e.box(protocol.Classic), e.box(protocol.Classic)
		send(t, a, b, "1")
		send(t, a, b, "2")
		if _, err := a.Send(ctx, b.Address(), "3"); client.Code(err) != protocol.CodeRateLimited {
			t.Fatalf("third send: %v", err)
		}
	})
	t.Run("polls", func(t *testing.T) {
		// A burst of 10 (a new box, or after a restart), then one more
		// every 50 s: a poll a minute never runs dry, one every 30 s does.
		l := relaxed()
		d := DefaultLimits()
		l.PollBurst, l.PollRefill = d.PollBurst, d.PollRefill
		e := newEnv(t, l)
		b := e.box(protocol.Classic) // init's activation is one poll
		for range 9 {
			receive(t, b)
		}
		_, err := b.Receive(ctx)
		var ae *client.APIError
		if !errors.As(err, &ae) || ae.Problem.Code != protocol.CodeRateLimited || ae.RetryAfter != 50*time.Second {
			t.Fatalf("eleventh poll at once: %v", err)
		}
		e.clock.Add(50 * time.Second)
		receive(t, b)
		for range 60 { // an hour of polls once a minute
			e.clock.Add(time.Minute)
			receive(t, b)
		}
		e.clock.Add(10 * 50 * time.Second) // full again
		for i := range 23 {                // 11.5 minutes
			e.clock.Add(30 * time.Second)
			if _, err := b.Receive(ctx); err != nil {
				t.Fatalf("poll %d every 30 s: %v", i, err)
			}
		}
		e.clock.Add(30 * time.Second)
		if _, err := b.Receive(ctx); client.Code(err) != protocol.CodeRateLimited {
			t.Fatalf("polls every 30 s outlasted the burst: %v", err)
		}
	})
}

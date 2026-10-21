package server

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/IronGall-dev/irongall-client/protocol"
)

// Every answer is paced, so no connection outlives the deadline its peer
// sets by not sending or not reading (LIMITS.md, a body's and a response's
// time; IronGall-dev/irongall-server#28, #31, #75, #77). These run through
// HTTPServer, the server irongalld serves the API with, on a port of their
// own, since net/http's own reading and writing is what they hold.

// pacedLimits are limits with every body and answer paced at a second, and
// a megabyte a second more for each second, so a test's slow peer is cut
// at a second.
func pacedLimits() Limits {
	l := relaxed()
	l.BodyTimeout, l.BodyMinRate = time.Second, 1<<20
	return l
}

// served serves s's handler as irongalld does, and returns its address and
// how many of its connections have closed.
func served(t *testing.T, s *Server, l Limits) (string, *atomic.Int64) {
	t.Helper()
	closed := new(atomic.Int64)
	srv := HTTPServer("", s.Handler(), l, time.Minute)
	srv.ConnState = func(_ net.Conn, st http.ConnState) {
		if st == http.StateClosed || st == http.StateHijacked {
			closed.Add(1)
		}
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return ln.Addr().String(), closed
}

// closesWithin reports whether the server ends conn within d, whatever it
// writes first, and what it wrote.
func closesWithin(conn net.Conn, d time.Duration) (bool, string) {
	_ = conn.SetReadDeadline(time.Now().Add(d))
	got, err := io.ReadAll(conn)
	var ne net.Error
	return !errors.As(err, &ne) || !ne.Timeout(), string(got)
}

// A body that stops after its head is cut off at the read deadline, behind
// any answer: one a handler gives after it reads, and every one written
// before the body is read, which net/http drains first (#77). Cut off where
// a handler reads it, the answer is 408 request_timeout (RFC 9110 §15.5.9);
// behind an answer written first, the peer gets the end of the connection,
// that answer before it or not.
func TestABodyThatStopsIsCutBehindEveryAnswer(t *testing.T) {
	nobody := strings.Repeat("ab", 32)
	cases := []struct {
		name    string
		limits  func(*Limits)
		ready   bool
		spend   bool // spend the address's one call first
		head    string
		status  string // the answer's status line, if one is checked
		limited bool
	}{
		{"read by its handler", nil, true, false, "PUT /v1/" + nobody + " HTTP/1.1", "408", false},
		{"the gate's refusal", func(l *Limits) { l.RequestBurst, l.RequestRefill = 1, time.Hour }, true, true, "POST /v1/" + nobody + "/messages HTTP/1.1", "", true},
		{"unrouted's refusal", func(l *Limits) { l.RequestBurst, l.RequestRefill = 1, time.Hour }, true, true, "POST /nothing HTTP/1.1", "", true},
		{"the router's 404", nil, true, false, "POST /v1/" + nobody + "/nothing/here HTTP/1.1", "", false},
		{"the link page's 405", nil, true, false, "POST " + protocol.LinkPath + nobody + " HTTP/1.1", "", false},
		{"OPTIONS *", nil, true, false, "OPTIONS * HTTP/1.1", "", false},
		{"a server not ready", nil, false, false, "PUT /v1/" + nobody + " HTTP/1.1", "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			l := pacedLimits()
			if c.limits != nil {
				c.limits(&l)
			}
			ready := c.ready
			reg := prometheus.NewRegistry()
			s := New(Config{Store: NewMemStore(time.Now), Limits: l, Ready: func() bool { return ready }, Metrics: NewMetrics(reg)})
			addr, _ := served(t, s, l)
			if c.spend {
				resp, err := http.Get("http://" + addr + protocol.LinkPath + nobody)
				if err != nil {
					t.Fatal(err)
				}
				_ = resp.Body.Close()
			}
			conn, err := net.Dial("tcp", addr)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = conn.Close() }()
			if _, err := io.WriteString(conn, c.head+"\r\nHost: "+addr+"\r\nContent-Type: application/json\r\nContent-Length: 1000\r\n\r\n{"); err != nil {
				t.Fatal(err)
			}
			start := time.Now()
			ok, got := closesWithin(conn, 5*time.Second)
			if !ok {
				t.Fatalf("a body that stopped after its head: the connection was held past %v", time.Since(start).Round(time.Millisecond))
			}
			if c.status != "" && !strings.HasPrefix(got, "HTTP/1.1 "+c.status+" ") {
				t.Errorf("answered %.40q, want %s", got, c.status)
			}
			if c.status == "408" && !strings.Contains(got, `"code":"request_timeout"`) {
				t.Errorf("a 408 that is not request_timeout: %q", got)
			}
			// An answer written before the body is read follows net/http's
			// drain of it, which the deadline ends, and may not reach a peer
			// that stops: what the refusal was, its count says.
			if d := counts(t, reg, "irongalld_limit_requests_total")["decision=denied,limit=requests,subject=ip"]; c.limited && d != 1 {
				t.Errorf("refused for the flood budget %v times, want 1", d)
			}
			t.Logf("cut after %v", time.Since(start).Round(10*time.Millisecond))
		})
	}
}

// An answer its peer never reads is cut off at the write deadline, every
// kind: a page outside the API, the router's own, one with no body, and a
// site's page larger than every buffer between (#31). The peer asks again
// and again on one connection and reads nothing, with a small receive
// buffer.
func TestAnAnswerNeverReadIsCut(t *testing.T) {
	big := make([]byte, 8<<20)
	if _, err := rand.Read(big); err != nil {
		t.Fatal(err)
	}
	site, err := LoadSite(writeSite(t, map[string]string{"index.html": "<!doctype html><title>front</title>", "big.png": string(big)}))
	if err != nil {
		t.Fatal(err)
	}
	l := pacedLimits()
	e := newEnv(t, l, func(c *Config) { c.Site = site })
	r := e.raw().register(protocol.MaxPrekeyLifetime)
	pass := r.pass(1)
	tag := e.do("GET", r.path("/messages"), nil, pass).header.Get("ETag")
	nobody := strings.Repeat("ab", 32)
	cases := []struct {
		name, req string
		once      bool
	}{
		{"the link page", "GET " + protocol.LinkPath + nobody + " HTTP/1.1\r\nHost: %s\r\n\r\n", false},
		{"the router's 404", "GET /nothing/here.html HTTP/1.1\r\nHost: %s\r\n\r\n", false},
		{"a 304, with no body", "GET " + r.path("/messages") + " HTTP/1.1\r\nHost: %s\r\nAuthorization: " + pass + "\r\nIf-None-Match: " + tag + "\r\n\r\n", false},
		{"a site's large page", "GET /big.png HTTP/1.1\r\nHost: %s\r\n\r\n", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			addr, closed := served(t, e.server, l)
			req := strings.ReplaceAll(c.req, "%s", e.name())
			d := net.Dialer{Control: func(_, _ string, rc syscall.RawConn) error {
				return rc.Control(func(fd uintptr) { _ = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUF, 1024) })
			}}
			conn, err := d.Dial("tcp", addr)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = conn.Close() }()
			go func() { // ask, and never read
				for {
					if _, err := io.WriteString(conn, req); err != nil || c.once {
						return
					}
				}
			}()
			deadline := time.Now().Add(6 * time.Second)
			for closed.Load() == 0 && time.Now().Before(deadline) {
				time.Sleep(50 * time.Millisecond)
			}
			if closed.Load() == 0 {
				t.Errorf("a peer that never reads holds the connection past every deadline")
			}
		})
	}
}

// An honest slow reader of a large page is not cut: each write moves the
// deadline on, so a peer that keeps reading gets the whole page however
// long it takes, as a body that keeps coming does.
func TestASlowReaderIsNotCut(t *testing.T) {
	page := make([]byte, 1<<20)
	if _, err := rand.Read(page); err != nil {
		t.Fatal(err)
	}
	site, err := LoadSite(writeSite(t, map[string]string{"index.html": "<!doctype html><title>front</title>", "big.png": string(page)}))
	if err != nil {
		t.Fatal(err)
	}
	l := pacedLimits()
	s := New(Config{Store: NewMemStore(time.Now), Limits: l, Site: site})
	addr, _ := served(t, s, l)
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := fmt.Fprintf(conn, "GET /big.png HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", addr); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	start, got := time.Now(), 0
	buf := make([]byte, 64<<10)
	for {
		n, err := io.ReadFull(resp.Body, buf)
		got += n
		if err != nil {
			break
		}
		time.Sleep(200 * time.Millisecond) // 320 KiB a second: three seconds for the page
	}
	if got != len(page) {
		t.Errorf("a slow reader got %d of %d bytes in %v", got, len(page), time.Since(start).Round(time.Millisecond))
	}
}

// slowStore is a store whose DeleteMessages takes hold, and whose reads of
// a box read their context first, as DynamoStore's calls do.
type slowStore struct {
	Store
	hold time.Duration
}

func (s slowStore) DeleteMessages(ctx context.Context, a protocol.Address) error {
	select {
	case <-time.After(s.hold):
		return s.Store.DeleteMessages(ctx, a)
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s slowStore) Box(ctx context.Context, a protocol.Address) (*Box, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return s.Store.Box(ctx, a)
}

// A body's read deadline ends with the body: a handler that runs past it
// once the body is read is not cut, and the next request on the connection
// is answered as on a new one (#28). The read that ends a body is where
// net/http begins its own read of the connection, for the next request,
// and a deadline set there would cancel every request still to come on it.
func TestAPacedBodysDeadlineEndsWithTheBody(t *testing.T) {
	l := pacedLimits()
	e := newEnv(t, l, func(c *Config) { c.Store = slowStore{Store: c.Store, hold: 3 * time.Second} })
	r := e.raw().register(protocol.MaxPrekeyLifetime)
	rev, err := protocol.SignRevocation(r.signer, r.id.Address())
	if err != nil {
		t.Fatal(err)
	}
	addr, _ := served(t, e.server, l)
	one := &http.Client{Transport: &http.Transport{MaxConnsPerHost: 1}} // one kept-alive connection
	do := func(method, path, body string) int {
		t.Helper()
		var rd io.Reader
		if body != "" {
			rd = strings.NewReader(body)
		}
		req, err := http.NewRequest(method, "http://"+addr+path, rd)
		if err != nil {
			t.Fatal(err)
		}
		req.Host = e.name()
		resp, err := one.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		return resp.StatusCode
	}
	nobody := "/v1/" + strings.Repeat("ab", 32)
	if got := do("GET", nobody, ""); got != http.StatusNotFound {
		t.Fatalf("before: %d", got)
	}
	j, err := json.Marshal(protocol.Revocations{Identity: r.id.Document(), Revocation: rev})
	if err != nil {
		t.Fatal(err)
	}
	if got := do("PUT", r.path("/revocations"), string(j)); got != http.StatusCreated {
		t.Errorf("a revocation whose delete takes past the body's deadline: %d, want 201", got)
	}
	for range 2 {
		if got := do("GET", nobody, ""); got != http.StatusNotFound {
			t.Errorf("after, on the same connection: %d, want 404", got)
		}
	}
}

// OPTIONS * reaches the server's handler, and is counted as a request no
// route answers (#75), where net/http would answer it 200 itself, its body
// read, before any handler or count: from an address with one call, the
// first is the router's 400, and the second is refused for the flood
// budget.
func TestOptionsStarIsCounted(t *testing.T) {
	l := relaxed()
	l.RequestBurst, l.RequestRefill = 1, time.Hour
	s := New(Config{Store: NewMemStore(time.Now), Limits: l})
	addr, _ := served(t, s, l)
	for _, want := range []string{"400", "429"} {
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(conn, "OPTIONS * HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"); err != nil {
			t.Fatal(err)
		}
		ok, got := closesWithin(conn, 5*time.Second)
		_ = conn.Close()
		if !ok || !strings.HasPrefix(got, "HTTP/1.1 "+want+" ") {
			t.Errorf("OPTIONS *: %.40q, want %s", got, want)
		}
	}
}

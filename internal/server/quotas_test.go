package server

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/IronGall-dev/irongall-client/api/apitest"
	"github.com/IronGall-dev/irongall-client/protocol"
)

// caller makes requests from any address straight to e's server, wrapped as
// every test server is (apitest): a request comes from the address ip, as
// its peer, and is answered whatever it is, a router's plain 404 among them.
func (e *env) caller() func(ip, method, path string, body any, pass string) reply {
	h := apitest.Handler(e.t, e.server.Handler())
	return func(ip, method, path string, body any, pass string) reply {
		e.t.Helper()
		var rd io.Reader = http.NoBody
		if body != nil {
			j, _ := json.Marshal(body)
			rd = bytes.NewReader(j)
		}
		req := httptest.NewRequest(method, path, rd)
		req.Host = e.name()
		req.RemoteAddr = net.JoinHostPort(ip, "40000")
		if pass != "" {
			req.Header.Set("Authorization", pass)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return reply{status: w.Code, header: w.Header(), body: w.Body.Bytes()}
	}
}

// waits reports r's Retry-After, in seconds.
func waits(r reply) int {
	n, _ := strconv.Atoi(r.header.Get("Retry-After"))
	return n
}

// Every limit a rate_limited answers for names itself in quota_id, and whom
// it counted the call against in subject (PROTOCOL.md §13): the box for a
// call with its pass, the address for one with none.
func TestEveryRefusalNamesItsLimit(t *testing.T) {
	l := relaxed()
	l.PollBurst, l.PollRefill = 1, time.Minute
	l.CallBurst, l.CallRefill = 1, time.Minute
	l.MissesPerMinute, l.SendsPerMinutePerIP, l.RegistrationsPerHour = 2, 1, 1
	e := newEnv(t, l)
	b := e.raw().register(protocol.MaxPrekeyLifetime)

	e.want(e.do("GET", b.path("/messages"), nil, b.pass(1)), http.StatusOK, "")
	e.limited(e.do("GET", b.path("/messages"), nil, b.pass(1)), protocol.QuotaPolls)

	e.want(e.do("GET", b.path("/acl"), nil, b.pass(1)), http.StatusOK, "")
	e.limited(e.do("GET", b.path("/acl"), nil, b.pass(1)), protocol.QuotaCalls)

	// The send's count is taken before its pass is read; a send with none is
	// a check that failed, one of the address's misses.
	e.want(e.do("POST", b.path("/messages"), nil, ""), http.StatusUnauthorized, "")
	e.limited(e.do("POST", b.path("/messages"), nil, ""), protocol.QuotaSendsBeforePass)

	e.want(e.do("GET", "/v1/"+strings.Repeat("1", 64), nil, ""), http.StatusNotFound, protocol.CodeNoSuchMailbox)
	e.limited(e.do("GET", "/v1/"+strings.Repeat("2", 64), nil, ""), protocol.QuotaMisses)

	// The registration came from this address, so its count is spent.
	r := e.raw()
	r.prekey(1, e.clock.Now().Add(protocol.PrekeyLifetime), nil)
	e.limited(e.do("PUT", r.path(""), r.registration(1), r.pass(1)), protocol.QuotaRegistrations)
}

// A refusal of a box's calls gives the longest wait among the box's other
// counts in memory that the same call would spend, under that count's name
// (RFC 8555 §6.6; IronGall-dev/irongall-server#56): a send's sends a day, a
// renewal's renewals a day. A box whose other counts are not spent is told
// the calls' wait.
func TestARefusalGivesTheLongestWait(t *testing.T) {
	l := relaxed()
	l.CallBurst, l.CallRefill = 1, time.Minute
	l.SendsPerDay, l.RenewalsPerDay = 1, 1
	e := newEnv(t, l)
	a, b, c := e.box(protocol.Classic), e.box(protocol.Classic), e.box(protocol.Classic)
	to := "/v1/" + b.Address().String()

	e.want(e.do("POST", to+"/messages", e.sealTo(b), e.pass(a)), http.StatusCreated, "")
	got := e.do("POST", to+"/messages", e.sealTo(b), e.pass(a))
	e.limited(got, protocol.QuotaSends)
	if w := waits(got); w < 23*3600 || w > 24*3600 {
		t.Fatalf("a send past its calls and its sends waits %d s, want the sends' day", w)
	}
	var p protocol.Problem
	if err := json.Unmarshal(got.body, &p); err != nil || p.Limit == nil || *p.Limit != 1 {
		t.Fatalf("the sends' refusal carries no limit: %s", got.body)
	}
	// The control: a box that has sent nothing is told its calls' wait.
	e.want(e.do("GET", "/v1/"+c.Address().String()+"/acl", nil, e.pass(c)), http.StatusOK, "")
	got = e.do("POST", to+"/messages", e.sealTo(b), e.pass(c))
	e.limited(got, protocol.QuotaCalls)
	if w := waits(got); w > 60 {
		t.Fatalf("a send past its calls alone waits %d s, want the calls' minute", w)
	}

	r := e.raw().register(protocol.MaxPrekeyLifetime)
	until := e.clock.Now().Add(protocol.PrekeyLifetime)
	r.prekeyUnder(r.work[1], 2, until, nil)
	e.want(e.do("PUT", r.path("/prekey"), r.upload(2), r.pass(1)), http.StatusOK, "")
	r.prekeyUnder(r.work[1], 3, until, nil)
	got = e.do("PUT", r.path("/prekey"), r.upload(3), r.pass(1))
	e.limited(got, protocol.QuotaRenewals)
	if w := waits(got); w < 23*3600 {
		t.Fatalf("a renewal past its calls and its renewals waits %d s, want the renewals' day", w)
	}
}

// A registration is counted by the caller's IPv6 /48 as well as by its /64
// (IronGall-dev/irongall-server#57): a /48 cannot register more by moving
// from one /64 to the next, a refusal by either spends neither, and an IPv4
// address has no /48 count. The operator's clear forgets both.
func TestRegistrationsAreCountedByTheRange(t *testing.T) {
	l := relaxed()
	l.RegistrationsPerHour, l.RangeRegistrationsPerHour = 2, 3
	e := newEnv(t, l)
	call := e.caller()
	register := func(ip string) reply {
		t.Helper()
		r := e.raw()
		r.prekey(1, e.clock.Now().Add(protocol.PrekeyLifetime), nil)
		return call(ip, "PUT", r.path(""), r.registration(1), r.pass(1))
	}
	e.want(register("2001:db8:1:1::1"), http.StatusCreated, "")
	e.want(register("2001:db8:1:1::2"), http.StatusCreated, "") // the same /64
	e.limited(register("2001:db8:1:1::3"), protocol.QuotaRegistrations)
	e.want(register("2001:db8:1:2::1"), http.StatusCreated, "") // another /64, the same /48: its third
	e.limited(register("2001:db8:1:3::1"), protocol.QuotaRegistrationsRange)
	e.limited(register("2001:db8:1:3::1"), protocol.QuotaRegistrationsRange) // what was refused spent nothing of its /64
	e.want(register("2001:db8:2:1::1"), http.StatusCreated, "")              // another /48
	for range 2 {
		e.want(register("192.0.2.9"), http.StatusCreated, "")
	}
	e.limited(register("192.0.2.9"), protocol.QuotaRegistrations)

	if _, cleared, _ := e.server.ClearAddress("2001:db8:1:3::5"); strings.Join(cleared, ",") != "registrations_range" {
		t.Fatalf("clearing an address in a spent /48 cleared %v", cleared)
	}
	e.want(register("2001:db8:1:3::1"), http.StatusCreated, "")
}

// Every call with no pass, and every request no route matches, the link page
// and a site's pages among them, spends one flood budget of its caller's
// address (IronGall-dev/irongall-server#58), refused rate_limited naming
// requests. A call with a pass spends its box's budgets, never this one, and
// another address's budget is its own.
func TestTheFloodBudget(t *testing.T) {
	l := relaxed()
	l.RequestBurst, l.RequestRefill = 6, time.Second
	e := newEnv(t, l)
	b := e.raw().register(protocol.MaxPrekeyLifetime)
	call := e.caller()
	const ip = "198.51.100.4"
	for _, c := range []struct {
		method, path string
		status       int
	}{
		{"GET", b.path(""), http.StatusOK},
		{"GET", b.path("/revocations"), http.StatusNotFound},
		{"PUT", b.path("/revocations"), http.StatusBadRequest},
		{"GET", protocol.LinkPath + b.id.Address().String(), http.StatusOK},
		{"GET", "/v1/" + b.id.Address().String() + "/nothing/here", http.StatusNotFound},
		{"GET", "/nothing", http.StatusNotFound},
	} {
		if got := call(ip, c.method, c.path, nil, ""); got.status != c.status {
			t.Fatalf("%s %s: %d, want %d: %s", c.method, c.path, got.status, c.status, got.body)
		}
	}
	got := call(ip, "GET", b.path(""), nil, "")
	e.limited(got, protocol.QuotaRequests)
	if w := waits(got); w != 1 {
		t.Fatalf("the flood budget's wait: %d s, want 1", w)
	}
	e.limited(call(ip, "GET", "/nothing", nil, ""), protocol.QuotaRequests)
	e.limited(call(ip, "GET", protocol.LinkPath+b.id.Address().String(), nil, ""), protocol.QuotaRequests)
	if got := call(ip, "GET", b.path("/messages"), nil, b.pass(1)); got.status != http.StatusOK {
		t.Fatalf("a call with a pass from a flooding address: %d %s", got.status, got.body)
	}
	if got := call("198.51.100.5", "GET", b.path(""), nil, ""); got.status != http.StatusOK {
		t.Fatalf("another address: %d %s", got.status, got.body)
	}
	e.clock.Add(time.Second)
	e.want(call(ip, "GET", b.path(""), nil, ""), http.StatusOK, "")
	if _, cleared, _ := e.server.ClearAddress(ip); strings.Join(cleared, ",") != "requests" {
		t.Fatalf("clearing a flooding address cleared %v", cleared)
	}
}

// The operator lists the keys a limit holds deepest in debt now, deepest
// first, by the limit's name (limits top): which box takes the most new mail,
// say. It keeps nothing, and knows every limit by the name a refusal gives it.
func TestLimitsTop(t *testing.T) {
	l := relaxed()
	l.ReceiveBurst, l.ReceiveRefill = 10, time.Minute
	e := newEnv(t, l)
	a, b, c := e.box(protocol.Classic), e.box(protocol.Classic), e.box(protocol.Classic)
	for range 3 {
		e.want(e.do("POST", "/v1/"+b.Address().String()+"/messages", e.sealTo(b), e.pass(a)), http.StatusCreated, "")
	}
	e.want(e.do("POST", "/v1/"+c.Address().String()+"/messages", e.sealTo(c), e.pass(a)), http.StatusCreated, "")
	top, ok := e.server.Top(string(protocol.CodeMailboxBusy), 1)
	if !ok || len(top) != 1 || top[0].Key != b.Address().String() || top[0].FullIn != 180 {
		t.Fatalf("the top of mailbox_busy: %+v %v, want b, full in 180 s", top, ok)
	}
	if top, _ := e.server.Top(string(protocol.CodeMailboxBusy), 5); len(top) != 2 || top[1].Key != c.Address().String() {
		t.Fatalf("the top two of mailbox_busy: %+v", top)
	}
	for _, q := range protocol.Quotas() {
		if _, ok := e.server.Top(string(q), 1); !ok {
			t.Errorf("limits top does not know the limit %s", q)
		}
	}
	if _, ok := e.server.Top("nonsense", 1); ok {
		t.Fatal("limits top knows a limit that is none")
	}
}

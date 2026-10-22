package server

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/IronGall-dev/irongall-client/protocol"
)

// Posts of the same ciphertext from one sender in flight at once are one
// call (IronGall-dev/irongall-server#76): the second waits for the first and
// is answered 200 with its receipt, never refused by a quota the first one
// spent (PROTOCOL.md §8), for the sends a day, the pair cap and the box's
// new mail alike. Another sender's post of the same bytes is its own, and is
// answered 409 by the dedupe or the write.
func TestPostsOfTheSameBytesInFlightAreOneCall(t *testing.T) {
	for _, c := range []struct {
		name string
		set  func(*Limits)
	}{
		{"sends a day", func(l *Limits) { l.SendsPerDay = 2 }},
		{"the pair cap", func(l *Limits) { l.PairCap = 2 }},
		{"the box's new mail", func(l *Limits) { l.ReceiveBurst, l.ReceiveRefill = 2, time.Hour }},
	} {
		l := relaxed()
		l.PairCap, l.BoxCap = 0, 0
		c.set(&l)
		e := newEnv(t, l, func(cfg *Config) { cfg.Store = slowPut{cfg.Store, 40 * time.Millisecond} })
		for i := range 5 {
			to, from := e.raw().register(protocol.MaxPrekeyLifetime), e.raw().register(protocol.MaxPrekeyLifetime)
			e.want(e.sendTo(to, 1, 1, from, 1), http.StatusCreated, "") // one of each budget spent
			ct := sealFor(t, to, 1)
			var r1, r2 reply
			var wg sync.WaitGroup
			wg.Add(2)
			go func() { defer wg.Done(); r1 = e.do("POST", to.path("/messages"), sealedTo(1, 1, ct), from.pass(1)) }()
			time.Sleep(5 * time.Millisecond)
			go func() { defer wg.Done(); r2 = e.do("POST", to.path("/messages"), sealedTo(1, 1, ct), from.pass(1)) }()
			wg.Wait()
			if got := fmt.Sprint(r1.status, " ", r2.status); got != "201 200" {
				t.Errorf("%s, trial %d: the same bytes posted twice at once answered %s %s, %s %s; want 201 and 200", c.name, i, got, r1.code(), r2.code(), r2.body)
			}
		}
	}

	e := newEnv(t, relaxed(), func(cfg *Config) { cfg.Store = slowPut{cfg.Store, 40 * time.Millisecond} })
	to, a, b := e.raw().register(protocol.MaxPrekeyLifetime), e.raw().register(protocol.MaxPrekeyLifetime), e.raw().register(protocol.MaxPrekeyLifetime)
	ct := sealFor(t, to, 1)
	var ra, rb reply
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); ra = e.do("POST", to.path("/messages"), sealedTo(1, 1, ct), a.pass(1)) }()
	time.Sleep(5 * time.Millisecond)
	go func() { defer wg.Done(); rb = e.do("POST", to.path("/messages"), sealedTo(1, 1, ct), b.pass(1)) }()
	wg.Wait()
	if got := fmt.Sprint(ra.status, " ", rb.status); got != "201 409" && got != "409 201" {
		t.Errorf("the same bytes from two senders at once answered %s; want 201 and 409, whichever won", got)
	}

	// A sender at its sends a day and one with sends left post the same
	// bytes at once: the second is never handed the first one's refusal.
	l := relaxed()
	l.SendsPerDay = 1
	e = newEnv(t, l, func(cfg *Config) { cfg.Store = slowDedupe{cfg.Store, 40 * time.Millisecond} })
	to, spent, fresh := e.raw().register(protocol.MaxPrekeyLifetime), e.raw().register(protocol.MaxPrekeyLifetime), e.raw().register(protocol.MaxPrekeyLifetime)
	e.want(e.sendTo(to, 1, 1, spent, 1), http.StatusCreated, "")
	ct = sealFor(t, to, 1)
	wg.Add(2)
	go func() { defer wg.Done(); ra = e.do("POST", to.path("/messages"), sealedTo(1, 1, ct), spent.pass(1)) }()
	time.Sleep(5 * time.Millisecond)
	go func() { defer wg.Done(); rb = e.do("POST", to.path("/messages"), sealedTo(1, 1, ct), fresh.pass(1)) }()
	wg.Wait()
	if ra.status != http.StatusTooManyRequests || rb.status != http.StatusCreated {
		t.Errorf("a sender at its limit and one with sends left posting the same bytes at once: %d %s and %d %s; want 429 and 201", ra.status, ra.code(), rb.status, rb.code())
	}
}

// revokedBetween revokes box a, once, just before the first read of its
// record once set: in a send, the read after its pass's check.
type revokedBetween struct {
	Store
	a    protocol.Address
	rv   *Revocations
	done atomic.Bool
}

func (s *revokedBetween) Box(ctx context.Context, a protocol.Address) (*Box, error) {
	if a == s.a && s.done.CompareAndSwap(false, true) {
		if err := s.Store.Revoke(ctx, a, s.rv); err != nil {
			return nil, err
		}
	}
	return s.Store.Box(ctx, a)
}

// A sender revoked between its pass's check and the send's read of its
// record is refused there, as its pass's check would have refused it
// (sender), and its mail is not taken.
func TestASenderRevokedDuringItsSendIsRefused(t *testing.T) {
	s := &revokedBetween{}
	e := newEnv(t, relaxed(), func(c *Config) { s.Store, c.Store = c.Store, s })
	to, from := e.raw().register(protocol.MaxPrekeyLifetime), e.raw().register(protocol.MaxPrekeyLifetime)
	sig, err := protocol.SignRevocation(from.signer, from.id.Address())
	if err != nil {
		t.Fatal(err)
	}
	s.a, s.rv = from.id.Address(), &Revocations{Identity: from.id.Document(), Address: sig}
	e.want(e.sendTo(to, 1, 1, from, 1), http.StatusForbidden, protocol.CodeSenderRevoked)
	if n, _ := e.store.Count(context.Background(), to.id.Address()); n != 0 {
		t.Errorf("the box took %d messages from a sender revoked during its send", n)
	}
}

// heldDeletes holds every delete of a box's mail until released, counting
// them.
type heldDeletes struct {
	Store
	started, release chan struct{}
	once             sync.Once
	n                atomic.Int64
}

func (s *heldDeletes) DeleteMessages(ctx context.Context, a protocol.Address) error {
	s.n.Add(1)
	s.once.Do(func() { close(s.started) })
	<-s.release
	return s.Store.DeleteMessages(ctx, a)
}

// Revocations sent for a revoked box while its delete is in flight start no
// delete of their own (IronGall-dev/irongall-server#29): they wait for the
// one in flight and are answered 410, and the revoking PUT is answered with
// its delete's result.
func TestPUTsDuringARevocationsDeleteStartNoOther(t *testing.T) {
	hs := &heldDeletes{started: make(chan struct{}), release: make(chan struct{})}
	e := newEnv(t, relaxed(), func(c *Config) { hs.Store, c.Store = c.Store, hs })
	a, b := e.box(protocol.Classic), e.box(protocol.Classic)
	send(t, b, a, "waiting in A's box when it is revoked")
	rec := record(t, a)
	path := revocationPath(a.Address())
	junk := protocol.Revocations{Identity: rec.Identity, Revocation: []byte("not a signature")}

	owner := make(chan reply, 1)
	go func() { owner <- e.do("PUT", path, rec, "") }()
	<-hs.started // the owner's delete is under way, and memory still shows the mail
	const k = 8
	codes := make(chan string, k)
	for range k {
		go func() {
			r := e.do("PUT", path, junk, "")
			codes <- fmt.Sprint(r.status, " ", r.code())
		}()
	}
	time.Sleep(300 * time.Millisecond) // for the PUTs to reach a delete of their own, if they would
	close(hs.release)
	for range k {
		if got := <-codes; got != "410 revoked" {
			t.Errorf("a PUT during the delete: %s", got)
		}
	}
	e.want(<-owner, http.StatusCreated, "")
	if n := hs.n.Load(); n != 1 {
		t.Errorf("%d PUTs during one delete drew %d deletes of the box's mail; want 1", k, n)
	}
}

// On DynamoDB: a duplicate whose dedupe read missed an item acked meanwhile
// puts the body again, and the write that finds the item not live deletes it
// (IronGall-dev/irongall-server#16). The message is not served either way.
func TestADuplicateAfterAnAckLeavesNoBody(t *testing.T) {
	e, s := dynamoEnv(t)
	ctx := context.Background()
	a, b := e.box(protocol.Classic), e.box(protocol.Classic)
	body := []byte("acked, then posted again")
	id := idOf(t, send(t, a, b, string(body)))
	if res := receive(t, b); len(res.Delivered) != 1 {
		t.Fatalf("delivered %d", len(res.Delivered))
	}
	now := e.clock.Now().UTC().Truncate(time.Millisecond)
	h := &Header{ID: id, From: a.Address(), Size: 1, ReceivedAt: now, ExpiresAt: now.Add(protocol.Retention)}
	orig, err := s.PutMessage(ctx, b.Address(), h, []byte("the duplicate's body"))
	if err != nil || orig == nil {
		t.Fatalf("the duplicate's write: %v, %v; want the original's header", orig, err)
	}
	if s.bodyExists(t, b.Address(), id) {
		t.Error("a duplicate after the message's ack left its body in the bucket")
	}
}

// slowDedupe makes every dedupe read take d, so that a post refused at its
// counts is refused after a post that came later has reached its own.
type slowDedupe struct {
	Store
	d time.Duration
}

func (s slowDedupe) Dedupe(ctx context.Context, box protocol.Address, id [32]byte) (*Header, error) {
	time.Sleep(s.d)
	return s.Store.Dedupe(ctx, box, id)
}

// slowRead makes a read of address x take a while.
type slowRead struct {
	Store
	x protocol.Address
}

func (s slowRead) Box(ctx context.Context, a protocol.Address) (*Box, error) {
	if a == s.x {
		time.Sleep(300 * time.Millisecond)
	}
	return s.Store.Box(ctx, a)
}

// A lookup that waits on another's read of the same address, whose caller
// was refused before reading, makes its own read: it is never handed the
// refusal of another caller's address (lookup).
func TestALookupIsNeverRefusedForAnotherCallersMisses(t *testing.T) {
	l := relaxed()
	l.MissesPerMinute = 1
	var x, y protocol.Address
	x[0], y[0] = 9, 10
	e := newEnv(t, l, func(c *Config) { c.Store, c.TrustedProxies = slowRead{c.Store, x}, loopback })
	from := func(ip string, a protocol.Address) chan int {
		got := make(chan int, 1)
		go func() {
			req, _ := http.NewRequest(http.MethodGet, e.srv.URL+"/v1/"+a.String(), nil)
			req.Header.Set("CF-Connecting-IP", ip)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				got <- 0
				return
			}
			_ = resp.Body.Close()
			got <- resp.StatusCode
		}()
		return got
	}
	first := from("192.0.2.1", x) // holds the caller's one miss while its read is slow
	time.Sleep(50 * time.Millisecond)
	refused := from("192.0.2.1", y) // waits for that miss to settle, then is refused
	time.Sleep(50 * time.Millisecond)
	other := from("192.0.2.2", y) // joins that read of y
	if got := <-first; got != http.StatusNotFound {
		t.Fatalf("the first lookup: %d", got)
	}
	if got := <-refused; got != http.StatusTooManyRequests {
		t.Fatalf("the lookup past its address's misses: %d; the test wants it refused", got)
	}
	if got := <-other; got != http.StatusNotFound {
		t.Errorf("a lookup from another address, joined to a read whose caller was refused: %d, want 404", got)
	}
}

// alwaysRead holds nothing in memory, so every lookup reads, and holds each
// read until two have begun.
type alwaysRead struct {
	Store
	begun chan struct{}
}

func (s alwaysRead) Known(protocol.Address) (*Box, bool) { return nil, false }

func (s alwaysRead) Box(ctx context.Context, a protocol.Address) (*Box, error) {
	s.begun <- struct{}{}
	time.Sleep(100 * time.Millisecond)
	return s.Store.Box(ctx, a)
}

// Lookups that share a read each get a copy of their own of the record, since
// a caller may change the one it has (a renewal does).
func TestLookupsThatShareAReadGetCopiesOfTheirOwn(t *testing.T) {
	e := newEnv(t, relaxed())
	b := e.raw().register(protocol.MaxPrekeyLifetime)
	s := New(Config{Store: alwaysRead{e.store, make(chan struct{}, 2)}, Limits: relaxed(), Now: e.clock.Now})
	req := httptest.NewRequest(http.MethodGet, b.path(""), nil)
	var got [2]*Box
	var wg sync.WaitGroup
	for i := range got {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var err error
			if got[i], err = s.lookup(req, b.id.Address()); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if got[0] == nil || got[0] == got[1] {
		t.Errorf("two lookups that shared a read got %p and %p; want two copies", got[0], got[1])
	}
}

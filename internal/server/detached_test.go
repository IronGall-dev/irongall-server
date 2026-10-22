package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"

	"filippo.io/age"
	"github.com/IronGall-dev/irongall-client/protocol"
	"github.com/aws/smithy-go"
)

// heldTillGone holds a write, while armed, until its request's context has
// ended, then makes it and returns the error its own context gives, as the
// AWS SDK does when its caller goes after the request went out. The
// in-memory store ignores contexts, so this is what shows whose context a
// write runs on.
type heldTillGone struct {
	Store
	armed   atomic.Bool
	req     chan context.Context // the request's, from the middleware
	entered chan struct{}
	cut     atomic.Int32 // writes whose own context ended with their request's
}

func (h *heldTillGone) hold(ctx context.Context) bool {
	if !h.armed.Load() {
		return false
	}
	rc := <-h.req
	h.entered <- struct{}{}
	<-rc.Done()
	if ctx.Err() != nil {
		h.cut.Add(1)
	}
	return true
}

func (h *heldTillGone) PutMessage(ctx context.Context, box protocol.Address, hd *Header, body []byte) (*Header, error) {
	held := h.hold(ctx)
	orig, err := h.Store.PutMessage(ctx, box, hd, body)
	if err != nil || orig != nil || !held {
		return orig, err
	}
	return nil, ctx.Err()
}

func (h *heldTillGone) UpdateBox(ctx context.Context, b *Box) error {
	held := h.hold(ctx)
	if err := h.Store.UpdateBox(ctx, b); err != nil || !held {
		return err
	}
	return ctx.Err()
}

// sealFor is an age file sealed to raw box to's prekey of the given serial.
func sealFor(t *testing.T, to *raw, serial uint64) []byte {
	t.Helper()
	var ct bytes.Buffer
	w, err := age.Encrypt(&ct, to.keys[serial].Recipient())
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.WriteString(w, `{"v":1}`)
	_ = w.Close()
	return ct.Bytes()
}

// A write runs to its end however its caller goes, and what it changed is
// counted (IronGall-dev/irongall-server#14): a send and a renewal whose
// callers hang up while each is being written are stored, and each spends
// its count, so the next one is refused.
func TestAWriteOutlivesItsCallersHangUp(t *testing.T) {
	ctx0 := context.Background()
	l := relaxed()
	l.SendsPerDay, l.RenewalsPerDay = 1, 1
	h := &heldTillGone{req: make(chan context.Context, 1), entered: make(chan struct{}, 1)}
	e := newEnv(t, l, func(c *Config) { h.Store, c.Store = c.Store, h })
	done := make(chan struct{}, 8)
	e.setMiddle(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
		held := h.armed.Load()
		if held {
			h.req <- r.Context()
		}
		next.ServeHTTP(w, r)
		if held {
			done <- struct{}{}
		}
	})
	hangUp := func(method, path, ctype string, body []byte, pass string) {
		t.Helper()
		ctx, cancel := context.WithCancel(ctx0)
		h.armed.Store(true)
		gone := make(chan struct{})
		go func() {
			defer close(gone)
			req, _ := http.NewRequestWithContext(ctx, method, e.srv.URL+path, bytes.NewReader(body))
			req.Header.Set("Content-Type", ctype)
			req.Header.Set("Authorization", pass)
			if resp, err := http.DefaultClient.Do(req); err == nil {
				_ = resp.Body.Close()
			}
		}()
		<-h.entered
		h.armed.Store(false)
		cancel()
		<-gone
		<-done // the handler has returned
		if n := h.cut.Swap(0); n != 0 {
			t.Errorf("%s %s: the write ran on its request's context, which ended with it", method, path)
		}
	}

	from, to := e.raw().register(protocol.MaxPrekeyLifetime), e.raw().register(protocol.MaxPrekeyLifetime)
	hangUp("POST", to.path("/messages?")+sealedTo(1, 1, nil).Encode(), protocol.CiphertextContentType, sealFor(t, to, 1), from.pass(1))
	if n, _ := e.store.Count(ctx0, to.id.Address()); n != 1 {
		t.Fatalf("a send whose caller hung up mid-write: the box holds %d messages", n)
	}
	e.want(e.sendTo(to, 1, 1, from, 1), http.StatusTooManyRequests, protocol.CodeRateLimited)

	r := e.raw().register(protocol.MaxPrekeyLifetime)
	r.prekeyUnder(r.work[1], 2, e.clock.Now().Add(protocol.MaxPrekeyLifetime), nil)
	up, _ := json.Marshal(r.upload(2))
	hangUp("PUT", r.path("/prekey"), "application/json", up, r.pass(1))
	if b, _ := e.store.Box(ctx0, r.id.Address()); b.Prekey.Serial != 2 {
		t.Fatalf("a renewal whose caller hung up mid-write: the box is at prekey %d", b.Prekey.Serial)
	}
	r.prekeyUnder(r.work[1], 3, e.clock.Now().Add(protocol.MaxPrekeyLifetime), nil)
	e.want(e.do("PUT", r.path("/prekey"), r.upload(3), r.pass(1)), http.StatusTooManyRequests, protocol.CodeRateLimited)

	// An ACL put whose caller hangs up while it is written still deletes
	// the mail its deny list matches, which comes after the write.
	denied := e.raw().register(protocol.MaxPrekeyLifetime)
	e.want(e.sendTo(r, 2, 1, denied, 1), http.StatusCreated, "")
	acl, _ := json.Marshal(aclOf(1, []string{"*"}, []string{denied.id.Address().String()}))
	hangUp("PUT", r.path("/acl"), "application/json", acl, r.pass(1))
	if n, _ := e.store.Count(ctx0, r.id.Address()); n != 0 {
		t.Errorf("an ACL put whose caller hung up mid-write left %d messages from the sender it denies", n)
	}

	// The owner's delete, whose mark is held, and whose second pass over the
	// mail comes after it.
	hangUp("DELETE", r.path(""), "", nil, r.pass(1))
	if b, _ := e.store.Box(ctx0, r.id.Address()); b.State != Deleted {
		t.Errorf("a delete whose caller hung up mid-write left the box %s", b.State)
	}
}

// aroundADelete runs hooks inside a box's delete and a send: before each
// PutMessage and UpdateBox, and it fails the DeleteMessages call of the
// number set.
type aroundADelete struct {
	Store
	mu         sync.Mutex
	put        func()
	update     func(*Box)
	deletes    int
	failDelete int
}

func (s *aroundADelete) set(f func(*aroundADelete)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f(s)
}

func (s *aroundADelete) PutMessage(ctx context.Context, box protocol.Address, h *Header, body []byte) (*Header, error) {
	s.mu.Lock()
	f := s.put
	s.put = nil
	s.mu.Unlock()
	if f != nil {
		f()
	}
	return s.Store.PutMessage(ctx, box, h, body)
}

func (s *aroundADelete) UpdateBox(ctx context.Context, b *Box) error {
	s.mu.Lock()
	f := s.update
	s.update = nil
	s.mu.Unlock()
	if f != nil {
		f(b)
	}
	return s.Store.UpdateBox(ctx, b)
}

func (s *aroundADelete) DeleteMessages(ctx context.Context, a protocol.Address) error {
	s.mu.Lock()
	s.deletes++
	fail := s.deletes == s.failDelete
	s.mu.Unlock()
	if fail {
		return errors.New("injected: a delete that failed")
	}
	return s.Store.DeleteMessages(ctx, a)
}

// Mail sent around a box's delete does not outlive it
// (IronGall-dev/irongall-server#15): a send that writes after the box is
// marked deleted deletes what it wrote and is answered 404; one that writes
// between the delete's first pass over the mail and the mark is deleted by
// the second; and what a second pass that failed left is deleted when the
// delete is undone, so the box comes back with no mail. A send that writes
// after the box's address is revoked is answered 410 and leaves nothing.
func TestMailSentAroundADeleteDoesNotOutliveIt(t *testing.T) {
	ctx0 := context.Background()
	s := &aroundADelete{}
	e := newEnv(t, relaxed(), func(c *Config) { s.Store, c.Store = c.Store, s })
	undo := func(owner *raw) {
		t.Helper()
		owner.prekey(2, e.clock.Now().Add(protocol.MaxPrekeyLifetime), nil)
		e.want(e.do("PUT", owner.path(""), owner.registration(2), owner.pass(2)), http.StatusCreated, "")
		if l := listOf(t, e.do("GET", owner.path("/messages"), nil, owner.pass(2))); l.Count != 0 {
			t.Errorf("the box came back from its delete holding %d messages", l.Count)
		}
	}

	// A send that writes after the mark.
	owner, from := e.raw().register(protocol.MaxPrekeyLifetime), e.raw().register(protocol.MaxPrekeyLifetime)
	writing, release := make(chan struct{}), make(chan struct{})
	s.set(func(s *aroundADelete) { s.put = func() { close(writing); <-release } })
	sent := make(chan reply, 1)
	go func() { sent <- e.sendTo(owner, 1, 1, from, 1) }()
	<-writing
	e.want(e.do("DELETE", owner.path(""), nil, owner.pass(1)), http.StatusNoContent, "")
	close(release)
	e.want(<-sent, http.StatusNotFound, protocol.CodeNoSuchMailbox)
	if n, _ := e.store.Count(ctx0, owner.id.Address()); n != 0 {
		t.Errorf("a send that wrote after the mark left %d messages", n)
	}
	undo(owner)

	// A send that writes between the first pass and the mark, then the
	// second pass fails.
	for _, second := range []string{"deletes it", "fails"} {
		owner, from := e.raw().register(protocol.MaxPrekeyLifetime), e.raw().register(protocol.MaxPrekeyLifetime)
		var before reply
		s.set(func(s *aroundADelete) {
			s.deletes, s.failDelete = 0, 0
			if second == "fails" {
				s.failDelete = 2
			}
			s.update = func(b *Box) {
				if b.State == Deleted {
					before = e.sendTo(owner, 1, 1, from, 1) // the box is not marked yet
				}
			}
		})
		e.want(e.do("DELETE", owner.path(""), nil, owner.pass(1)), http.StatusNoContent, "")
		e.want(before, http.StatusCreated, "")
		n, _ := e.store.Count(ctx0, owner.id.Address())
		switch {
		case second == "deletes it" && n != 0:
			t.Errorf("a send that wrote before the mark left %d messages after the second pass", n)
		case second == "fails" && n != 1:
			t.Fatalf("with the second pass failed, the box holds %d messages; the test wants the one left", n)
		}
		undo(owner)
	}

	// A send that writes after the address is revoked.
	owner, from = e.raw().register(protocol.MaxPrekeyLifetime), e.raw().register(protocol.MaxPrekeyLifetime)
	writing, release = make(chan struct{}), make(chan struct{})
	s.set(func(s *aroundADelete) { s.put = func() { close(writing); <-release } })
	go func() { sent <- e.sendTo(owner, 1, 1, from, 1) }()
	<-writing
	sig, err := protocol.SignRevocation(owner.signer, owner.id.Address())
	if err != nil {
		t.Fatal(err)
	}
	e.want(e.do("PUT", owner.path("/revocations"), protocol.Revocations{Identity: owner.id.Document(), Revocation: sig}, ""), http.StatusCreated, "")
	close(release)
	e.want(<-sent, http.StatusGone, protocol.CodeRevoked)
	if n, _ := e.store.Count(ctx0, owner.id.Address()); n != 0 {
		t.Errorf("a send that wrote after the revocation left %d messages", n)
	}
}

// failPut fails each PutMessage with err, while err is set, and writes
// nothing.
type failPut struct {
	Store
	mu  sync.Mutex
	err error
}

func (s *failPut) PutMessage(ctx context.Context, box protocol.Address, h *Header, body []byte) (*Header, error) {
	s.mu.Lock()
	err := s.err
	s.mu.Unlock()
	if err != nil {
		return nil, err
	}
	return s.Store.PutMessage(ctx, box, h, body)
}

// A count reserved for a write is kept when the write may have been applied,
// whatever error it returned, and given back only for a refusal the store
// stated (IronGall-dev/irongall-server#14): a send whose write timed out, or
// met a fault of AWS's own, spends its send a day; one AWS throttled, or
// refused for the call itself, does not.
func TestACountIsKeptWhenItsWriteMayHaveBeenApplied(t *testing.T) {
	for _, c := range []struct {
		name string
		err  error
		kept bool
	}{
		{"a timeout", context.DeadlineExceeded, true},
		{"a fault of AWS's own", &smithy.GenericAPIError{Code: "InternalServerError", Fault: smithy.FaultServer}, true},
		{"an error of no kind the store states", errors.New("injected"), true},
		{"a throttle", &smithy.GenericAPIError{Code: "ProvisionedThroughputExceededException", Fault: smithy.FaultClient}, false},
		{"a refusal of the call", &smithy.GenericAPIError{Code: "ValidationException", Fault: smithy.FaultClient}, false},
		{"a stale record", ErrStale, false},
	} {
		l := relaxed()
		l.SendsPerDay = 1
		s := &failPut{}
		e := newEnv(t, l, func(cfg *Config) { s.Store, cfg.Store = cfg.Store, s })
		from, to := e.raw().register(protocol.MaxPrekeyLifetime), e.raw().register(protocol.MaxPrekeyLifetime)
		s.mu.Lock()
		s.err = c.err
		s.mu.Unlock()
		e.want(e.sendTo(to, 1, 1, from, 1), http.StatusServiceUnavailable, protocol.CodeUnavailable)
		s.mu.Lock()
		s.err = nil
		s.mu.Unlock()
		if got := e.sendTo(to, 1, 1, from, 1); (got.status == http.StatusTooManyRequests) != c.kept {
			t.Errorf("%s: the next send %d %s; want the count kept %v", c.name, got.status, got.code(), c.kept)
		}
	}
}

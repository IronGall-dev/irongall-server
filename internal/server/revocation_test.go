package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/IronGall-dev/irongall-client/client"
	"github.com/IronGall-dev/irongall-client/protocol"
)

// Revocation (PROTOCOL.md §6.3) as this server enforces it: the identity's
// own signature over the fixed statement ends a box for good, with no pass,
// and nothing else does. The server keeps the signature and serves it, so
// that nobody has to take its word that a box is revoked.

func revocationPath(a protocol.Address) string { return "/v1/" + a.String() + "/revocations" }

// record is a box's own revocation, as its owner makes it.
func record(t *testing.T, b *client.Box) *protocol.Revocations {
	t.Helper()
	rec, err := b.Revocation()
	if err != nil {
		t.Fatal(err)
	}
	return rec
}

func TestRevocation(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t, relaxed())
	a, b, c := e.box(protocol.Classic), e.box(protocol.Classic), e.box(protocol.Classic)
	send(t, b, a, "waiting in A's box when it is revoked")
	send(t, a, b, "sent by A before it was revoked")
	passA := e.pass(a)
	rec := record(t, a)
	path := revocationPath(a.Address())

	// Nothing is held about a box that is not revoked, or about no box.
	e.want(e.do("GET", path, nil, ""), 404, protocol.CodeNotRevoked)
	e.want(e.do("GET", revocationPath(protocol.Address{1}), nil, ""), 404, protocol.CodeNoSuchMailbox)

	// What is not a revocation of A, each of it well signed by someone.
	docA, docB := a.Identity().Document(), b.Identity().Document()
	sign := func(by *client.Box, of protocol.Address, namespace string) []byte {
		t.Helper()
		sig, err := protocol.Sign(worker(t, by), protocol.RevocationStatement(of), namespace)
		if err != nil {
			t.Fatal(err)
		}
		return sig
	}
	ofB := record(t, b)
	for name, bad := range map[string]struct {
		body any
		code protocol.Code
	}{
		"a working key of A, under A's certificate": {protocol.Revocations{Identity: docA, Revocation: sign(a, a.Address(), protocol.RevokeNamespace(a.Address()))}, protocol.CodeBadRevocation},
		"B's revocation, with A's document":         {protocol.Revocations{Identity: docA, Revocation: ofB.Revocation}, protocol.CodeBadRevocation},
		"a working key of A, as a prekey statement": {protocol.Revocations{Identity: docA, Revocation: sign(a, a.Address(), protocol.PrekeyNamespace(a.Address()))}, protocol.CodeBadRevocation},
		"not a signature":                           {protocol.Revocations{Identity: docA, Revocation: []byte("revoke it")}, protocol.CodeBadRevocation},
		"B's document":                              {protocol.Revocations{Identity: docB, Revocation: rec.Revocation}, protocol.CodeIdentityMismatch},
		"B's whole record":                          {ofB, protocol.CodeIdentityMismatch},
		"no signature":                              {[]byte(`{"identity":"` + string(mustJSONBytes(t, docA)) + `"}`), protocol.CodeBadRequest},
		"no document":                               {[]byte(`{"revocation":"eA=="}`), protocol.CodeBadRequest},
		"a member the body does not have":           {[]byte(`{"identity":"eA==","revocation":"eA==","reason":"lost"}`), protocol.CodeBadRequest},
		"not JSON":                                  {[]byte(`revoke`), protocol.CodeBadRequest},
	} {
		if r := e.do("PUT", path, bad.body, ""); r.status != 400 || r.code() != bad.code {
			t.Errorf("%s: %d %s, want 400 %s: %s", name, r.status, r.code(), bad.code, r.body)
		}
	}
	// A pass does not revoke, nor does it help: the signature is the authority.
	e.want(e.do("PUT", path, protocol.Revocations{Identity: docA, Revocation: sign(a, a.Address(), protocol.RevokeNamespace(a.Address()))}, passA), 400, protocol.CodeBadRevocation)
	e.want(e.do("PUT", revocationPath(protocol.Address{1}), rec, ""), 400, protocol.CodeIdentityMismatch)
	// After all of that the box is as it was.
	e.want(e.do("GET", path, nil, ""), 404, protocol.CodeNotRevoked)
	if n, _, _ := e.store.Count(ctx, a.Address()); n != 1 {
		t.Fatalf("A holds %d messages before it is revoked, want 1", n)
	}
	send(t, c, a, "A still takes mail")

	// The revocation, with no pass: 201, and the box is gone for good.
	first := e.do("PUT", path, rec, "")
	e.want(first, 201, "")
	if string(first.body) != "{}\n" && string(first.body) != "{}" {
		t.Errorf("the answer to a revocation: %q", first.body)
	}
	stored, err := e.store.Box(ctx, a.Address())
	if err != nil || stored.State != Revoked || string(stored.Revocation) != string(rec.Revocation) {
		t.Fatalf("the record after a revocation: %+v, %v", stored, err)
	}
	if n, _, _ := e.store.Count(ctx, a.Address()); n != 0 {
		t.Errorf("a revoked box still holds %d messages", n)
	}

	// Everyone is told, and anyone who asks is shown why.
	e.want(e.do("GET", "/v1/"+a.Address().String()+"/identity", nil, ""), 410, protocol.CodeRevoked)
	e.want(e.do("GET", "/v1/"+a.Address().String()+"/messages", nil, passA), 410, protocol.CodeRevoked)
	e.want(e.do("DELETE", "/v1/"+a.Address().String(), nil, passA), 410, protocol.CodeRevoked)
	shown := e.do("GET", path, nil, "")
	e.want(shown, 200, "")
	var got protocol.Revocations
	if err := json.Unmarshal(shown.body, &got); err != nil {
		t.Fatal(err)
	}
	if id, err := protocol.VerifyRevocation(a.Address(), got.Identity, got.Revocation); err != nil || id.Address() != a.Address() {
		t.Fatalf("what the server shows for a revoked box does not verify: %v", err)
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(shown.body, &members); err != nil || len(members) != 2 {
		t.Errorf("the record served has %d members, want identity and revocation: %s", len(members), shown.body)
	}

	// The clients meet it and check it for themselves.
	var gone *client.RevokedError
	if _, err := c.Send(ctx, a.Address(), "to a revoked box"); !errors.As(err, &gone) || gone.Address != a.Address() || gone.Own {
		t.Fatalf("a send to a revoked box: %v", err)
	}
	if _, err := a.Send(ctx, c.Address(), "from a revoked box"); !errors.As(err, &gone) || !gone.Own {
		t.Fatalf("a send from a revoked box: %v", err)
	}
	if _, err := a.Receive(ctx); !errors.As(err, &gone) || !gone.Own {
		t.Fatalf("a revoked box's poll: %v", err)
	}
	// Mail A sent before is refused by its reader, who is shown the same proof.
	res := receive(t, b)
	if len(res.Delivered) != 0 || len(res.Refused) != 1 || res.Refused[0].Code != client.RefusedRevoked {
		t.Fatalf("mail from a box revoked since: %+v", res)
	}

	// Nothing brings it back: not a registration, not a new prekey, and a
	// second revocation changes nothing.
	if _, err := a.Rekey(ctx, protocol.Classic); client.Code(err) != protocol.CodeRevoked {
		t.Fatalf("a revoked box's renewal: %v", err)
	}
	e.want(e.do("PUT", path, rec, ""), 200, "")
	e.want(e.do("PUT", path, protocol.Revocations{Identity: docA, Revocation: []byte("revoke it")}, ""), 400, protocol.CodeBadRevocation)
	e.want(e.do("GET", "/v1/"+a.Address().String()+"/identity", nil, ""), 410, protocol.CodeRevoked)
}

// A closed box can be revoked, and then no prekey reopens it.
func TestAClosedBoxIsRevoked(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t, relaxed())
	a := e.box(protocol.Classic)
	e.want(e.do("DELETE", "/v1/"+a.Address().String(), nil, e.pass(a)), 204, "")
	e.want(e.do("GET", revocationPath(a.Address()), nil, ""), 404, protocol.CodeNotRevoked)
	e.want(e.do("PUT", revocationPath(a.Address()), record(t, a), ""), 201, "")
	if _, err := a.Rekey(ctx, protocol.Classic); client.Code(err) != protocol.CodeRevoked {
		t.Fatalf("a prekey for a box closed and then revoked: %v", err)
	}
	e.want(e.do("GET", revocationPath(a.Address()), nil, ""), 200, "")
}

// A body that is not a revocation costs the server a signature check that
// nothing has paid for, so it counts as a lookup of a box that does not
// exist does. A revocation that verifies is never refused for that.
func TestJunkRevocationsAreLimited(t *testing.T) {
	l := relaxed()
	l.MissesPerMinute = 2
	e := newEnv(t, l)
	a := e.box(protocol.Classic)
	junk := protocol.Revocations{Identity: a.Identity().Document(), Revocation: []byte("revoke it")}
	path := revocationPath(a.Address())
	e.want(e.do("PUT", path, junk, ""), 400, protocol.CodeBadRevocation)
	e.want(e.do("PUT", path, junk, ""), 400, protocol.CodeBadRevocation)
	limited := e.do("PUT", path, junk, "")
	e.want(limited, 429, protocol.CodeRateLimited)
	if limited.header.Get("Retry-After") == "" {
		t.Error("a limited revocation carries no Retry-After")
	}
	e.want(e.do("GET", "/v1/"+a.Address().String()+"/identity", nil, ""), 200, "")
	e.clock.Add(protocol.MaxSkew) // long past the limit's minute
	e.want(e.do("PUT", path, record(t, a), ""), 201, "")
}

// No cache may keep an answer of the API: a box's prekey changes daily and a
// box can be revoked at any moment, and a 410 is cacheable unless it says
// otherwise. The page a link opens is the one answer that may be kept.
func TestNoAnswerOfTheAPIIsStored(t *testing.T) {
	e := newEnv(t, relaxed())
	a := e.box(protocol.Classic)
	base := "/v1/" + a.Address().String()
	check := func(r reply, what string) {
		t.Helper()
		if got := r.header.Get("Cache-Control"); got != "no-store" {
			t.Errorf("%s: Cache-Control %q, want no-store", what, got)
		}
	}
	check(e.do("GET", base+"/identity", nil, ""), "an identity")
	check(e.do("GET", base+"/revocations", nil, ""), "a 404")
	check(e.do("GET", base+"/messages", nil, e.pass(a)), "a list")
	check(e.do("GET", base+"/messages", nil, ""), "a 401")
	e.want(e.do("PUT", base+"/revocations", record(t, a), ""), 201, "")
	check(e.do("GET", base+"/identity", nil, ""), "a 410")
	check(e.do("GET", base+"/revocations", nil, ""), "a revocation")
	if got := e.do("GET", protocol.LinkPath+a.Address().String(), nil, "").header.Get("Cache-Control"); got == "no-store" || got == "" {
		t.Errorf("the link page: Cache-Control %q", got)
	}
}

func mustJSONBytes(t *testing.T, b []byte) []byte {
	t.Helper()
	j, err := json.Marshal(protocol.Bytes(b))
	if err != nil {
		t.Fatal(err)
	}
	return j[1 : len(j)-1]
}

// The revocation is in the box's record, so a process that starts later, or
// another one beside this, serves the same proof and the same 410: nothing
// about a revoked box lives only in the memory of the process that took the
// revocation. AWS only: the in-memory store has one process.
func TestARevocationOutlivesTheProcess(t *testing.T) {
	e, _ := dynamoEnv(t)
	a := e.box(protocol.Classic)
	rec := record(t, a)
	e.want(e.do("PUT", revocationPath(a.Address()), rec, ""), 201, "")

	later := startDynamo(t, e.clock.Now) // its memory holds nothing of A
	srv := httptest.NewServer(New(Config{Store: later, Keys: e.keys, Limits: relaxed(), Now: e.clock.Now, Ready: later.Ready}).Handler())
	defer srv.Close()
	e2 := &env{t: t, clock: e.clock, srv: srv}
	e2.want(e2.do("GET", "/v1/"+a.Address().String()+"/identity", nil, ""), 410, protocol.CodeRevoked)
	shown := e2.do("GET", revocationPath(a.Address()), nil, "")
	e2.want(shown, 200, "")
	var got protocol.Revocations
	if err := json.Unmarshal(shown.body, &got); err != nil {
		t.Fatal(err)
	}
	if _, err := protocol.VerifyRevocation(a.Address(), got.Identity, got.Revocation); err != nil || string(got.Revocation) != string(rec.Revocation) {
		t.Fatalf("what a later process shows for a revoked box: %v", err)
	}
	e2.want(e2.do("PUT", revocationPath(a.Address()), rec, ""), 200, "")
}

// countingDeletes wraps a Store and counts DeleteMessages, the read of the
// messages table a revocation draws.
type countingDeletes struct {
	Store
	mu sync.Mutex
	n  int
}

func (s *countingDeletes) DeleteMessages(ctx context.Context, a protocol.Address) error {
	s.mu.Lock()
	s.n++
	s.mu.Unlock()
	return s.Store.DeleteMessages(ctx, a)
}

func (s *countingDeletes) deletes() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.n
}

// A box's own revocation is public: whoever holds it may send it back. The
// server verified it when it stored it, so a body that is byte for byte the
// one held is answered 200 without a second check, a write, or, for a
// revoked box, another read of its messages.
func TestASecondRevocationCostsNothing(t *testing.T) {
	keys, err := NewDevKeys()
	if err != nil {
		t.Fatal(err)
	}
	clk := &clock{t: time.Now().UTC().Truncate(time.Second)}
	cs := &countingDeletes{Store: NewMemStore(clk.Now)}
	e := &env{t: t, clock: clk, keys: keys, store: cs}
	e.server = New(Config{Store: cs, Keys: keys, Limits: relaxed(), Now: clk.Now})
	e.srv = httptest.NewServer(e.server.Handler())
	t.Cleanup(e.srv.Close)

	a := e.box(protocol.Classic)
	rec := record(t, a)
	path := revocationPath(a.Address())

	// The first revocation ends the box and clears its mail: one read.
	e.want(e.do("PUT", path, rec, ""), 201, "")
	if n := cs.deletes(); n != 1 {
		t.Fatalf("a revocation read the messages table %d times, want 1", n)
	}
	// The same revocation again changes nothing, and reads nothing.
	e.want(e.do("PUT", path, rec, ""), 200, "")
	if n := cs.deletes(); n != 1 {
		t.Errorf("a resent revocation read the messages table %d times, want 1", n)
	}
}

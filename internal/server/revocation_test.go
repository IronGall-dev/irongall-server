package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/IronGall-dev/irongall-client/api/apitest"
	"github.com/IronGall-dev/irongall-client/client"
	"github.com/IronGall-dev/irongall-client/protocol"
)

// Revocation (PROTOCOL.md §6.3) as this server enforces it: the identity's
// own signature over the fixed statement ends a box for good, with no pass,
// and nothing else does. The server keeps the signature and serves it, in
// the 410 a read of the box answers, so that nobody has to take its word
// that a box is revoked.

func revocationPath(a protocol.Address) string { return "/v1/" + a.String() + "/revocations" }

func boxPath(a protocol.Address) string { return "/v1/" + a.String() }

// held is the revocation record a read of a box (GET /v1/<address>) shows,
// read as a client reads it: the 200's revocation of certificates, or the
// 410's record. Nil when it shows none.
func held(t *testing.T, r reply) *protocol.Revocations {
	t.Helper()
	switch r.status {
	case 200:
		var b protocol.BoxResponse
		if err := protocol.Unmarshal(r.body, &b); err != nil {
			t.Fatalf("the read of a box: %v: %s", err, r.body)
		}
		return b.Record()
	case 410:
		var p protocol.Problem
		if err := protocol.Unmarshal(r.body, &p); err != nil {
			t.Fatalf("the read of a revoked box: %v: %s", err, r.body)
		}
		return p.Record
	}
	t.Fatalf("the read of a box: %d %s", r.status, r.body)
	return nil
}

// recordOf is the record a 410 carries as it was written, and its members.
func recordOf(t *testing.T, r reply) ([]byte, map[string]json.RawMessage) {
	t.Helper()
	var p struct {
		Record json.RawMessage `json:"record"`
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(r.body, &p); err != nil || json.Unmarshal(p.Record, &members) != nil {
		t.Fatalf("no record in %s", r.body)
	}
	return p.Record, members
}

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
	read := boxPath(a.Address())

	// Nothing is held about a box that is not revoked: its read is 200 and
	// shows none. There is none of no box.
	unrevoked := e.do("GET", read, nil, "")
	e.want(unrevoked, 200, "")
	if got := held(t, unrevoked); got != nil {
		t.Fatalf("a box nobody revoked is read with a revocation: %s", unrevoked.body)
	}
	e.want(e.do("GET", boxPath(protocol.Address{1}), nil, ""), 404, protocol.CodeNoSuchMailbox)

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
	recJSON, _ := json.Marshal(rec)
	for name, bad := range map[string]struct {
		body any
		code protocol.Code
	}{
		"a working key of A, under A's certificate": {protocol.Revocations{Identity: docA, Revocation: sign(a, a.Address(), protocol.RevokeNamespace(a.Address()))}, protocol.CodeBadRevocation},
		"B's revocation, with A's document":         {protocol.Revocations{Identity: docA, Revocation: ofB.Revocation}, protocol.CodeBadRevocation},
		"a working key of A, as a prekey statement": {protocol.Revocations{Identity: docA, Revocation: sign(a, a.Address(), protocol.PrekeyNamespace(a.Address()))}, protocol.CodeBadRevocation},
		"not a signature":                           {protocol.Revocations{Identity: docA, Revocation: []byte("revoke it")}, protocol.CodeBadRevocation},
		"A's own, over the bound":                   {protocol.Revocations{Identity: docA, Revocation: append(append([]byte{}, rec.Revocation...), bytes.Repeat([]byte{'.'}, protocol.MaxSignature+1-len(rec.Revocation))...)}, protocol.CodeBadRevocation},
		"B's document":                              {protocol.Revocations{Identity: docB, Revocation: rec.Revocation}, protocol.CodeIdentityMismatch},
		"B's whole record":                          {ofB, protocol.CodeIdentityMismatch},
		"no signature":                              {[]byte(`{"identity":"` + string(mustJSONBytes(t, docA)) + `"}`), protocol.CodeBadRequest},
		"no document":                               {[]byte(`{"revocation":"eA=="}`), protocol.CodeBadRequest},
		"a member the body does not have":           {[]byte(`{"identity":"eA==","revocation":"eA==","reason":"lost"}`), protocol.CodeBadRequest},
		"not JSON":                                  {[]byte(`revoke`), protocol.CodeBadRequest},
		"a name in another case":                    {bytes.Replace(recJSON, []byte(`"revocation"`), []byte(`"Revocation"`), 1), protocol.CodeBadRequest},
		"a name twice":                              {bytes.Replace(recJSON, []byte(`{`), []byte(`{"revocation":"eA==",`), 1), protocol.CodeBadRequest},
		"a second value after it":                   {append(append([]byte{}, recJSON...), "{}"...), protocol.CodeBadRequest},
		"base64 with its unused bits set":           {unusedBitsSet(t, recJSON), protocol.CodeBadEncoding},
		"a record of another type":                  {bytes.Replace(recJSON, []byte(`"type":"revocation_record"`), []byte(`"type":"revocation"`), 1), protocol.CodeBadRequest},
	} {
		if r := e.do("PUT", path, bad.body, ""); r.status != 400 || r.code() != bad.code {
			t.Errorf("%s: %d %s, want 400 %s: %s", name, r.status, r.code(), bad.code, r.body)
		}
	}
	// A record of another type is refused by name, as a member the body does
	// not have is.
	other := e.do("PUT", path, bytes.Replace(recJSON, []byte(`"type":"revocation_record"`), []byte(`"type":""`), 1), "")
	var p protocol.Problem
	if err := json.Unmarshal(other.body, &p); err != nil || other.status != 400 || p.Code != protocol.CodeBadRequest || p.Member != "type" {
		t.Errorf("a record whose type is empty: %d %s", other.status, other.body)
	}
	// A pass does not revoke, nor does it help: the signature is the authority.
	e.want(e.do("PUT", path, protocol.Revocations{Identity: docA, Revocation: sign(a, a.Address(), protocol.RevokeNamespace(a.Address()))}, passA), 400, protocol.CodeBadRevocation)
	e.want(e.do("PUT", revocationPath(protocol.Address{1}), rec, ""), 400, protocol.CodeIdentityMismatch)
	// After all of that the box is as it was.
	unrevoked = e.do("GET", read, nil, "")
	e.want(unrevoked, 200, "")
	if got := held(t, unrevoked); got != nil {
		t.Fatalf("what was refused is shown: %s", unrevoked.body)
	}
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

	// Everyone is told, and anyone who reads the box is shown why: its 410
	// carries the record.
	shown := e.do("GET", read, nil, "")
	e.want(shown, 410, protocol.CodeRevoked)
	e.want(e.do("GET", "/v1/"+a.Address().String()+"/messages", nil, passA), 410, protocol.CodeRevoked)
	e.want(e.do("DELETE", "/v1/"+a.Address().String(), nil, passA), 410, protocol.CodeRevoked)
	got := held(t, shown)
	if got == nil {
		t.Fatalf("a revoked box is read with no record: %s", shown.body)
	}
	if id, err := protocol.VerifyRevocation(a.Address(), got.Identity, got.Revocation); err != nil || id.Address() != a.Address() || !bytes.Equal(got.Revocation, rec.Revocation) {
		t.Fatalf("what the server shows for a revoked box does not verify: %v", err)
	}
	if written, members := recordOf(t, shown); len(members) != 3 || !bytes.HasPrefix(written, []byte(`{"type":"revocation_record",`)) {
		t.Errorf("the record served has %d members, want its type first, then identity and revocation: %s", len(members), shown.body)
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
	// second revocation changes nothing. Whatever is sent for a revoked box
	// is answered from its record, with no check: nothing could change it.
	if _, err := a.Rekey(ctx, protocol.Classic); !errors.As(err, &gone) || !gone.Own {
		t.Fatalf("a revoked box's renewal: %v", err)
	}
	e.want(e.do("PUT", path, rec, ""), 410, protocol.CodeRevoked)
	e.want(e.do("PUT", path, protocol.Revocations{Identity: docA, Revocation: []byte("revoke it")}, ""), 410, protocol.CodeRevoked)
	e.want(e.do("GET", read, nil, ""), 410, protocol.CodeRevoked)
}

// A closed box can be revoked, and then no prekey reopens it.
func TestAClosedBoxIsRevoked(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t, relaxed())
	a := e.box(protocol.Classic)
	e.want(e.do("DELETE", "/v1/"+a.Address().String(), nil, e.pass(a)), 204, "")
	closed := e.do("GET", boxPath(a.Address()), nil, "")
	e.want(closed, 200, "")
	if got := held(t, closed); got != nil {
		t.Fatalf("a closed box nobody revoked is read with a revocation: %s", closed.body)
	}
	rec := record(t, a)
	e.want(e.do("PUT", revocationPath(a.Address()), rec, ""), 201, "")
	var gone *client.RevokedError
	if _, err := a.Rekey(ctx, protocol.Classic); !errors.As(err, &gone) || !gone.Own {
		t.Fatalf("a prekey for a box closed and then revoked: %v", err)
	}
	shown := e.do("GET", boxPath(a.Address()), nil, "")
	e.want(shown, 410, protocol.CodeRevoked)
	if got := held(t, shown); got == nil || !bytes.Equal(got.Revocation, rec.Revocation) {
		t.Fatalf("a box closed and then revoked is read without its revocation: %s", shown.body)
	}
}

// A revoked box is read as its record: 410 revoked, carrying all this server
// holds that the identity signed about the address, which is the revocation,
// and the revocation of its certificates beside it when one was put. Each
// part is the bytes that were put, and verifies, so a client takes "revoked"
// from the one read with no second call and on none of the server's word.
func TestARevokedBoxIsReadAsItsRecord(t *testing.T) {
	e := newEnv(t, relaxed())
	alone, withCerts := e.raw().register(protocol.MaxPrekeyLifetime), e.raw().register(protocol.MaxPrekeyLifetime)
	certs := withCerts.certs(1)
	e.want(e.do("PUT", withCerts.path("/revocations"), certs, ""), 200, "")
	for name, c := range map[string]struct {
		box     *raw
		put     protocol.Revocations
		members int
	}{
		"revoked alone":                         {alone, protocol.Revocations{Identity: alone.id.Document()}, 3},
		"revoked with its certificates revoked": {withCerts, certs, 5},
	} {
		var err error
		if c.put.Revocation, err = protocol.SignRevocation(c.box.signer, c.box.id.Address()); err != nil {
			t.Fatal(err)
		}
		e.want(e.do("PUT", c.box.path("/revocations"), c.put, ""), 201, "")
		shown := e.do("GET", c.box.path(""), nil, "")
		e.want(shown, 410, protocol.CodeRevoked)
		got := held(t, shown)
		if got == nil || !bytes.Equal(got.Identity, c.box.id.Document()) || !bytes.Equal(got.Revocation, c.put.Revocation) ||
			!bytes.Equal(got.RevokedCertificates, c.put.RevokedCertificates) || !bytes.Equal(got.RevokedCertificatesSignature, c.put.RevokedCertificatesSignature) {
			t.Errorf("%s: the record is not what was put: %s", name, shown.body)
			continue
		}
		if id, err := protocol.VerifyRevocation(c.box.id.Address(), got.Identity, got.Revocation); err != nil || id.Address() != c.box.id.Address() {
			t.Errorf("%s: the revocation in the record does not verify: %v", name, err)
		}
		if len(c.put.RevokedCertificates) > 0 {
			if l, err := protocol.VerifyRevokedCertificates(c.box.id.Address(), got.Identity, got.RevokedCertificates, got.RevokedCertificatesSignature); err != nil || l.Through != 1 {
				t.Errorf("%s: the revocation of certificates in the record does not verify: %+v, %v", name, l, err)
			}
		}
		if written, members := recordOf(t, shown); len(members) != c.members || !bytes.HasPrefix(written, []byte(`{"type":"revocation_record",`)) {
			t.Errorf("%s: the record has %d members, want its type first and %d more: %s", name, len(members), c.members-1, shown.body)
		}
	}
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
	e.want(e.do("GET", boxPath(a.Address()), nil, ""), 200, "")
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
	check(e.do("GET", base, nil, ""), "a box")
	check(e.do("GET", boxPath(protocol.Address{1}), nil, ""), "a 404")
	check(e.do("GET", base+"/messages", nil, e.pass(a)), "a list")
	check(e.do("GET", base+"/messages", nil, ""), "a 401")
	e.want(e.do("PUT", base+"/revocations", record(t, a), ""), 201, "")
	check(e.do("GET", base, nil, ""), "a 410 with its revocation")
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
	srv := httptest.NewServer(apitest.Handler(t, New(Config{Store: later, Keys: e.keys, Limits: relaxed(), Now: e.clock.Now, Ready: later.Ready}).Handler()))
	defer srv.Close()
	e2 := &env{t: t, clock: e.clock, srv: srv}
	shown := e2.do("GET", boxPath(a.Address()), nil, "")
	e2.want(shown, 410, protocol.CodeRevoked)
	got := held(t, shown)
	if got == nil {
		t.Fatalf("a later process reads a revoked box with no record: %s", shown.body)
	}
	if _, err := protocol.VerifyRevocation(a.Address(), got.Identity, got.Revocation); err != nil || string(got.Revocation) != string(rec.Revocation) {
		t.Fatalf("what a later process shows for a revoked box: %v", err)
	}
	e2.want(e2.do("PUT", revocationPath(a.Address()), rec, ""), 410, protocol.CodeRevoked) // and answers what is sent for it from that record
}

// countingDeletes wraps a Store and counts DeleteMessages, the read of the
// messages table a revocation draws. Its next fail calls fail before the
// store is asked, as a store that is down for a moment does.
type countingDeletes struct {
	Store
	mu   sync.Mutex
	n    int
	fail int
}

func (s *countingDeletes) DeleteMessages(ctx context.Context, a protocol.Address) error {
	s.mu.Lock()
	s.n++
	failing := s.fail > 0
	if failing {
		s.fail--
	}
	s.mu.Unlock()
	if failing {
		return errors.New("the delete failed")
	}
	return s.Store.DeleteMessages(ctx, a)
}

func (s *countingDeletes) deletes() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.n
}

// countingEnv is an env whose store counts DeleteMessages.
func countingEnv(t *testing.T) (*env, *countingDeletes) {
	t.Helper()
	keys, err := NewDevKeys()
	if err != nil {
		t.Fatal(err)
	}
	clk := &clock{t: time.Now().UTC().Truncate(time.Second)}
	inner, ready := newTestStore(t, clk.Now)
	cs := &countingDeletes{Store: inner}
	e := &env{t: t, clock: clk, keys: keys, store: cs}
	e.server = New(Config{Store: cs, Keys: keys, Limits: relaxed(), Now: clk.Now, Ready: ready})
	e.srv = httptest.NewServer(apitest.Handler(t, e.server.Handler()))
	t.Cleanup(e.srv.Close)
	return e, cs
}

// A box's own revocation is public: whoever holds it may send it back, as it
// is or as the same signature in other bytes that verify. A revoked box takes
// nothing more, so each is answered 410 from its record with no check, and
// none draws another read of the box's messages: the box holds none.
func TestASecondRevocationReadsNoMail(t *testing.T) {
	e, cs := countingEnv(t)
	a := e.box(protocol.Classic)
	rec := record(t, a)
	path := revocationPath(a.Address())

	// The first revocation ends the box and clears its mail: one read.
	e.want(e.do("PUT", path, rec, ""), 201, "")
	if n := cs.deletes(); n != 1 {
		t.Fatalf("a revocation read the messages table %d times, want 1", n)
	}
	// The same revocation again changes nothing, and reads nothing.
	e.want(e.do("PUT", path, rec, ""), 410, protocol.CodeRevoked)
	if n := cs.deletes(); n != 1 {
		t.Errorf("a resent revocation read the messages table %d times, want 1", n)
	}
	// Nor does the same signature in other bytes: a line feed after its
	// armour, which anyone can add.
	other := *rec
	other.Revocation = append(bytes.Clone(rec.Revocation), '\n')
	e.want(e.do("PUT", path, other, ""), 410, protocol.CodeRevoked)
	if n := cs.deletes(); n != 1 {
		t.Errorf("a revocation resent in other bytes read the messages table %d times, want 1", n)
	}
}

// The record is written before the mail is deleted, so a delete that fails
// leaves a revoked box holding mail. The caller is told it failed, and the
// same revocation again finishes it, answered 410 as anything for a revoked
// box is: memory shows the box holding mail, and that is what a second delete
// is for.
func TestARevocationRetriedAfterAFailedDeleteDeletes(t *testing.T) {
	ctx := context.Background()
	e, cs := countingEnv(t)
	a, b := e.box(protocol.Classic), e.box(protocol.Classic)
	send(t, b, a, "waiting in A's box when it is revoked")
	rec := record(t, a)
	path := revocationPath(a.Address())

	cs.mu.Lock()
	cs.fail = 1
	cs.mu.Unlock()
	if r := e.do("PUT", path, rec, ""); r.status < 500 {
		t.Fatalf("a revocation whose delete failed was answered %d: %s", r.status, r.body)
	}
	if stored, err := e.store.Box(ctx, a.Address()); err != nil || stored.State != Revoked {
		t.Fatalf("after a revocation whose delete failed the box is %+v, %v", stored, err)
	}
	if n, _, err := e.store.Count(ctx, a.Address()); err != nil || n != 1 {
		t.Fatalf("after a revocation whose delete failed the box holds %d messages (%v), want the 1 it had", n, err)
	}
	e.want(e.do("PUT", path, rec, ""), 410, protocol.CodeRevoked)
	if n, _, err := e.store.Count(ctx, a.Address()); err != nil || n != 0 {
		t.Errorf("after the retry the revoked box holds %d messages (%v), want none", n, err)
	}
	// With the box empty, one more reads nothing.
	e.want(e.do("PUT", path, rec, ""), 410, protocol.CodeRevoked)
	if n := cs.deletes(); n != 2 {
		t.Errorf("a revocation, its retry and one more read the messages table %d times, want 2", n)
	}
}

// A revocation of the address may come with the revocation of its
// certificates the box already holds: the record a server shows for an
// address carries both. That is nothing new, and the revocation of the
// address is taken all the same. A part that is not a revocation of
// certificates is refused, with the revocation beside it, and nothing changes.
// Once the box is revoked, anything sent for it is answered from its record.
func TestARevocationComesWithTheCertificatesHeld(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t, relaxed())
	r := e.raw().register(protocol.MaxPrekeyLifetime)
	path := r.path("/revocations")
	both := r.certs(7)
	e.want(e.do("PUT", path, both, ""), 200, "")
	var err error
	if both.Revocation, err = protocol.SignRevocation(r.signer, r.id.Address()); err != nil {
		t.Fatal(err)
	}
	junk := both
	junk.RevokedCertificates, junk.RevokedCertificatesSignature = []byte("not a revocation"), []byte("not a signature")
	e.want(e.do("PUT", path, junk, ""), 400, protocol.CodeBadRevocation)
	if stored, err := e.store.Box(ctx, r.id.Address()); err != nil || stored.State == Revoked {
		t.Fatalf("a revocation that came with something that is not one was taken: %+v, %v", stored, err)
	}
	e.want(e.do("PUT", path, both, ""), 201, "")
	if stored, err := e.store.Box(ctx, r.id.Address()); err != nil || stored.State != Revoked || !bytes.Equal(stored.Revocation, both.Revocation) {
		t.Fatalf("a revocation that came with the certificates' already held was not taken: %+v, %v", stored, err)
	}
	e.want(e.do("PUT", path, junk, ""), 410, protocol.CodeRevoked)
}

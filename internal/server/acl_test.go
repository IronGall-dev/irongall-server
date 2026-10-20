package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/IronGall-dev/irongall-client/api/apitest"
	"github.com/IronGall-dev/irongall-client/client"
	"github.com/IronGall-dev/irongall-client/protocol"
)

// aclOf is an ACL document: the version, and the lists as given.
func aclOf(version uint64, allow, deny []string) protocol.ACLDocument {
	return protocol.ACLDocument{Version: &version, Allow: allow, Deny: deny}
}

// aclReply reads an ACL document out of an answer.
func aclReply(t *testing.T, r reply) protocol.ACLDocument {
	t.Helper()
	var d protocol.ACLDocument
	if err := protocol.Unmarshal(r.body, &d); err != nil {
		t.Fatalf("not an ACL document: %v: %s", err, r.body)
	}
	return d
}

// sealTo is a send to box to, as the server sees one: an age file to its
// current prekey under both its serials. What is inside is the recipient's
// to judge, so a test needs nothing more.
func (e *env) sealTo(to *client.Box) sealed {
	e.t.Helper()
	b, err := e.store.Box(context.Background(), to.Address())
	if err != nil {
		e.t.Fatal(err)
	}
	rcpt, err := b.Prekey.Recipient()
	if err != nil {
		e.t.Fatal(err)
	}
	var ct bytes.Buffer
	w, err := age.Encrypt(&ct, rcpt)
	if err != nil {
		e.t.Fatal(err)
	}
	_, _ = io.WriteString(w, `{"v":1}`)
	_ = w.Close()
	serial, under := e.numbers(to.Address())
	return sealedTo(serial, under, ct.Bytes())
}

// A box's ACL is the box's own to read and replace, whole and only upward;
// one that is not an ACL, or holds more entries than the server takes, is
// refused before anything is stored.
func TestACLRoute(t *testing.T) {
	l := relaxed()
	l.ACLEntries = 3
	e := newEnv(t, l)
	b, other := e.box(protocol.Classic), e.box(protocol.Classic)
	path := "/v1/" + b.Address().String() + "/acl"
	pass := e.pass(b)
	x, y := other.Address().String(), strings.Repeat("ab", 32)

	// The box's own pass, and only that.
	e.want(e.do("GET", path, nil, ""), 401, protocol.CodeUnauthorized)
	e.want(e.do("PUT", path, aclOf(1, []string{"*"}, nil), ""), 401, protocol.CodeUnauthorized)
	e.want(e.do("GET", path, nil, e.pass(other)), 401, protocol.CodeUnauthorized)
	e.want(e.do("PUT", path, aclOf(1, []string{"*"}, nil), e.pass(other)), 401, protocol.CodeUnauthorized)

	// A box that has put none lets everyone in, at version 0.
	got := e.do("GET", path, nil, pass)
	e.want(got, 200, "")
	if string(bytes.TrimSpace(got.body)) != `{"version":0,"allow":["*"],"deny":[]}` {
		t.Fatalf("no ACL: %s", got.body)
	}

	for name, body := range map[string]any{
		"no allow list":      []byte(`{"version":1,"deny":[]}`),
		"allow null":         []byte(`{"version":1,"allow":null}`),
		"no version":         []byte(`{"allow":["*"]}`),
		"version 0":          aclOf(0, []string{"*"}, nil),
		"an uppercase entry": aclOf(1, []string{strings.ToUpper(y)}, nil),
		"a partial pattern":  aclOf(1, []string{"*" + y[1:]}, nil),
		"a member it lacks":  []byte(`{"version":1,"allow":["*"],"block":[]}`),
		"not JSON":           []byte(`allow everyone`),
	} {
		if r := e.do("PUT", path, body, pass); r.status != 400 || r.code() != protocol.CodeBadRequest {
			t.Errorf("%s: %d %s, want 400 %s: %s", name, r.status, r.code(), protocol.CodeBadRequest, r.body)
		}
	}
	// Over the entries, and over the body's bound drawn from them, which is
	// refused before it is parsed: the limit is the entries either way
	// (PROTOCOL.md §13: a too_large on an ACL is entries).
	huge := aclOf(1, []string{"*"}, []string{strings.Repeat(" ", int(e.server.aclBodyLimit()))})
	for _, body := range []any{aclOf(1, []string{"*", x}, []string{y, x}), huge} {
		r := e.do("PUT", path, body, pass)
		e.want(r, 413, protocol.CodeTooLarge)
		if p := r.problem(); p.Limit == nil || *p.Limit != 3 {
			t.Errorf("an ACL over 3 entries is told the limit %v, want its 3 entries: %s", p.Limit, r.body)
		}
	}
	if r := e.do("GET", path, nil, pass); !bytes.Contains(r.body, []byte(`"version":0`)) {
		t.Fatalf("a refused ACL was stored: %s", r.body)
	}

	// Taken: stored and answered in its one form, sorted and each once.
	put := e.do("PUT", path, aclOf(2, []string{y, x, y}, []string{}), pass)
	e.want(put, 200, "")
	lo, hi := min(x, y), max(x, y)
	want := `{"version":2,"allow":["` + lo + `","` + hi + `"],"deny":[]}`
	if string(bytes.TrimSpace(put.body)) != want {
		t.Fatalf("PUT answered %s, want %s", put.body, want)
	}
	if r := e.do("GET", path, nil, pass); string(bytes.TrimSpace(r.body)) != want {
		t.Fatalf("GET answered %s, want %s", r.body, want)
	}
	// Only upward.
	e.want(e.do("PUT", path, aclOf(2, []string{"*"}, nil), pass), 409, protocol.CodeConflict)
	e.want(e.do("PUT", path, aclOf(1, []string{"*"}, nil), pass), 409, protocol.CodeConflict)
	e.want(e.do("PUT", path, aclOf(3, []string{"*"}, nil), pass), 200, "")
	if d := aclReply(t, e.do("GET", path, nil, pass)); *d.Version != 3 || len(d.Allow) != 1 || d.Allow[0] != "*" || d.Deny == nil {
		t.Fatalf("after version 3: %+v", d)
	}

	// The record carries it, as the store writes it and reads it back.
	stored, err := e.store.Box(context.Background(), b.Address())
	if err != nil || stored.ACL == nil || stored.ACL.Version != 3 || !stored.ACL.Allow.Any {
		t.Fatalf("the stored ACL: %+v, %v", stored.ACL, err)
	}
	back, err := decodeBox(item(boxItem(stored)))
	if err != nil || back.ACL == nil || back.ACL.Version != 3 || !back.ACL.SameLists(stored.ACL) {
		t.Fatalf("the ACL does not come back from the record as it went in: %+v, %v", back.ACL, err)
	}
	none, err := e.store.Box(context.Background(), other.Address())
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := boxItem(none)["acl"]; ok {
		t.Fatal("a box with no ACL has one in its record")
	}
	if back, err := decodeBox(item(boxItem(none))); err != nil || back.ACL != nil {
		t.Fatalf("a record with no ACL reads back with one: %+v, %v", back.ACL, err)
	}
}

// With no bound on its entries, an ACL's body is still bounded, to keep the
// record one item: a body over that is too_large with the body's bytes as
// its limit, the one limit there is (PROTOCOL.md §13).
func TestAnUnboundedACLNamesItsBodysBytes(t *testing.T) {
	l := relaxed()
	l.ACLEntries = 0
	e := newEnv(t, l)
	b := e.box(protocol.Classic)
	huge := aclOf(1, []string{"*"}, []string{strings.Repeat(" ", int(e.server.aclBodyLimit()))})
	r := e.do("PUT", "/v1/"+b.Address().String()+"/acl", huge, e.pass(b))
	e.want(r, 413, protocol.CodeTooLarge)
	if p := r.problem(); p.Limit == nil || *p.Limit != uint64(aclBodyUnbounded) {
		t.Errorf("an unbounded ACL's body over its bound is told the limit %v, want its %d bytes: %s", p.Limit, aclBodyUnbounded, r.body)
	}
}

// A send the ACL refuses is refused with one code and one wording, whether
// its sender is denied or only not allowed, before anything of the sender's
// quotas is spent; a sender it lets in is taken.
func TestACLRefusesSends(t *testing.T) {
	l := relaxed()
	l.SendsPerDay = 1
	e := newEnv(t, l)
	a, b, c := e.box(protocol.Classic), e.box(protocol.Classic), e.box(protocol.Classic)
	to := "/v1/" + b.Address().String()
	acl := func(v uint64, allow, deny []string) {
		t.Helper()
		e.want(e.do("PUT", to+"/acl", aclOf(v, allow, deny), e.pass(b)), 200, "")
	}

	acl(1, []string{a.Address().String()}, nil)
	notAllowed := e.do("POST", to+"/messages", e.sealTo(b), e.pass(c))
	e.want(notAllowed, 403, protocol.CodeSenderNotAllowed)
	e.want(e.do("POST", to+"/messages", e.sealTo(b), e.pass(c)), 403, protocol.CodeSenderNotAllowed)
	e.want(e.do("POST", to+"/messages", e.sealTo(b), e.pass(a)), 201, "")

	acl(2, []string{"*"}, []string{a.Address().String()})
	denied := e.do("POST", to+"/messages", e.sealTo(b), e.pass(a))
	e.want(denied, 403, protocol.CodeSenderNotAllowed)
	var p, q protocol.Problem
	_ = json.Unmarshal(notAllowed.body, &p)
	_ = json.Unmarshal(denied.body, &q)
	if p.Detail != q.Detail || p.Hint != q.Hint || p.Title != q.Title {
		t.Fatalf("denied and not allowed tell apart:\n%s\n%s", notAllowed.body, denied.body)
	}
	// c was refused twice under SendsPerDay 1: neither refusal spent its
	// send, which "*" now lets through, and the count then holds.
	e.want(e.do("POST", to+"/messages", e.sealTo(b), e.pass(c)), 201, "")
	e.limited(e.do("POST", to+"/messages", e.sealTo(b), e.pass(c)), protocol.QuotaSends)
}

// A deny list deletes the box's unacked mail from what it matches, and only
// that; a retry of a message stored before is still answered with its
// receipt, since a retry is no new mail (PROTOCOL.md §4.5 step 6).
func TestACLDenyPurges(t *testing.T) {
	e := newEnv(t, relaxed())
	ctx := context.Background()
	a, b, c := e.box(protocol.Classic), e.box(protocol.Classic), e.box(protocol.Classic)
	to := "/v1/" + b.Address().String()
	first := e.sealTo(b)
	stored := e.do("POST", to+"/messages", first, e.pass(a))
	e.want(stored, 201, "")
	e.want(e.do("POST", to+"/messages", e.sealTo(b), e.pass(a)), 201, "")
	e.want(e.do("POST", to+"/messages", e.sealTo(b), e.pass(c)), 201, "")
	count := func(from *client.Box) int {
		t.Helper()
		n, _, err := e.store.PairCount(ctx, b.Address(), from.Address())
		if err != nil {
			t.Fatal(err)
		}
		return n
	}
	if count(a) != 2 || count(c) != 1 {
		t.Fatalf("before: %d from a, %d from c", count(a), count(c))
	}

	e.want(e.do("PUT", to+"/acl", aclOf(1, []string{"*"}, []string{a.Address().String()}), e.pass(b)), 200, "")
	if count(a) != 0 || count(c) != 1 {
		t.Fatalf("after denying a: %d from a, %d from c", count(a), count(c))
	}
	if n, err := e.store.Count(ctx, b.Address()); err != nil || n != 1 {
		t.Fatalf("the box holds %d, %v", n, err)
	}
	retry := e.do("POST", to+"/messages", first, e.pass(a))
	e.want(retry, 200, "")
	if !bytes.Equal(retry.body, stored.body) {
		t.Fatalf("a retry's receipt changed: %s, was %s", retry.body, stored.body)
	}
	e.want(e.do("POST", to+"/messages", e.sealTo(b), e.pass(a)), 403, protocol.CodeSenderNotAllowed)

	// Deny "*": everything goes, and nothing more comes.
	e.want(e.do("PUT", to+"/acl", aclOf(2, []string{"*"}, []string{"*"}), e.pass(b)), 200, "")
	if n, err := e.store.Count(ctx, b.Address()); err != nil || n != 0 {
		t.Fatalf("after denying everyone the box holds %d, %v", n, err)
	}
	e.want(e.do("POST", to+"/messages", e.sealTo(b), e.pass(c)), 403, protocol.CodeSenderNotAllowed)
}

// On DynamoDB, an ACL put through one process reaches another through the
// stream, and that process then refuses what it refuses.
func TestACLReachesAnotherProcess(t *testing.T) {
	e, _ := dynamoEnv(t)
	other := startDynamo(t, e.clock.Now)
	srv2 := httptest.NewServer(apitest.Handler(t, New(Config{Store: other, Limits: relaxed(), Now: e.clock.Now, Ready: other.Ready}).Handler()))
	t.Cleanup(srv2.Close)
	e2 := &env{t: t, clock: e.clock, store: other, srv: srv2}
	a, b := e.box(protocol.Classic), e.box(protocol.Classic)
	to := "/v1/" + b.Address().String()

	// The other process holds b's record, with no ACL in it.
	e2.want(e2.do("POST", to+"/messages", e2.sealTo(b), e2.pass(a)), 201, "")
	e.want(e.do("PUT", to+"/acl", aclOf(1, []string{"*"}, []string{a.Address().String()}), e.pass(b)), 200, "")
	start := time.Now()
	for {
		if rec, ok := other.Known(b.Address()); ok && rec != nil && rec.ACL != nil {
			break
		}
		if time.Since(start) > 15*time.Second {
			t.Fatal("the ACL did not reach the other process within 15 s")
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Logf("an ACL put on one process reached the other in %s", time.Since(start))
	e2.want(e2.do("POST", to+"/messages", e2.sealTo(b), e2.pass(a)), 403, protocol.CodeSenderNotAllowed)
	if d := aclReply(t, e2.do("GET", to+"/acl", nil, e2.pass(b))); *d.Version != 1 || len(d.Deny) != 1 {
		t.Fatalf("the other process answers %+v", d)
	}
}

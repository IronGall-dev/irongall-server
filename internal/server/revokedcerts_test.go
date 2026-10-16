package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http/httptest"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/IronGall-dev/irongall-client/client"
	"github.com/IronGall-dev/irongall-client/protocol"
)

// Revoking certificates (PROTOCOL.md §6.3a) as this server enforces it: the
// identity signs a revocation of every certificate through a serial, with no
// pass, and the address goes on. The server keeps the highest one and serves
// it, takes no pass and no prekey statement under a revoked certificate, and
// sends nobody to a prekey under one.

// certs is the revocation of r's certificates through a serial, signed by its
// identity, in the record that carries it.
func (r *raw) certs(through uint64) protocol.Revocations {
	r.e.t.Helper()
	l, err := protocol.NewRevokedCertificates(r.id.Address(), through)
	if err != nil {
		r.e.t.Fatal(err)
	}
	sig, err := protocol.SignRevokedCertificates(r.signer, l)
	if err != nil {
		r.e.t.Fatal(err)
	}
	return protocol.Revocations{Identity: r.id.Document(), RevokedCertificates: l.Statement(), RevokedCertificatesSignature: sig}
}

// sendTo posts an age file sealed to the prekey of to's given serial, naming
// that serial and a certificate serial, with from's pass under its
// certificate of the serial given.
func (e *env) sendTo(to *raw, serial, under uint64, from *raw, fromUnder uint64) reply {
	e.t.Helper()
	var ct bytes.Buffer
	w, err := age.Encrypt(&ct, to.keys[serial].Recipient())
	if err != nil {
		e.t.Fatal(err)
	}
	_, _ = io.WriteString(w, `{"v":1}`)
	_ = w.Close()
	return e.do("POST", to.path(""), protocol.SendRequest{PrekeySerial: &serial, CertificateSerial: &under, Ciphertext: ct.Bytes()}, from.pass(fromUnder))
}

func TestRevokedCertificates(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t, relaxed())
	now := e.clock.Now()
	r, other := e.raw().register(protocol.MaxPrekeyLifetime), e.raw().register(protocol.MaxPrekeyLifetime)
	put := func(serial, under uint64) reply {
		return e.do("PUT", r.path("/prekey"), r.upload(serial), r.pass(under))
	}
	r.prekey(2, now.Add(protocol.MaxPrekeyLifetime), nil)
	e.want(put(2, 2), 200, "") // the box stands at certificate 2, prekey 2
	path := r.path("/revocations")
	good := r.certs(1)

	// What is not a revocation of this box's certificates, each of it well
	// signed by someone.
	byWork, err := protocol.Sign(r.work[2], good.RevokedCertificates, protocol.RevokedCertsNamespace(r.id.Address()))
	if err != nil {
		t.Fatal(err)
	}
	blank := append(bytes.Clone(good.RevokedCertificates), '\n')
	blankSig, err := protocol.Sign(r.signer, blank, protocol.RevokedCertsNamespace(r.id.Address()))
	if err != nil {
		t.Fatal(err)
	}
	asRevocation, err := protocol.Sign(r.signer, good.RevokedCertificates, protocol.RevokeNamespace(r.id.Address()))
	if err != nil {
		t.Fatal(err)
	}
	theirs := other.certs(1)
	for name, bad := range map[string]struct {
		body any
		code protocol.Code
	}{
		"a working key of the box, under its certificate":  {protocol.Revocations{Identity: r.id.Document(), RevokedCertificates: good.RevokedCertificates, RevokedCertificatesSignature: byWork}, protocol.CodeBadRevocation},
		"another box's, with this box's document":          {protocol.Revocations{Identity: r.id.Document(), RevokedCertificates: theirs.RevokedCertificates, RevokedCertificatesSignature: theirs.RevokedCertificatesSignature}, protocol.CodeBadRevocation},
		"the identity's signature in another namespace":    {protocol.Revocations{Identity: r.id.Document(), RevokedCertificates: good.RevokedCertificates, RevokedCertificatesSignature: asRevocation}, protocol.CodeBadRevocation},
		"a blank line after it, which the identity signed": {protocol.Revocations{Identity: r.id.Document(), RevokedCertificates: blank, RevokedCertificatesSignature: blankSig}, protocol.CodeBadRevocation},
		"another box's whole record":                       {theirs, protocol.CodeIdentityMismatch},
		"a statement and no signature":                     {[]byte(`{"identity":"` + string(mustJSONBytes(t, r.id.Document())) + `","revoked_certificates":"eA=="}`), protocol.CodeBadRequest},
		"a signature and no statement":                     {[]byte(`{"identity":"` + string(mustJSONBytes(t, r.id.Document())) + `","revoked_certificates_signature":"eA=="}`), protocol.CodeBadRequest},
	} {
		if got := e.do("PUT", path, bad.body, ""); got.status != 400 || got.code() != bad.code {
			t.Errorf("%s: %d %s, want 400 %s: %s", name, got.status, got.code(), bad.code, got.body)
		}
	}
	// A pass does not help: the identity's signature is the authority.
	e.want(e.do("PUT", path, protocol.Revocations{Identity: r.id.Document(), RevokedCertificates: good.RevokedCertificates, RevokedCertificatesSignature: byWork}, r.pass(2)), 400, protocol.CodeBadRevocation)
	e.want(e.do("GET", path, nil, ""), 404, protocol.CodeNotRevoked)

	// The revocation, with no pass: the address goes on, and anyone is shown
	// it.
	e.want(e.do("PUT", path, good, ""), 200, "")
	stored, err := e.store.Box(ctx, r.id.Address())
	if err != nil || stored.State != Active || !bytes.Equal(stored.RevokedCerts, good.RevokedCertificates) || !bytes.Equal(stored.RevokedCertsSig, good.RevokedCertificatesSignature) {
		t.Fatalf("the record after a revocation of certificates: %+v, %v", stored, err)
	}
	shown := e.do("GET", path, nil, "")
	e.want(shown, 200, "")
	var got protocol.Revocations
	if err := json.Unmarshal(shown.body, &got); err != nil {
		t.Fatal(err)
	}
	if l, err := protocol.VerifyRevokedCertificates(r.id.Address(), got.Identity, got.RevokedCertificates, got.RevokedCertificatesSignature); err != nil || l.Through != 1 || !l.Revokes(1) || l.Revokes(2) {
		t.Fatalf("what the server shows for a box with its certificates revoked does not verify: %+v, %v", l, err)
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(shown.body, &members); err != nil || len(members) != 3 || members["revocation"] != nil {
		t.Errorf("the record served has %d members, want identity, the statement and its signature: %s", len(members), shown.body)
	}
	e.want(e.do("GET", r.path("/identity"), nil, ""), 200, "")
	e.want(e.do("GET", r.path("/messages"), nil, r.pass(2)), 200, "")
	e.want(e.sendTo(other, 1, 1, r, 2), 201, "")
	e.want(e.sendTo(r, 2, 2, other, 1), 201, "")

	// The same one again changes nothing.
	e.want(e.do("PUT", path, good, ""), 200, "")
	e.want(e.do("GET", r.path("/messages"), nil, r.pass(2)), 200, "")

	// One through the box's current certificate. No pass of the box is
	// taken, as an owner or as a sender, though the server took this very
	// pass a moment ago; nobody is sent to its prekey; and nothing under that
	// certificate is taken as a prekey, the current statement included.
	held := r.pass(2)
	e.want(e.do("GET", r.path("/messages"), nil, held), 200, "")
	e.want(e.do("PUT", path, r.certs(2), ""), 200, "")
	// The highest stands: one through a lower serial is refused, so what was
	// revoked stays revoked.
	e.want(e.do("PUT", path, good, ""), 409, protocol.CodeConflict)
	e.want(e.do("GET", r.path("/messages"), nil, held), 401, protocol.CodeCertificateRevoked)
	e.want(e.do("GET", r.path("/messages"), nil, r.pass(2)), 401, protocol.CodeCertificateRevoked)
	e.want(e.do("DELETE", r.path(""), nil, r.pass(2)), 401, protocol.CodeCertificateRevoked)
	e.want(e.sendTo(other, 1, 1, r, 2), 401, protocol.CodeCertificateRevoked)
	e.want(e.sendTo(r, 2, 2, other, 1), 409, protocol.CodePrekeyExpired)
	e.want(put(2, 2), 401, protocol.CodeCertificateRevoked)
	current := r.work[2]
	r.prekeyUnder(current, 3, now.Add(time.Hour), nil)
	e.want(put(3, 2), 401, protocol.CodeCertificateRevoked)
	if n, _, _ := e.store.Count(ctx, r.id.Address()); n != 1 {
		t.Errorf("the box holds %d messages after its certificate was revoked, want the 1 it had", n)
	}
	e.want(e.do("GET", r.path("/identity"), nil, ""), 200, "")

	// It comes back with a prekey under a new certificate, which needs no
	// pass under the old one.
	r.prekey(3, now.Add(protocol.MaxPrekeyLifetime), nil)
	e.want(put(3, 3), 200, "")
	e.want(e.do("GET", r.path("/messages"), nil, r.pass(3)), 200, "")
	e.want(e.sendTo(r, 2, 2, other, 1), 409, protocol.CodeStalePrekey)
	e.want(e.sendTo(r, 3, 3, other, 1), 201, "")
	e.want(e.sendTo(other, 1, 1, r, 3), 201, "")

	// One may run through a serial no certificate has yet: none at or below
	// it is then taken, and the next one above is.
	e.want(e.do("PUT", path, r.certs(4), ""), 200, "")
	r.prekey(4, now.Add(protocol.MaxPrekeyLifetime), nil)
	e.want(put(4, 4), 401, protocol.CodeCertificateRevoked)
	r.prekey(5, now.Add(protocol.MaxPrekeyLifetime), nil)
	e.want(put(5, 5), 200, "")

	// A revocation of the address may come with one of its certificates.
	// Everything in a body is checked before anything is changed: a good
	// revocation of certificates with what is not a revocation of the
	// address, and the other way about, each change nothing.
	both := other.certs(1)
	if both.Revocation, err = protocol.SignRevocation(other.signer, other.id.Address()); err != nil {
		t.Fatal(err)
	}
	halfList, halfRevocation := both, both
	halfList.Revocation = []byte("revoke it")
	halfRevocation.RevokedCertificatesSignature = byWork
	e.want(e.do("PUT", other.path("/revocations"), halfList, ""), 400, protocol.CodeBadRevocation)
	e.want(e.do("PUT", other.path("/revocations"), halfRevocation, ""), 400, protocol.CodeBadRevocation)
	if stored, err = e.store.Box(ctx, other.id.Address()); err != nil || stored.State != Active || len(stored.RevokedCerts) != 0 || len(stored.Revocation) != 0 {
		t.Fatalf("a body that verified in part changed the record: %+v, %v", stored, err)
	}
	e.want(e.do("GET", other.path("/revocations"), nil, ""), 404, protocol.CodeNotRevoked)
	// Whole, both are kept, and both are shown. A revoked box takes nothing
	// more: whatever is sent for it is answered from its record.
	e.want(e.do("PUT", other.path("/revocations"), both, ""), 201, "")
	shown = e.do("GET", other.path("/revocations"), nil, "")
	e.want(shown, 200, "")
	members = nil
	if err := json.Unmarshal(shown.body, &members); err != nil || len(members) != 4 {
		t.Errorf("the record served for a revoked box that had its certificates revoked has %d members, want 4: %s", len(members), shown.body)
	}
	e.want(e.do("GET", other.path("/identity"), nil, ""), 410, protocol.CodeRevoked)
	e.want(e.do("PUT", other.path("/revocations"), other.certs(2), ""), 410, protocol.CodeRevoked)
	e.want(e.do("PUT", other.path("/revocations"), both, ""), 410, protocol.CodeRevoked)
}

// A body that is not a revocation of certificates costs the server a
// signature check that nothing has paid for, as one that is not a revocation
// of the address does.
func TestJunkRevocationsOfCertificatesAreLimited(t *testing.T) {
	l := relaxed()
	l.MissesPerMinute = 2
	e := newEnv(t, l)
	r := e.raw().register(protocol.MaxPrekeyLifetime)
	junk := protocol.Revocations{Identity: r.id.Document(), RevokedCertificates: []byte("every certificate\n"), RevokedCertificatesSignature: []byte("revoke them")}
	path := r.path("/revocations")
	e.want(e.do("PUT", path, junk, ""), 400, protocol.CodeBadRevocation)
	e.want(e.do("PUT", path, junk, ""), 400, protocol.CodeBadRevocation)
	e.want(e.do("PUT", path, junk, ""), 429, protocol.CodeRateLimited)
	e.clock.Add(protocol.MaxSkew) // long past the limit's minute
	e.want(e.do("PUT", path, r.certs(1), ""), 200, "")
}

// The Go client against this server: a box renews and revokes every
// certificate before its new one. Mail it sent under the old one is refused
// by its reader, who is shown the revocation and checks it; mail under the new one
// is delivered; and the box, whose working key before the renewal is now
// worth nothing here, goes on at its address.
func TestTheClientRevokesItsEarlierCertificates(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t, relaxed())
	a, b := e.box(protocol.Classic), e.box(protocol.Classic)
	send(t, a, b, "under A's first certificate")
	taken, old := worker(t, a), e.pass(a)
	_, first := e.numbers(a.Address())
	if _, err := a.Rekey(ctx, protocol.Classic); err != nil {
		t.Fatal(err)
	}
	_, second := e.numbers(a.Address())
	certs, err := a.RevokeEarlier(ctx)
	if err != nil || certs == nil || second <= first || !certs.Revokes(first) || certs.Revokes(second) {
		t.Fatalf("RevokeEarlier: %+v, %v", certs, err)
	}
	// The working key from before: its pass is refused, and a prekey it
	// signs at the highest serial there is, is refused too.
	e.want(e.do("GET", "/v1/"+a.Address().String()+"/messages", nil, old), 401, protocol.CodeCertificateNotCurrent)
	key, _ := age.GenerateX25519Identity()
	top := &protocol.Prekey{Address: a.Address(), Serial: protocol.MaxSerial, Key: key.Recipient().String(), NotAfter: e.clock.Now().Add(time.Hour)}
	sig, err := protocol.Sign(taken, top.Statement(), protocol.PrekeyNamespace(a.Address()))
	if err != nil {
		t.Fatal(err)
	}
	e.want(e.do("PUT", "/v1/"+a.Address().String()+"/prekey", protocol.PrekeyRequest{Prekey: top.Statement(), PrekeySignature: sig}, e.passFor(taken, a.Address(), e.name())), 401, protocol.CodeCertificateRevoked)

	send(t, a, b, "under A's second certificate")
	res := receive(t, b)
	if len(res.Delivered) != 1 || len(res.Refused) != 1 || res.Refused[0].Code != client.RefusedCertificate || string(res.Delivered[0].Envelope.Body) != `"under A's second certificate"` {
		t.Fatalf("B's drain of mail from a box that revoked its first certificate: %+v", res)
	}
	send(t, b, a, "to A at its second certificate")
	if res := receive(t, a); len(res.Delivered) != 1 {
		t.Fatalf("A's drain after its renewal: %+v", res)
	}
}

// A box's statements are ordered by certificate first, so a prekey published
// at the highest serial there is, with a working key someone took, does not
// end the address: the box's next renewal passes it, and its senders follow.
func TestAPrekeyAtTheHighestSerialDoesNotEndTheAddress(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t, relaxed())
	a, b := e.box(protocol.Classic), e.box(protocol.Classic)
	taken := worker(t, a)
	_, first := e.numbers(a.Address())
	key, _ := age.GenerateX25519Identity()
	top := &protocol.Prekey{Address: a.Address(), Serial: protocol.MaxSerial, Key: key.Recipient().String(), NotAfter: e.clock.Now().Add(time.Hour)}
	sig, err := protocol.Sign(taken, top.Statement(), protocol.PrekeyNamespace(a.Address()))
	if err != nil {
		t.Fatal(err)
	}
	e.want(e.do("PUT", "/v1/"+a.Address().String()+"/prekey", protocol.PrekeyRequest{Prekey: top.Statement(), PrekeySignature: sig}, e.passFor(taken, a.Address(), e.name())), 200, "")
	send(t, b, a, "encrypted to the prekey the thief published")
	if _, err := a.Rekey(ctx, protocol.Classic); err != nil {
		t.Fatalf("a renewal after a prekey at the highest serial: %v", err)
	}
	stored, err := e.store.Box(ctx, a.Address())
	if err != nil || stored.CertSerial <= first || stored.Prekey.Serial != stored.CertSerial || stored.Prekey.Serial >= protocol.MaxSerial {
		t.Fatalf("the record after the renewal: certificate %d, prekey %d, %v", stored.CertSerial, stored.Prekey.Serial, err)
	}
	send(t, b, a, "to the box's own prekey again")
	res := receive(t, a)
	if len(res.Delivered) != 1 || string(res.Delivered[0].Envelope.Body) != `"to the box's own prekey again"` {
		t.Fatalf("A's drain after the renewal: %+v", res)
	}
}

// The revocation of certificates is in the box's record, so a process that
// starts later serves the same one and refuses the same pass: nothing about a
// revoked certificate lives only in the memory of the process that took the
// revocation. AWS only: the in-memory store has one process.
func TestARevocationOfCertificatesOutlivesTheProcess(t *testing.T) {
	e, _ := dynamoEnv(t)
	r := e.raw().register(protocol.MaxPrekeyLifetime)
	rec := r.certs(1)
	e.want(e.do("PUT", r.path("/revocations"), rec, ""), 200, "")

	later := startDynamo(t, e.clock.Now) // its memory holds nothing of the box
	srv := httptest.NewServer(New(Config{Store: later, Keys: e.keys, Limits: relaxed(), Now: e.clock.Now, Ready: later.Ready}).Handler())
	defer srv.Close()
	e2 := &env{t: t, clock: e.clock, srv: srv}
	r2 := *r
	r2.e = e2
	e2.want(e2.do("GET", r.path("/messages"), nil, r2.pass(1)), 401, protocol.CodeCertificateRevoked)
	shown := e2.do("GET", r.path("/revocations"), nil, "")
	e2.want(shown, 200, "")
	var got protocol.Revocations
	if err := json.Unmarshal(shown.body, &got); err != nil {
		t.Fatal(err)
	}
	if _, err := protocol.VerifyRevokedCertificates(r.id.Address(), got.Identity, got.RevokedCertificates, got.RevokedCertificatesSignature); err != nil || !bytes.Equal(got.RevokedCertificates, rec.RevokedCertificates) {
		t.Fatalf("what a later process shows for a box with its certificates revoked: %v", err)
	}
	e2.want(e2.do("PUT", r.path("/revocations"), rec, ""), 200, "")
	r2.prekey(2, e.clock.Now().Add(time.Hour), nil)
	e2.want(e2.do("PUT", r.path("/prekey"), r2.upload(2), r2.pass(2)), 200, "")
	e2.want(e2.do("GET", r.path("/messages"), nil, r2.pass(2)), 200, "")
}

// What memory holds of a box comes from its record two ways: from the record
// decoded whole, when a process loads the box, and from the standing read off
// a stream record, when another process wrote it. Both say the same of a
// revocation of certificates: whether it covers the box's current one.
func TestARecordsStandingKnowsItsRevokedCertificates(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t, relaxed())
	r := e.raw().register(protocol.MaxPrekeyLifetime)
	r.prekey(3, e.clock.Now().Add(protocol.MaxPrekeyLifetime), nil)
	e.want(e.do("PUT", r.path("/prekey"), r.upload(3), r.pass(3)), 200, "") // the box stands at certificate 3
	for i, c := range []struct {
		through uint64
		listed  bool
	}{
		{0, false},
		{2, false},
		{3, true},
	} {
		if c.through != 0 {
			e.want(e.do("PUT", r.path("/revocations"), r.certs(c.through), ""), 200, "")
		}
		b, err := e.store.Box(ctx, r.id.Address())
		if err != nil {
			t.Fatal(err)
		}
		it := item(boxItem(b))
		st, rev, err := decodeStanding(it)
		want, werr := b.standing()
		if err != nil || werr != nil || st != want || st.Listed != c.listed || rev != b.Rev {
			t.Errorf("case %d: the standing read off the record says listed %v at rev %d (%v), the box's own says %v at rev %d (%v), want %v, and the two the same throughout", i, st.Listed, rev, err, want.Listed, b.Rev, werr, c.listed)
		}
		back, err := decodeBox(it)
		if err != nil || !bytes.Equal(back.RevokedCerts, b.RevokedCerts) || !bytes.Equal(back.RevokedCertsSig, b.RevokedCertsSig) || (c.through != 0) != (len(back.RevokedCerts) > 0) {
			t.Errorf("case %d: the revocation of certificates does not come back from the record as it went in: %v", i, err)
		}
	}
}

// A holder of a box's working key spends the box's renewals for the day, and
// holds nothing by it: a renewal under a later certificate is the identity's
// act, counted apart (Limits.IdentityActsPerDay), so the owner's remedy renews
// and revokes the taken certificate the same day. From then on this server
// takes nothing more under that certificate.
func TestTheRemedyRenewsWhenATakerSpentTheDaysRenewals(t *testing.T) {
	ctx := context.Background()
	l := relaxed()
	l.RenewalsPerDay = DefaultLimits().RenewalsPerDay
	l.IdentityActsPerDay = DefaultLimits().IdentityActsPerDay
	e := newEnv(t, l)
	now := e.clock.Now()
	e.clock.Add(now.Truncate(24 * time.Hour).Add(25 * time.Hour).Sub(now)) // 01:00 UTC, far from a day's end
	a := e.box(protocol.Classic)
	taken := worker(t, a)
	_, inUse := e.numbers(a.Address())
	thief := func(serial uint64) reply {
		key, err := age.GenerateX25519Identity()
		if err != nil {
			t.Fatal(err)
		}
		p := &protocol.Prekey{Address: a.Address(), Serial: serial, Key: key.Recipient().String(), NotAfter: e.clock.Now().Add(time.Hour)}
		sig, err := protocol.Sign(taken, p.Statement(), protocol.PrekeyNamespace(a.Address()))
		if err != nil {
			t.Fatal(err)
		}
		return e.do("PUT", "/v1/"+a.Address().String()+"/prekey", protocol.PrekeyRequest{Prekey: p.Statement(), PrekeySignature: sig}, e.passFor(taken, a.Address(), e.name()))
	}
	for i := range l.RenewalsPerDay {
		e.want(thief(inUse+uint64(i)+1), 200, "")
	}
	e.want(thief(inUse+uint64(l.RenewalsPerDay)+1), 429, protocol.CodeRenewalsSpent) // the taker is out of renewals
	r, err := a.RenewAndRevoke(ctx, protocol.Classic)
	if err != nil || r == nil || r.NotRenewed != nil || r.Prekey == nil || r.Revoked == nil || !r.Revoked.Revokes(inUse) || r.Revoked.Revokes(r.Below) {
		t.Fatalf("the owner's remedy after the taker's renewals: %+v, %v", r, err)
	}
	e.want(thief(inUse+100), 401, protocol.CodeCertificateRevoked)
	if _, cert := e.numbers(a.Address()); cert != r.Below {
		t.Fatalf("the box stands at certificate %d, not the one the remedy made, %d", cert, r.Below)
	}
}

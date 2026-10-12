package server

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/IronGall-dev/irongall-client/client"
	"github.com/IronGall-dev/irongall-client/protocol"
	"golang.org/x/crypto/ssh"
)

// The server's answers, checked over raw HTTP, against the status map
// (PROTOCOL.md §13) and the box states (§3a).

type reply struct {
	status int
	header http.Header
	body   []byte
}

func (r reply) code() protocol.Code {
	var p protocol.Problem
	_ = json.Unmarshal(r.body, &p)
	return p.Code
}

func (e *env) do(method, path string, body any, token string) reply {
	e.t.Helper()
	var rd io.Reader
	if body != nil {
		if raw, ok := body.([]byte); ok {
			rd = bytes.NewReader(raw)
		} else {
			j, _ := json.Marshal(body)
			rd = bytes.NewReader(j)
		}
	}
	req, _ := http.NewRequest(method, e.srv.URL+path, rd)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	r := reply{status: resp.StatusCode, header: resp.Header, body: b}
	if resp.StatusCode >= 400 {
		var p protocol.Problem
		if err := json.Unmarshal(b, &p); err != nil || resp.Header.Get("Content-Type") != protocol.ProblemContentType ||
			p.Status != resp.StatusCode || p.Type != p.Code.TypeURI() || p.Code.Status() != resp.StatusCode {
			e.t.Fatalf("%s %s: %d is not a problem+json body matching the status map: %s", method, path, resp.StatusCode, b)
		}
	}
	return r
}

func (e *env) want(r reply, status int, code protocol.Code) {
	e.t.Helper()
	if r.status != status || (code != "" && r.code() != code) {
		e.t.Fatalf("got %d %s, want %d %s: %s", r.status, r.code(), status, code, r.body)
	}
}

// raw is a box built by hand, for requests the client would never make.
type raw struct {
	signer ssh.Signer
	id     *protocol.Identity
	keys   map[uint64]*age.X25519Identity
	stmt   map[uint64][]byte
	sig    map[uint64][]byte
}

func newRaw(t *testing.T) *raw {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	s, _ := ssh.NewSignerFromKey(priv)
	id, err := protocol.NewIdentity(pub)
	if err != nil {
		t.Fatal(err)
	}
	return &raw{signer: s, id: id, keys: map[uint64]*age.X25519Identity{}, stmt: map[uint64][]byte{}, sig: map[uint64][]byte{}}
}

func (r *raw) path(rest string) string { return "/v1/" + r.id.Address().String() + rest }

// prekey makes statement serial, with a new key unless key is given.
func (r *raw) prekey(t *testing.T, serial uint64, notAfter time.Time, key *age.X25519Identity) {
	t.Helper()
	if key == nil {
		key, _ = age.GenerateX25519Identity()
	}
	r.keys[serial] = key
	p := &protocol.Prekey{Address: r.id.Address(), Serial: serial, Key: key.Recipient().String(), NotAfter: notAfter}
	r.stmt[serial] = p.Statement()
	r.sig[serial], _ = protocol.Sign(r.signer, p.Statement(), protocol.PrekeyNamespace(r.id.Address()))
}

func (r *raw) registration(serial uint64) protocol.RegisterRequest {
	return protocol.RegisterRequest{Identity: r.id.Document(), Prekey: r.stmt[serial], PrekeySignature: r.sig[serial]}
}

// token decrypts a token response with every key the box holds.
func (r *raw) token(t *testing.T, rep reply) string {
	t.Helper()
	var tr protocol.TokenResponse
	if err := json.Unmarshal(rep.body, &tr); err != nil {
		t.Fatal(err)
	}
	var ids []age.Identity
	for _, k := range r.keys {
		ids = append(ids, k)
	}
	d, err := age.Decrypt(bytes.NewReader(tr.Token), ids...)
	if err != nil {
		t.Fatal(err)
	}
	tok, _ := io.ReadAll(d)
	return string(tok)
}

func TestRegistration(t *testing.T) {
	e := newEnv(t, relaxed())
	now := e.clock.Now()
	r := newRaw(t)
	r.prekey(t, 1, now.Add(protocol.MaxPrekeyLifetime), nil)
	reg := r.registration(1)

	e.want(e.do("PUT", "/v1/nope", reg, ""), 400, protocol.CodeBadAddress)
	e.want(e.do("PUT", r.path(""), []byte(`{"identity":"","prekey":"","prekey_signature":"","extra":1}`), ""), 400, protocol.CodeBadRequest)
	e.want(e.do("PUT", r.path(""), []byte(`{"identity":"","prekey":""}`), ""), 400, protocol.CodeBadRequest)
	e.want(e.do("PUT", r.path(""), []byte(`{"identity":"","prekey":"","prekey_signature":null}`), ""), 400, protocol.CodeBadRequest)
	e.want(e.do("PUT", r.path(""), []byte(`{"identity":"not base64!","prekey":"","prekey_signature":""}`), ""), 400, protocol.CodeBadEncoding)
	e.want(e.do("PUT", r.path(""), []byte(`not json`), ""), 400, protocol.CodeBadRequest)

	other := newRaw(t)
	e.want(e.do("PUT", other.path(""), reg, ""), 400, protocol.CodeIdentityMismatch)

	// A document that hashes to its address but breaks the grammar.
	commented := append(bytes.TrimSuffix(r.id.Document(), []byte("\n")), []byte(" comment\n")...)
	h := sha256.Sum256(commented)
	e.want(e.do("PUT", "/v1/"+hex.EncodeToString(h[:]), protocol.RegisterRequest{Identity: commented, Prekey: reg.Prekey, PrekeySignature: reg.PrekeySignature}, ""), 400, protocol.CodeIdentityMismatch)

	// A small-order key: the grammar holds, the key check fails.
	small, err := os.ReadFile("../../../irongall-client/testdata/vectors/identity/small-order-1.doc")
	if err != nil {
		t.Fatal(err)
	}
	h = sha256.Sum256(small)
	e.want(e.do("PUT", "/v1/"+hex.EncodeToString(h[:]), protocol.RegisterRequest{Identity: small, Prekey: reg.Prekey, PrekeySignature: reg.PrekeySignature}, ""), 400, protocol.CodeBadKey)

	// A prekey signed by another identity; one valid for too long; one expired.
	other.prekey(t, 1, now.Add(protocol.MaxPrekeyLifetime), nil)
	e.want(e.do("PUT", r.path(""), protocol.RegisterRequest{Identity: reg.Identity, Prekey: reg.Prekey, PrekeySignature: other.sig[1]}, ""), 400, protocol.CodeBadKey)
	long := newRaw(t)
	long.prekey(t, 1, now.Add(protocol.MaxPrekeyLifetime+time.Second), nil)
	e.want(e.do("PUT", long.path(""), long.registration(1), ""), 400, protocol.CodeBadKey)
	expired := newRaw(t)
	expired.prekey(t, 1, now, nil)
	e.want(e.do("PUT", expired.path(""), expired.registration(1), ""), 400, protocol.CodeBadKey)

	// Registered: 201, then an identical retry is 200 with the same token,
	// and anything else is a conflict.
	first := e.do("PUT", r.path(""), reg, "")
	e.want(first, 201, "")
	tok := r.token(t, first)
	if !strings.HasPrefix(tok, "igt1_") || len(tok) != 55 {
		t.Fatalf("token %q", tok)
	}
	again := e.do("PUT", r.path(""), reg, "")
	e.want(again, 200, "")
	if r.token(t, again) != tok {
		t.Fatal("an identical retry returned another token")
	}
	r2 := *r
	r2.keys = map[uint64]*age.X25519Identity{}
	r2.stmt, r2.sig = map[uint64][]byte{}, map[uint64][]byte{}
	r2.prekey(t, 1, now.Add(protocol.MaxPrekeyLifetime), nil)
	e.want(e.do("PUT", r.path(""), r2.registration(1), ""), 409, protocol.CodeConflict)

	// Pending until its first owner call.
	a := e.box(protocol.Classic)
	_, err = a.Send(context.Background(), r.id.Address(), "too early")
	if client.Code(err) != protocol.CodeNoSuchMailbox || !strings.Contains(err.Error(), "not activated") {
		t.Fatalf("send to a pending box: %v", err)
	}
	e.want(e.do("GET", r.path("/messages"), nil, tok), 200, "")
	if _, err := a.Send(context.Background(), r.id.Address(), "now"); err != nil {
		t.Fatalf("send to the activated box: %v", err)
	}

	// The registration limit, per IP.
	l := relaxed()
	l.RegistrationsPerHour = 1
	e2 := newEnv(t, l)
	x, y := newRaw(t), newRaw(t)
	x.prekey(t, 1, now.Add(time.Hour), nil)
	y.prekey(t, 1, now.Add(time.Hour), nil)
	e2.want(e2.do("PUT", x.path(""), x.registration(1), ""), 201, "")
	rl := e2.do("PUT", y.path(""), y.registration(1), "")
	e2.want(rl, 429, protocol.CodeRateLimited)
	if rl.header.Get("Retry-After") == "" {
		t.Fatal("429 without Retry-After")
	}
}

func TestOwnerCalls(t *testing.T) {
	e := newEnv(t, relaxed())
	now := e.clock.Now()
	r := newRaw(t)
	r.prekey(t, 1, now.Add(protocol.MaxPrekeyLifetime), nil)
	tok := r.token(t, e.do("PUT", r.path(""), r.registration(1), ""))

	noTok := e.do("GET", r.path("/messages"), nil, "")
	e.want(noTok, 401, protocol.CodeUnauthorized)
	if noTok.header.Get("WWW-Authenticate") != "Bearer" {
		t.Fatalf("WWW-Authenticate %q", noTok.header.Get("WWW-Authenticate"))
	}
	// One MAC character changed (the last base64 character holds only two
	// bits, so it is not the one to change).
	flip := map[byte]string{'A': "B"}[tok[20]]
	if flip == "" {
		flip = "A"
	}
	bad := e.do("GET", r.path("/messages"), nil, tok[:20]+flip+tok[21:])
	e.want(bad, 401, protocol.CodeUnauthorized)
	if bad.header.Get("WWW-Authenticate") != `Bearer error="invalid_token"` {
		t.Fatalf("WWW-Authenticate %q", bad.header.Get("WWW-Authenticate"))
	}
	// Another box's token is not this box's.
	o := newRaw(t)
	o.prekey(t, 1, now.Add(time.Hour), nil)
	otok := o.token(t, e.do("PUT", o.path(""), o.registration(1), ""))
	e.want(e.do("GET", r.path("/messages"), nil, otok), 401, protocol.CodeUnauthorized)

	empty := e.do("GET", r.path("/messages"), nil, tok)
	e.want(empty, 200, "")
	if string(bytes.TrimSpace(empty.body)) != `{"count":0,"messages":[],"next_cursor":null,"poll_after":60}` {
		t.Fatalf("empty list %s", empty.body)
	}
	e.want(e.do("GET", r.path("/messages?cursor=zzz"), nil, tok), 400, protocol.CodeBadRequest)
	e.want(e.do("GET", r.path("/messages?limit=5"), nil, tok), 400, protocol.CodeBadRequest)
	e.want(e.do("GET", r.path("/messages/"+strings.Repeat("a", 64)), nil, tok), 404, protocol.CodeNoSuchMessage)
	e.want(e.do("DELETE", r.path("/messages/"+strings.Repeat("a", 64)), nil, tok), 404, protocol.CodeNoSuchMessage)
	e.want(e.do("POST", r.path("/token"), nil, ""), 200, "")

	// Close: mail deleted, owner calls and /token 404, /identity still
	// answers so the owner can read its serial; a new prekey reopens it.
	a := e.box(protocol.Classic)
	if _, err := a.Send(context.Background(), r.id.Address(), "deleted by close"); err != nil {
		t.Fatal(err)
	}
	e.want(e.do("DELETE", r.path(""), nil, tok), 204, "")
	e.want(e.do("GET", r.path("/messages"), nil, tok), 404, protocol.CodeNoSuchMailbox)
	e.want(e.do("POST", r.path("/token"), nil, ""), 404, protocol.CodeNoSuchMailbox)
	e.want(e.do("GET", r.path("/identity"), nil, ""), 200, "")
	e.want(e.do("PUT", r.path(""), r.registration(1), ""), 409, protocol.CodeConflict)
	if _, err := a.Send(context.Background(), r.id.Address(), "to a closed box"); client.Code(err) != protocol.CodeNoSuchMailbox {
		t.Fatalf("send to a closed box: %v", err)
	}
	r.prekey(t, 2, now.Add(protocol.MaxPrekeyLifetime), nil)
	reopened := e.do("PUT", r.path("/prekey"), protocol.PrekeyRequest{Prekey: r.stmt[2], PrekeySignature: r.sig[2]}, "")
	e.want(reopened, 200, "")
	tok2 := r.token(t, reopened)
	if _, err := a.Send(context.Background(), r.id.Address(), "to a reopened box"); client.Code(err) != protocol.CodeNoSuchMailbox || !strings.Contains(err.Error(), "not activated") {
		t.Fatalf("send to a reopened box before its owner polls: %v", err)
	}
	e.want(e.do("GET", r.path("/messages"), nil, tok), 401, protocol.CodeTokenStale)
	list := e.do("GET", r.path("/messages"), nil, tok2)
	e.want(list, 200, "")
	if !bytes.Contains(list.body, []byte(`"count":0`)) {
		t.Fatalf("close did not delete the mail: %s", list.body)
	}
}

func TestPrekeyRenewal(t *testing.T) {
	e := newEnv(t, relaxed())
	now := e.clock.Now()
	r := newRaw(t)
	r.prekey(t, 1, now.Add(protocol.MaxPrekeyLifetime), nil)
	e.want(e.do("PUT", r.path(""), r.registration(1), ""), 201, "")
	put := func(serial uint64) reply {
		return e.do("PUT", r.path("/prekey"), protocol.PrekeyRequest{Prekey: r.stmt[serial], PrekeySignature: r.sig[serial]}, "")
	}

	unknown := newRaw(t)
	unknown.prekey(t, 2, now.Add(time.Hour), nil)
	e.want(e.do("PUT", unknown.path("/prekey"), protocol.PrekeyRequest{Prekey: unknown.stmt[2], PrekeySignature: unknown.sig[2]}, ""), 404, protocol.CodeNoSuchMailbox)

	e.want(put(1), 200, "") // an identical retry of the current statement
	r.prekey(t, 2, now.Add(time.Hour), r.keys[1])
	e.want(put(2), 400, protocol.CodeBadKey) // the same key again
	r.prekey(t, 2, now.Add(time.Hour), nil)
	e.want(put(2), 200, "")
	r.prekey(t, 3, now.Add(time.Hour), r.keys[1])
	e.want(put(3), 400, protocol.CodeBadKey) // a live retired key
	r.prekey(t, 2, now.Add(2*time.Hour), nil)
	e.want(put(2), 409, protocol.CodeConflict) // not above the current serial
	r.prekey(t, 1, now.Add(2*time.Hour), nil)
	e.want(put(1), 409, protocol.CodeConflict)
}

func TestSendPipeline(t *testing.T) {
	e := newEnv(t, relaxed())
	ctx := context.Background()
	a, b := e.box(protocol.Classic), e.box(protocol.PostQuantum)
	bBox, _ := e.store.Box(ctx, b.Address())
	pqRecipient, _ := bBox.Prekey.Recipient()
	as := signer(t, a)

	// seal encrypts to the given recipients and signs for b.
	seal := func(rs ...age.Recipient) protocol.SendRequest {
		var ct bytes.Buffer
		w, err := age.Encrypt(&ct, rs...)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.WriteString(w, `{"v":1}`)
		_ = w.Close()
		sig, _ := protocol.Sign(as, ct.Bytes(), protocol.MessageNamespace(b.Address()))
		one := uint64(1)
		return protocol.SendRequest{From: a.Address().String(), PrekeySerial: &one, Ciphertext: ct.Bytes(), Signature: sig}
	}
	to := "/v1/" + b.Address().String()
	ok := seal(pqRecipient)
	classic, _ := age.GenerateX25519Identity()

	upper := ok
	upper.From = strings.ToUpper(upper.From)
	e.want(e.do("POST", to, upper, ""), 400, protocol.CodeBadAddress)
	zero := ok
	var z uint64
	zero.PrekeySerial = &z
	e.want(e.do("POST", to, zero, ""), 400, protocol.CodeBadRequest)
	noSerial := ok
	noSerial.PrekeySerial = nil
	e.want(e.do("POST", to, noSerial, ""), 400, protocol.CodeBadRequest)
	notAge := ok
	notAge.Ciphertext = []byte("not an age file")
	e.want(e.do("POST", to, notAge, ""), 400, protocol.CodeNotAge)
	e.want(e.do("POST", to, seal(classic.Recipient()), ""), 400, protocol.CodeWrongRecipientType)
	two, _ := age.GenerateHybridIdentity()
	e.want(e.do("POST", to, seal(pqRecipient, two.Recipient()), ""), 400, protocol.CodeWrongRecipientType)
	wrongNS := ok
	wrongNS.Signature, _ = protocol.Sign(as, ok.Ciphertext, protocol.MessageNamespace(a.Address()))
	e.want(e.do("POST", to, wrongNS, ""), 403, protocol.CodeBadSignature)
	stale := ok
	s9 := uint64(9)
	stale.PrekeySerial = &s9
	e.want(e.do("POST", to, stale, ""), 409, protocol.CodeStalePrekey)

	big := relaxed()
	big.MaxSize = 100
	small := newEnv(t, big)
	sa, sb := small.box(protocol.Classic), small.box(protocol.Classic)
	if _, err := sa.Send(ctx, sb.Address(), strings.Repeat("x", 200)); client.Code(err) != protocol.CodeTooLarge {
		t.Fatalf("send over the cap: %v", err)
	}

	unregistered := newRaw(t)
	fromNobody := ok
	fromNobody.From = unregistered.id.Address().String()
	e.want(e.do("POST", to, fromNobody, ""), 403, protocol.CodeUnknownSender)
	e.want(e.do("POST", "/v1/"+unregistered.id.Address().String(), ok, ""), 404, protocol.CodeNoSuchMailbox)

	// A registered sender that is not active: pending, then closed.
	p := newRaw(t)
	p.prekey(t, 1, e.clock.Now().Add(time.Hour), nil)
	ptok := p.token(t, e.do("PUT", p.path(""), p.registration(1), ""))
	fromPending := ok
	fromPending.From = p.id.Address().String()
	fromPending.Signature, _ = protocol.Sign(p.signer, ok.Ciphertext, protocol.MessageNamespace(b.Address()))
	e.want(e.do("POST", to, fromPending, ""), 403, protocol.CodeUnknownSender)
	e.want(e.do("DELETE", p.path(""), nil, ptok), 204, "")
	e.want(e.do("POST", to, fromPending, ""), 403, protocol.CodeUnknownSender)

	e.want(e.do("POST", to, ok, ""), 201, "")
	e.want(e.do("POST", to, ok, ""), 200, "")
	// The same ciphertext from another box: a conflict, never a receipt.
	c := e.box(protocol.Classic)
	fromC := ok
	fromC.From = c.Address().String()
	fromC.Signature, _ = protocol.Sign(signer(t, c), ok.Ciphertext, protocol.MessageNamespace(b.Address()))
	e.want(e.do("POST", to, fromC, ""), 409, protocol.CodeConflict)

	// Revoked boxes, set by hand: revocation's endpoint is not built yet.
	for _, box := range []protocol.Address{a.Address(), b.Address()} {
		rec, _ := e.store.Box(ctx, box)
		rec.State = Revoked
		_ = e.store.UpdateBox(ctx, rec)
	}
	e.want(e.do("POST", to, seal(pqRecipient), ""), 410, protocol.CodeRevoked)
	rec, _ := e.store.Box(ctx, b.Address())
	rec.State = Active
	_ = e.store.UpdateBox(ctx, rec)
	e.want(e.do("POST", to, seal(pqRecipient), ""), 403, protocol.CodeSenderRevoked)
	e.want(e.do("GET", "/v1/"+a.Address().String()+"/identity", nil, ""), 410, protocol.CodeRevoked)

	// An expired recipient prekey.
	e.clock.Add(protocol.MaxPrekeyLifetime)
	rec, _ = e.store.Box(ctx, a.Address())
	rec.State = Active
	_ = e.store.UpdateBox(ctx, rec)
	e.want(e.do("POST", to, seal(pqRecipient), ""), 409, protocol.CodePrekeyExpired)
}

// greaseRecipient adds a grease stanza, as rage and pyrage do.
type greaseRecipient struct{}

func (greaseRecipient) Wrap([]byte) ([]*age.Stanza, error) {
	return []*age.Stanza{{Type: "x-grease", Args: []string{"a", "b"}, Body: []byte("junk")}}, nil
}

func TestGreaseIsIgnored(t *testing.T) {
	e := newEnv(t, relaxed())
	ctx := context.Background()
	a, b := e.box(protocol.Classic), e.box(protocol.Classic)
	bBox, _ := e.store.Box(ctx, b.Address())
	rcpt, _ := bBox.Prekey.Recipient()
	var ct bytes.Buffer
	w, err := age.Encrypt(&ct, rcpt, greaseRecipient{})
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.WriteString(w, "x")
	_ = w.Close()
	sig, _ := protocol.Sign(signer(t, a), ct.Bytes(), protocol.MessageNamespace(b.Address()))
	one := uint64(1)
	req := protocol.SendRequest{From: a.Address().String(), PrekeySerial: &one, Ciphertext: ct.Bytes(), Signature: sig}
	e.want(e.do("POST", "/v1/"+b.Address().String(), req, ""), 201, "")
}

func TestPerIPLimits(t *testing.T) {
	l := relaxed()
	l.TokensPerMinute, l.SendsPerMinutePerIP = 1, 1
	e := newEnv(t, l)
	ctx := context.Background()
	a, b := e.box(protocol.Classic), e.box(protocol.Classic)
	e.want(e.do("POST", "/v1/"+b.Address().String()+"/token", nil, ""), 200, "")
	r := e.do("POST", "/v1/"+b.Address().String()+"/token", nil, "")
	e.want(r, 429, protocol.CodeRateLimited)
	var p protocol.Problem
	_ = json.Unmarshal(r.body, &p)
	if !strings.Contains(p.Detail, "; retry in "+r.header.Get("Retry-After")+"s") {
		t.Fatalf("the detail does not say the wait Retry-After gives (%s): %q", r.header.Get("Retry-After"), p.Detail)
	}
	send(t, a, b, "1")
	if _, err := a.Send(ctx, b.Address(), "2"); client.Code(err) != protocol.CodeRateLimited {
		t.Fatalf("second send in a minute from one IP: %v", err)
	}
}

// Behind a proxy every request comes from the proxy's address: per-IP limits
// key on CF-Connecting-IP from a trusted proxy, and on the peer otherwise, so
// no one outside can pick their own bucket.
func TestClientIPFromTrustedProxy(t *testing.T) {
	l := relaxed()
	l.TokensPerMinute = 1
	keys, _ := NewDevKeys()
	clk := time.Now()
	store := NewMemStore(func() time.Time { return clk })
	b := &Box{Addr: protocol.Address{1}, State: Active}
	for _, c := range []struct {
		name    string
		trusted []netip.Prefix
		second  int // the status of a second call from another CF-Connecting-IP
	}{
		{"trusted peer: one bucket per client", []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}, http.StatusNotFound},
		{"untrusted peer: the header is ignored", nil, http.StatusTooManyRequests},
	} {
		t.Run(c.name, func(t *testing.T) {
			srv := httptest.NewServer(New(Config{Store: store, Keys: keys, Limits: l, TrustedProxies: c.trusted}).Handler())
			defer srv.Close()
			call := func(ip string) int {
				req, _ := http.NewRequest(http.MethodPost, srv.URL+"/v1/"+b.Addr.String()+"/token", nil)
				req.Header.Set("CF-Connecting-IP", ip)
				resp, err := http.DefaultClient.Do(req)
				if err != nil {
					t.Fatal(err)
				}
				_ = resp.Body.Close()
				return resp.StatusCode
			}
			if got := call("192.0.2.1"); got != http.StatusNotFound {
				t.Fatalf("first call: %d", got)
			}
			if got := call("192.0.2.2"); got != c.second {
				t.Fatalf("second call, another client: %d, want %d", got, c.second)
			}
			if c.trusted != nil {
				if got := call("192.0.2.1"); got != http.StatusTooManyRequests {
					t.Fatalf("the same client again: %d, want 429", got)
				}
			}
		})
	}
}

// A send must name the box's current prekey serial, so after a renewal
// (here one that switches type) no mail reaches the retired key: a send
// naming its serial is stale, and one naming the current serial but sealed
// to the retired key's type is refused. The box may then delete the key.
func TestSendNamesTheCurrentPrekey(t *testing.T) {
	e := newEnv(t, relaxed())
	ctx := context.Background()
	a, b := e.box(protocol.Classic), e.box(protocol.Classic)
	old, _ := e.store.Box(ctx, b.Address())
	oldRecipient, _ := old.Prekey.Recipient()
	e.clock.Add(20 * 24 * time.Hour) // a renewal well before not_after
	if p, err := b.Rekey(ctx, protocol.PostQuantum); err != nil || p.Type() != protocol.PostQuantum {
		t.Fatalf("rekey to post-quantum: %v", err)
	}
	// sealOld seals a new envelope to the retired classic key, signed by A,
	// naming serial.
	sealOld := func(body string, serial uint64) protocol.SendRequest {
		env, _ := protocol.NewEnvelope(a.Address(), b.Address(), body, e.clock.Now())
		p, _ := env.Marshal()
		var ct bytes.Buffer
		w, _ := age.Encrypt(&ct, oldRecipient)
		_, _ = w.Write(p)
		_ = w.Close()
		sig, _ := protocol.Sign(signer(t, a), ct.Bytes(), protocol.MessageNamespace(b.Address()))
		return protocol.SendRequest{From: a.Address().String(), PrekeySerial: &serial, Ciphertext: ct.Bytes(), Signature: sig}
	}
	to := "/v1/" + b.Address().String()
	e.want(e.do("POST", to, sealOld("named the retired serial", 1), ""), 409, protocol.CodeStalePrekey)
	e.want(e.do("POST", to, sealOld("sealed to the retired key", 2), ""), 400, protocol.CodeWrongRecipientType)
	send(t, a, b, "after the switch") // to the post-quantum key
	if res := receive(t, b); len(res.Delivered) != 1 {
		t.Fatalf("delivered %d, want 1", len(res.Delivered))
	}
}

// A box renews its prekey at most RenewalsPerDay times a UTC day, then is
// told to wait for the next one; an identical retry of the current statement
// is not a renewal. Its record keeps only the RetiredKept newest retired
// prekeys, so a box that renews often cannot grow it.
func TestRenewalLimits(t *testing.T) {
	l := relaxed()
	l.RenewalsPerDay, l.RetiredKept = 3, 2
	e := newEnv(t, l)
	ctx := context.Background()
	now := e.clock.Now()
	e.clock.Add(now.Truncate(24 * time.Hour).Add(25 * time.Hour).Sub(now)) // 01:00 UTC, far from a day's end
	b := e.box(protocol.Classic)
	for i := range 3 {
		if _, err := b.Rekey(ctx, ""); err != nil {
			t.Fatalf("renewal %d: %v", i+1, err)
		}
	}
	_, err := b.Rekey(ctx, "")
	var ae *client.APIError
	if !errors.As(err, &ae) || ae.Problem.Code != protocol.CodeRateLimited || ae.RetryAfter != 23*time.Hour {
		t.Fatalf("a fourth renewal in a day: %v", err)
	}
	cur, _ := e.store.Box(ctx, b.Address())
	e.want(e.do("PUT", "/v1/"+b.Address().String()+"/prekey", protocol.PrekeyRequest{Prekey: cur.Statement, PrekeySignature: cur.Signature}, ""), 200, "")
	if len(cur.Retired) != 2 {
		t.Fatalf("the record keeps %d retired prekeys, want 2", len(cur.Retired))
	}
	for i, serial := range []string{"2", "3"} {
		st, err := os.ReadFile(filepath.Join(b.Dir(), "prekeys", serial+".txt"))
		if err != nil {
			t.Fatal(err)
		}
		p, _ := protocol.ParsePrekey(st)
		if cur.Retired[i].KeyHash != sha256.Sum256([]byte(p.Key)) {
			t.Fatalf("retired[%d] is not prekey %s: the newest are not the ones kept", i, serial)
		}
	}
	e.clock.Add(23 * time.Hour)
	if _, err := b.Rekey(ctx, ""); err != nil {
		t.Fatalf("a renewal the next day: %v", err)
	}
}

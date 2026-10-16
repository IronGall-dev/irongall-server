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
	"regexp"
	"strconv"
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

func (e *env) do(method, path string, body any, pass string) reply {
	e.t.Helper()
	return e.doAs("", method, path, body, pass)
}

// doAs is do, calling the server by the name host when one is given.
func (e *env) doAs(host, method, path string, body any, pass string) reply {
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
	if host != "" {
		req.Host = host
	}
	if pass != "" {
		req.Header.Set("Authorization", pass)
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
			p.Status != int64(resp.StatusCode) || p.Type != p.Code.TypeURI() || p.Code.Status() != resp.StatusCode {
			e.t.Fatalf("%s %s: %d is not a problem+json body matching the status map: %s", method, path, resp.StatusCode, b)
		}
		if got := resp.Header.Get("WWW-Authenticate"); (got == protocol.PassScheme) != (resp.StatusCode == http.StatusUnauthorized) {
			e.t.Fatalf("%s %s: %d with WWW-Authenticate %q", method, path, resp.StatusCode, got)
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

// name is the name the tests call the server by: the host of its URL.
func (e *env) name() string { return strings.TrimPrefix(e.srv.URL, "http://") }

// passFor is a pass of box a for the server called name, signed at the
// test's clock by signer: a working key under its certificate.
func (e *env) passFor(signer ssh.Signer, a protocol.Address, name string) string {
	e.t.Helper()
	auth, _, err := protocol.NewPass(signer, a, name, e.clock.Now())
	if err != nil {
		e.t.Fatal(err)
	}
	return auth
}

// numbers returns the serials a box stands at in the store: its prekey's and
// its certificate's. A client takes them from its clock, so a test reads
// them and never assumes one.
func (e *env) numbers(a protocol.Address) (prekey, cert uint64) {
	e.t.Helper()
	b, err := e.store.Box(context.Background(), a)
	if err != nil || b == nil {
		e.t.Fatalf("the box's record: %v", err)
	}
	return b.Prekey.Serial, b.CertSerial
}

// worker loads the working key of a client's box, under its certificate:
// the one made with the prekey it published last.
func worker(t *testing.T, b *client.Box) ssh.Signer {
	t.Helper()
	n, err := os.ReadFile(filepath.Join(b.Dir(), "serial"))
	if err != nil {
		t.Fatal(err)
	}
	stem := filepath.Join(b.Dir(), "work", strings.TrimSpace(string(n)))
	k, err := os.ReadFile(stem)
	if err != nil {
		t.Fatal(err)
	}
	work, err := ssh.ParsePrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	line, err := os.ReadFile(stem + "-cert.pub")
	if err != nil {
		t.Fatal(err)
	}
	key, _, _, _, err := ssh.ParseAuthorizedKey(line)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewCertSigner(key.(*ssh.Certificate), work)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// pass is a new pass of a client's box, as the box would sign it now.
func (e *env) pass(b *client.Box) string {
	e.t.Helper()
	return e.passFor(worker(e.t, b), b.Address(), e.name())
}

// raw is a box built by hand, for requests the client would never make. Each
// prekey statement is signed by a working key, under a certificate, and both
// are kept by the number they were made under.
type raw struct {
	e      *env
	signer ssh.Signer // the identity
	id     *protocol.Identity
	keys   map[uint64]*age.X25519Identity
	stmt   map[uint64][]byte
	sig    map[uint64][]byte
	work   map[uint64]ssh.Signer // a working key under its certificate, by the certificate's serial
}

func (e *env) raw() *raw {
	e.t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	s, _ := ssh.NewSignerFromKey(priv)
	id, err := protocol.NewIdentity(pub)
	if err != nil {
		e.t.Fatal(err)
	}
	return &raw{e: e, signer: s, id: id, keys: map[uint64]*age.X25519Identity{}, stmt: map[uint64][]byte{}, sig: map[uint64][]byte{},
		work: map[uint64]ssh.Signer{}}
}

func (r *raw) path(rest string) string { return "/v1/" + r.id.Address().String() + rest }

// certify makes a new working key and its certificate, of the given serial,
// replacing any the box holds at that serial.
func (r *raw) certify(serial uint64) ssh.Signer {
	r.e.t.Helper()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	work, _ := ssh.NewSignerFromKey(priv)
	cert, err := protocol.NewCertificate(r.id, r.signer, work.PublicKey(), serial, r.e.clock.Now())
	if err != nil {
		r.e.t.Fatal(err)
	}
	s, err := cert.Signer(work)
	if err != nil {
		r.e.t.Fatal(err)
	}
	r.work[serial] = s
	return s
}

// prekey makes statement serial, with a new key unless key is given, signed
// by a new working key under a new certificate of the same serial.
func (r *raw) prekey(serial uint64, notAfter time.Time, key *age.X25519Identity) {
	r.e.t.Helper()
	r.prekeyUnder(r.certify(serial), serial, notAfter, key)
}

// prekeyUnder makes statement serial, signed by signer.
func (r *raw) prekeyUnder(signer ssh.Signer, serial uint64, notAfter time.Time, key *age.X25519Identity) {
	r.e.t.Helper()
	if key == nil {
		key, _ = age.GenerateX25519Identity()
	}
	r.keys[serial] = key
	p := &protocol.Prekey{Address: r.id.Address(), Serial: serial, Key: key.Recipient().String(), NotAfter: notAfter}
	sig, err := protocol.Sign(signer, p.Statement(), protocol.PrekeyNamespace(r.id.Address()))
	if err != nil {
		r.e.t.Fatal(err)
	}
	r.stmt[serial], r.sig[serial] = p.Statement(), sig
}

func (r *raw) registration(serial uint64) protocol.RegisterRequest {
	return protocol.RegisterRequest{Identity: r.id.Document(), Prekey: r.stmt[serial], PrekeySignature: r.sig[serial]}
}

func (r *raw) upload(serial uint64) protocol.PrekeyRequest {
	return protocol.PrekeyRequest{Prekey: r.stmt[serial], PrekeySignature: r.sig[serial]}
}

// pass is a new pass under the certificate of the given serial.
func (r *raw) pass(serial uint64) string {
	r.e.t.Helper()
	return r.e.passFor(r.work[serial], r.id.Address(), r.e.name())
}

// register registers the box with a new prekey 1, valid for d.
func (r *raw) register(d time.Duration) *raw {
	r.e.t.Helper()
	r.prekey(1, r.e.clock.Now().Add(d), nil)
	r.e.want(r.e.do("PUT", r.path(""), r.registration(1), r.pass(1)), 201, "")
	return r
}

// A signature is at most protocol.MaxSignature bytes as it arrives (PROTOCOL.md
// §3), what follows its END line included, and is kept and served as it was
// sent (§4.5). A pass is at most protocol.MaxPassAuthorization.
func TestASignatureIsBounded(t *testing.T) {
	e := newEnv(t, relaxed())
	now := e.clock.Now()
	pad := func(sig []byte, to int) []byte {
		return append(append([]byte{}, sig...), bytes.Repeat([]byte{'.'}, to-len(sig))...)
	}

	r := e.raw()
	r.prekey(1, now.Add(protocol.PrekeyLifetime), nil)
	r.sig[1] = pad(r.sig[1], protocol.MaxSignature)
	e.want(e.do("PUT", r.path(""), r.registration(1), r.pass(1)), 201, "")
	var got protocol.IdentityResponse
	if err := json.Unmarshal(e.do("GET", r.path("/identity"), nil, "").body, &got); err != nil || !bytes.Equal(got.PrekeySignature, r.sig[1]) {
		t.Errorf("the signature is not served as it was sent: %v", err)
	}

	over := e.raw()
	over.prekey(1, now.Add(protocol.PrekeyLifetime), nil)
	pass := over.pass(1)
	over.sig[1] = pad(over.sig[1], protocol.MaxSignature+1)
	e.want(e.do("PUT", over.path(""), over.registration(1), pass), 400, protocol.CodeBadKey)

	// A renewal is held to it too.
	r.prekey(2, now.Add(protocol.PrekeyLifetime), nil)
	r.sig[2] = pad(r.sig[2], protocol.MaxSignature+1)
	e.want(e.do("PUT", r.path("/prekey"), r.upload(2), r.pass(2)), 400, protocol.CodeBadKey)

	e.want(e.do("GET", r.path("/messages"), nil, strings.Repeat("x", protocol.MaxPassAuthorization+1)), 401, protocol.CodeUnauthorized)
}

func TestRegistration(t *testing.T) {
	e := newEnv(t, relaxed())
	now := e.clock.Now()
	r := e.raw()
	r.prekey(1, now.Add(protocol.MaxPrekeyLifetime), nil)
	reg, pass := r.registration(1), r.pass(1)

	e.want(e.do("PUT", "/v1/nope", reg, pass), 400, protocol.CodeBadAddress)
	e.want(e.do("PUT", r.path(""), []byte(`{"identity":"","prekey":"","prekey_signature":"","extra":1}`), pass), 400, protocol.CodeBadRequest)
	e.want(e.do("PUT", r.path(""), []byte(`{"identity":"","prekey":""}`), pass), 400, protocol.CodeBadRequest)
	e.want(e.do("PUT", r.path(""), []byte(`{"identity":"","prekey":"","prekey_signature":null}`), pass), 400, protocol.CodeBadRequest)
	e.want(e.do("PUT", r.path(""), []byte(`{"identity":"not base64!","prekey":"","prekey_signature":""}`), pass), 400, protocol.CodeBadEncoding)
	e.want(e.do("PUT", r.path(""), []byte(`not json`), pass), 400, protocol.CodeBadRequest)
	// A body is read as every reader reads JSON (PROTOCOL.md §0b): names
	// exactly, none twice, one value, and each byte field in its one
	// encoding.
	rj, _ := json.Marshal(reg)
	for name, body := range map[string][]byte{
		"a name in another case": bytes.Replace(rj, []byte(`"identity"`), []byte(`"IDENTITY"`), 1),
		"a long s for an s":      bytes.Replace(rj, []byte(`"prekey_signature"`), []byte(`"prekey_\u017fignature"`), 1),
		"a name twice":           bytes.Replace(rj, []byte(`{`), []byte(`{"identity":"",`), 1),
		"a bracket after it":     append(append([]byte{}, rj...), ']'),
		"a brace after it":       append(append([]byte{}, rj...), '}'),
		"a byte-order mark":      append([]byte("\xef\xbb\xbf"), rj...),
		"NaN beside it":          bytes.Replace(rj, []byte(`{`), []byte(`{"x":NaN,`), 1),
	} {
		if got := e.do("PUT", r.path(""), body, pass); got.status != 400 || got.code() != protocol.CodeBadRequest {
			t.Errorf("%s: %d %s, want 400 %s", name, got.status, got.code(), protocol.CodeBadRequest)
		}
	}
	for name, body := range map[string][]byte{
		"base64 with no padding": bytes.Replace(rj, []byte(`="`), []byte(`"`), 1),
		"base64 wrapped":         bytes.Replace(rj, []byte(`","prekey"`), []byte(`\n","prekey"`), 1),
		"its unused bits set":    unusedBitsSet(t, rj),
	} {
		if got := e.do("PUT", r.path(""), body, pass); got.status != 400 || got.code() != protocol.CodeBadEncoding {
			t.Errorf("%s: %d %s, want 400 %s", name, got.status, got.code(), protocol.CodeBadEncoding)
		}
	}

	other := e.raw()
	e.want(e.do("PUT", other.path(""), reg, pass), 400, protocol.CodeIdentityMismatch)

	// A document that hashes to its address but breaks the grammar.
	commented := append(bytes.TrimSuffix(r.id.Document(), []byte("\n")), []byte(" comment\n")...)
	h := sha256.Sum256(commented)
	e.want(e.do("PUT", "/v1/"+hex.EncodeToString(h[:]), protocol.RegisterRequest{Identity: commented, Prekey: reg.Prekey, PrekeySignature: reg.PrekeySignature}, pass), 400, protocol.CodeIdentityMismatch)

	// A small-order key: the grammar holds, the key check fails.
	small, err := os.ReadFile("../../../irongall-client/testdata/vectors/identity/small-order-1.doc")
	if err != nil {
		t.Fatal(err)
	}
	h = sha256.Sum256(small)
	e.want(e.do("PUT", "/v1/"+hex.EncodeToString(h[:]), protocol.RegisterRequest{Identity: small, Prekey: reg.Prekey, PrekeySignature: reg.PrekeySignature}, pass), 400, protocol.CodeBadKey)

	// A prekey statement under another identity's certificate; one the
	// identity signed itself; one a working key signed with no certificate;
	// one valid for too long; one expired.
	other.prekey(1, now.Add(protocol.MaxPrekeyLifetime), nil)
	e.want(e.do("PUT", r.path(""), protocol.RegisterRequest{Identity: reg.Identity, Prekey: reg.Prekey, PrekeySignature: other.sig[1]}, pass), 400, protocol.CodeBadKey)
	byIdentity, _ := protocol.Sign(r.signer, reg.Prekey, protocol.PrekeyNamespace(r.id.Address()))
	e.want(e.do("PUT", r.path(""), protocol.RegisterRequest{Identity: reg.Identity, Prekey: reg.Prekey, PrekeySignature: byIdentity}, pass), 400, protocol.CodeBadKey)
	_, bare, _ := ed25519.GenerateKey(rand.Reader)
	bareSigner, _ := ssh.NewSignerFromKey(bare)
	byBare, _ := protocol.Sign(bareSigner, reg.Prekey, protocol.PrekeyNamespace(r.id.Address()))
	e.want(e.do("PUT", r.path(""), protocol.RegisterRequest{Identity: reg.Identity, Prekey: reg.Prekey, PrekeySignature: byBare}, pass), 400, protocol.CodeBadKey)
	long := e.raw()
	long.prekey(1, now.Add(protocol.MaxPrekeyLifetime+time.Second), nil)
	e.want(e.do("PUT", long.path(""), long.registration(1), long.pass(1)), 400, protocol.CodePrekeyTime)
	expired := e.raw()
	expired.prekey(1, now, nil)
	e.want(e.do("PUT", expired.path(""), expired.registration(1), expired.pass(1)), 400, protocol.CodePrekeyTime)

	// The pass: there must be one, this box's, for this server, not run out,
	// and under the certificate the statement is signed under. A statement
	// that leaked registers nothing for whoever found it.
	e.want(e.do("PUT", r.path(""), reg, ""), 401, protocol.CodeUnauthorized)
	e.want(e.do("PUT", r.path(""), reg, "Bearer igt1_abc"), 401, protocol.CodeUnauthorized)
	e.want(e.do("PUT", r.path(""), reg, other.pass(1)), 401, protocol.CodeUnauthorized)
	e.want(e.do("PUT", r.path(""), reg, e.passFor(r.work[1], r.id.Address(), "another.example")), 401, protocol.CodeUnauthorized)
	e.want(e.do("PUT", r.path(""), reg, e.passFor(r.certify(2), r.id.Address(), e.name())), 401, protocol.CodeCertificateNotCurrent)
	e.clock.Add(-protocol.PassLifetime)
	ranOut := r.pass(1)
	e.clock.Add(protocol.PassLifetime)
	e.want(e.do("PUT", r.path(""), reg, ranOut), 401, protocol.CodePassExpired)
	e.clock.Add(protocol.MaxPassLifetime)
	tooFar := r.pass(1)
	e.clock.Add(-protocol.MaxPassLifetime)
	e.want(e.do("PUT", r.path(""), reg, tooFar), 401, protocol.CodePassExpired)
	if _, err := e.store.Box(context.Background(), r.id.Address()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("a refused registration left a box: %v", err)
	}

	// Registered: 201, then an identical retry is 200, and anything else is
	// a conflict. Neither answer carries anything.
	first := e.do("PUT", r.path(""), reg, pass)
	e.want(first, 201, "")
	again := e.do("PUT", r.path(""), reg, pass)
	e.want(again, 200, "")
	for _, rep := range []reply{first, again} {
		if string(bytes.TrimSpace(rep.body)) != "{}" {
			t.Fatalf("a registration answered %s", rep.body)
		}
	}
	e.want(e.do("PUT", r.path(""), reg, ""), 401, protocol.CodeUnauthorized) // a retry needs its pass too
	r2 := e.raw()
	r2.signer, r2.id = r.signer, r.id
	r2.prekey(1, now.Add(protocol.MaxPrekeyLifetime), nil)
	e.want(e.do("PUT", r.path(""), r2.registration(1), r2.pass(1)), 409, protocol.CodeConflict)

	// In use at once: it takes mail, and its owner's calls are served.
	a := e.box(protocol.Classic)
	if _, err := a.Send(context.Background(), r.id.Address(), "at once"); err != nil {
		t.Fatalf("send to a box just registered: %v", err)
	}
	list := e.do("GET", r.path("/messages"), nil, pass)
	e.want(list, 200, "")
	if !bytes.Contains(list.body, []byte(`"count":1`)) {
		t.Fatalf("the new box's list: %s", list.body)
	}

	// The registration limit, per IP.
	l := relaxed()
	l.RegistrationsPerHour = 1
	e2 := newEnv(t, l)
	e2.raw().register(time.Hour)
	y := e2.raw()
	y.prekey(1, now.Add(time.Hour), nil)
	rl := e2.do("PUT", y.path(""), y.registration(1), y.pass(1))
	e2.want(rl, 429, protocol.CodeRateLimited)
	if rl.header.Get("Retry-After") == "" {
		t.Fatal("429 without Retry-After")
	}
}

func TestOwnerCalls(t *testing.T) {
	e := newEnv(t, relaxed())
	now := e.clock.Now()
	r := e.raw().register(protocol.MaxPrekeyLifetime)
	pass := r.pass(1)

	e.want(e.do("GET", r.path("/messages"), nil, ""), 401, protocol.CodeUnauthorized)
	e.want(e.do("GET", r.path("/messages"), nil, "Bearer "+strings.Repeat("a", 50)), 401, protocol.CodeUnauthorized)
	// One character of the signature changed, in a pass not yet shown and in
	// one the server has already taken.
	flip := func(p string) string {
		i := strings.Index(p, `signature="`) + 200
		c := "A"
		if p[i] == 'A' {
			c = "B"
		}
		return p[:i] + c + p[i+1:]
	}
	e.want(e.do("GET", r.path("/messages"), nil, flip(pass)), 401, protocol.CodeUnauthorized)
	e.want(e.do("GET", r.path("/messages"), nil, pass), 200, "")
	e.want(e.do("GET", r.path("/messages"), nil, flip(pass)), 401, protocol.CodeUnauthorized)
	// Another box's pass is not this box's, and neither is this box's pass
	// made for another server.
	o := e.raw().register(time.Hour)
	e.want(e.do("GET", r.path("/messages"), nil, o.pass(1)), 401, protocol.CodeUnauthorized)
	e.want(e.do("GET", r.path("/messages"), nil, e.passFor(r.work[1], r.id.Address(), "another.example")), 401, protocol.CodeUnauthorized)
	// A working key the identity certified, which the server never saw a
	// prekey under, is not the box's current one.
	e.want(e.do("GET", r.path("/messages"), nil, e.passFor(r.certify(2), r.id.Address(), e.name())), 401, protocol.CodeCertificateNotCurrent)

	empty := e.do("GET", r.path("/messages"), nil, pass)
	e.want(empty, 200, "")
	if string(bytes.TrimSpace(empty.body)) != `{"count":0,"messages":[],"next_cursor":null,"poll_after":60}` {
		t.Fatalf("empty list %s", empty.body)
	}
	e.want(e.do("GET", r.path("/messages?cursor=zzz"), nil, pass), 400, protocol.CodeBadRequest)
	e.want(e.do("GET", r.path("/messages?limit=5"), nil, pass), 400, protocol.CodeBadRequest)
	e.want(e.do("GET", r.path("/messages/"+strings.Repeat("a", 64)), nil, pass), 404, protocol.CodeNoSuchMessage)
	e.want(e.do("DELETE", r.path("/messages/"+strings.Repeat("a", 64)), nil, pass), 404, protocol.CodeNoSuchMessage)
	req, _ := http.NewRequest(http.MethodPost, e.srv.URL+r.path("/token"), nil)
	req.Header.Set("Authorization", pass)
	if resp, err := http.DefaultClient.Do(req); err != nil || (resp.StatusCode != 404 && resp.StatusCode != 405) {
		t.Fatalf("POST …/token is still a route: %v %v", resp, err)
	} else {
		_ = resp.Body.Close()
	}

	// A pass is taken until it runs out, and not a second longer, whether or
	// not the server has taken it before; then the box signs another.
	e.clock.Add(protocol.PassLifetime - time.Second)
	e.want(e.do("GET", r.path("/messages"), nil, pass), 200, "")
	e.clock.Add(time.Second)
	e.want(e.do("GET", r.path("/messages"), nil, pass), 401, protocol.CodePassExpired)
	pass = r.pass(1)
	e.want(e.do("GET", r.path("/messages"), nil, pass), 200, "")
	// One that runs out more than an hour ahead is refused as one run out is.
	e.clock.Add(protocol.MaxPassLifetime - protocol.PassLifetime + time.Second)
	ahead := r.pass(1)
	e.clock.Add(-(protocol.MaxPassLifetime - protocol.PassLifetime + time.Second))
	e.want(e.do("GET", r.path("/messages"), nil, ahead), 401, protocol.CodePassExpired)
	e.clock.Add(time.Second)
	e.want(e.do("GET", r.path("/messages"), nil, ahead), 200, "")

	// Close: mail deleted, owner calls 404, /identity still answers so the
	// owner can read its serial; a new prekey reopens it, in use at once.
	a := e.box(protocol.Classic)
	if _, err := a.Send(context.Background(), r.id.Address(), "deleted by close"); err != nil {
		t.Fatal(err)
	}
	e.want(e.do("DELETE", r.path(""), nil, pass), 204, "")
	e.want(e.do("GET", r.path("/messages"), nil, pass), 404, protocol.CodeNoSuchMailbox)
	e.want(e.do("GET", r.path("/identity"), nil, ""), 200, "")
	e.want(e.do("PUT", r.path(""), r.registration(1), pass), 409, protocol.CodeConflict)
	if _, err := a.Send(context.Background(), r.id.Address(), "to a closed box"); client.Code(err) != protocol.CodeNoSuchMailbox {
		t.Fatalf("send to a closed box: %v", err)
	}
	e.want(e.do("PUT", r.path("/prekey"), r.upload(1), pass), 200, "") // an identical retry reopens nothing
	e.want(e.do("GET", r.path("/messages"), nil, pass), 404, protocol.CodeNoSuchMailbox)
	r.prekey(2, now.Add(protocol.MaxPrekeyLifetime), nil)
	reopened := e.do("PUT", r.path("/prekey"), r.upload(2), r.pass(2))
	e.want(reopened, 200, "")
	if string(bytes.TrimSpace(reopened.body)) != "{}" {
		t.Fatalf("a prekey upload answered %s", reopened.body)
	}
	if _, err := a.Send(context.Background(), r.id.Address(), "to a reopened box"); err != nil {
		t.Fatalf("send to a reopened box: %v", err)
	}
	// The pass from before the new certificate is refused, though the server
	// took it a moment ago; one under the new certificate is taken.
	e.want(e.do("GET", r.path("/messages"), nil, pass), 401, protocol.CodeCertificateNotCurrent)
	list := e.do("GET", r.path("/messages"), nil, r.pass(2))
	e.want(list, 200, "")
	if !bytes.Contains(list.body, []byte(`"count":1`)) {
		t.Fatalf("close did not delete the mail: %s", list.body)
	}
}

// A pass is made for one server, by the name the box calls it. A server
// takes one only on a request that calls it by a name of its own: the name
// is not sent with the pass, so checked against whatever name a request
// gives, a pass made for another server would pass here.
func TestAPassIsForOneServer(t *testing.T) {
	keys, _ := NewDevKeys()
	clk := &clock{t: time.Now().UTC().Truncate(time.Second)}
	e := &env{t: t, clock: clk, keys: keys, store: NewMemStore(clk.Now)}
	e.srv = httptest.NewServer(New(Config{Store: e.store, Keys: keys, Limits: relaxed(), Now: clk.Now, Names: []string{"mail.example", "mail.example:8443"}}).Handler())
	t.Cleanup(e.srv.Close)
	r := e.raw()
	r.prekey(1, clk.Now().Add(time.Hour), nil)
	ours := e.passFor(r.work[1], r.id.Address(), "mail.example")
	theirs := e.passFor(r.work[1], r.id.Address(), "another.example")

	// Called by a name that is not its own, the server takes no pass: not
	// one made for that name, and not one made for its own.
	e.want(e.doAs("another.example", "PUT", r.path(""), r.registration(1), theirs), 401, protocol.CodeUnauthorized)
	e.want(e.doAs("another.example", "PUT", r.path(""), r.registration(1), ours), 401, protocol.CodeUnauthorized)
	e.want(e.do("PUT", r.path(""), r.registration(1), e.passFor(r.work[1], r.id.Address(), e.name())), 401, protocol.CodeUnauthorized)
	// Called by its own name: the pass made for that name, and no other.
	e.want(e.doAs("mail.example", "PUT", r.path(""), r.registration(1), theirs), 401, protocol.CodeUnauthorized)
	e.want(e.doAs("mail.example", "PUT", r.path(""), r.registration(1), ours), 201, "")
	e.want(e.doAs("MAIL.example", "GET", r.path("/messages"), nil, ours), 200, "")
	e.want(e.doAs("mail.example:8443", "GET", r.path("/messages"), nil, e.passFor(r.work[1], r.id.Address(), "mail.example:8443")), 200, "")
	e.want(e.doAs("mail.example", "GET", r.path("/messages"), nil, theirs), 401, protocol.CodeUnauthorized)
	// A pass the server has taken is taken again only as that pass: the
	// same box's pass for another server stays refused.
	e.want(e.doAs("mail.example", "GET", r.path("/messages"), nil, ours), 200, "")
	e.want(e.doAs("another.example", "GET", r.path("/messages"), nil, theirs), 401, protocol.CodeUnauthorized)
}

func TestPrekeyRenewal(t *testing.T) {
	e := newEnv(t, relaxed())
	now := e.clock.Now()
	r := e.raw().register(protocol.MaxPrekeyLifetime)
	put := func(serial, under uint64) reply {
		return e.do("PUT", r.path("/prekey"), r.upload(serial), r.pass(under))
	}

	unknown := e.raw()
	unknown.prekey(2, now.Add(time.Hour), nil)
	e.want(e.do("PUT", unknown.path("/prekey"), unknown.upload(2), unknown.pass(2)), 404, protocol.CodeNoSuchMailbox)

	e.want(put(1, 1), 200, "") // an identical retry of the current statement
	r.prekey(2, now.Add(time.Hour), r.keys[1])
	e.want(put(2, 2), 400, protocol.CodePrekeyNotNew) // the same key again
	r.prekey(2, now.Add(time.Hour), nil)
	// A good statement with no pass, with a pass under the box's current
	// certificate and not its own, and with another box's pass.
	e.want(e.do("PUT", r.path("/prekey"), r.upload(2), ""), 401, protocol.CodeUnauthorized)
	e.want(put(2, 1), 401, protocol.CodeCertificateNotCurrent)
	e.want(e.do("PUT", r.path("/prekey"), r.upload(2), unknown.pass(2)), 401, protocol.CodeUnauthorized)
	old := r.pass(1)
	e.want(e.do("GET", r.path("/messages"), nil, old), 200, "")
	e.want(put(2, 2), 200, "")
	// The box is now known by certificate 2: the pass under 1, taken a moment
	// ago, is refused, and so is a statement under 1.
	e.want(e.do("GET", r.path("/messages"), nil, old), 401, protocol.CodeCertificateNotCurrent)
	e.want(e.do("GET", r.path("/messages"), nil, r.pass(2)), 200, "")
	r.prekeyUnder(r.work[1], 3, now.Add(time.Hour), nil)
	e.want(put(3, 1), 401, protocol.CodeCertificateNotCurrent)
	// Another certificate of the current serial is not the current one.
	current := r.work[2]
	r.prekey(3, now.Add(time.Hour), nil)
	r.prekeyUnder(r.certify(2), 3, now.Add(time.Hour), nil)
	e.want(put(3, 2), 401, protocol.CodeCertificateNotCurrent)
	// A higher serial under the current certificate is taken.
	r.work[2] = current
	r.prekeyUnder(current, 3, now.Add(time.Hour), nil)
	e.want(put(3, 2), 200, "")
	e.want(e.do("GET", r.path("/messages"), nil, r.pass(2)), 200, "")

	r.prekey(4, now.Add(time.Hour), r.keys[1])
	e.want(put(4, 4), 400, protocol.CodePrekeyNotNew) // a live retired key
	// Under the box's current certificate the serial must rise.
	r.prekeyUnder(current, 3, now.Add(2*time.Hour), nil)
	e.want(put(3, 2), 409, protocol.CodeConflict)
	r.prekeyUnder(current, 1, now.Add(2*time.Hour), nil)
	e.want(put(1, 2), 409, protocol.CodeConflict)

	// A statement must not outlive the certificate it is signed under, and
	// a certificate that has ended signs nothing.
	e.clock.Add(protocol.CertificateLifetime - protocol.MaxPrekeyLifetime + time.Hour)
	r.prekeyUnder(current, 5, e.clock.Now().Add(protocol.MaxPrekeyLifetime), nil)
	e.want(put(5, 2), 400, protocol.CodeBadKey)
	e.clock.Add(protocol.MaxPrekeyLifetime)
	r.prekeyUnder(current, 5, e.clock.Now().Add(time.Hour), nil)
	e.want(e.do("PUT", r.path("/prekey"), r.upload(5), ""), 400, protocol.CodePrekeyTime)
	// The box cannot poll under an ended certificate either, and comes back
	// with a prekey under a new one.
	e.want(e.do("GET", r.path("/messages"), nil, r.pass(2)), 401, protocol.CodePassExpired)
	r.prekey(5, e.clock.Now().Add(time.Hour), nil)
	e.want(put(5, 5), 200, "")
	e.want(e.do("GET", r.path("/messages"), nil, r.pass(5)), 200, "")

	// A box's statements are ordered by certificate first. A later
	// certificate passes any serial under an earlier one: the box moves to
	// certificate 6 at prekey serial 1, below the 5 it stood at, and the
	// serial rises from there. An earlier certificate is refused whatever
	// serial comes under it.
	r.prekeyUnder(r.certify(6), 1, e.clock.Now().Add(time.Hour), nil)
	e.want(put(1, 6), 200, "")
	e.want(e.do("GET", r.path("/messages"), nil, r.pass(6)), 200, "")
	e.want(e.do("GET", r.path("/messages"), nil, r.pass(5)), 401, protocol.CodeCertificateNotCurrent)
	r.prekeyUnder(r.work[6], 1, e.clock.Now().Add(2*time.Hour), nil)
	e.want(put(1, 6), 409, protocol.CodeConflict)
	r.prekeyUnder(r.work[5], 9, e.clock.Now().Add(time.Hour), nil)
	e.want(put(9, 5), 401, protocol.CodeCertificateNotCurrent)
	r.prekeyUnder(r.work[6], 2, e.clock.Now().Add(time.Hour), nil)
	e.want(put(2, 6), 200, "")
}

func TestSendPipeline(t *testing.T) {
	e := newEnv(t, relaxed())
	ctx := context.Background()
	a, b := e.box(protocol.Classic), e.box(protocol.PostQuantum)
	bBox, _ := e.store.Box(ctx, b.Address())
	pqRecipient, _ := bBox.Prekey.Recipient()

	// seal encrypts to the given recipients. What is inside is the
	// recipient's to judge: the server sees an age file and a pass.
	seal := func(rs ...age.Recipient) protocol.SendRequest {
		var ct bytes.Buffer
		w, err := age.Encrypt(&ct, rs...)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.WriteString(w, `{"v":1}`)
		_ = w.Close()
		serial, under := e.numbers(b.Address())
		return protocol.SendRequest{PrekeySerial: &serial, CertificateSerial: &under, Ciphertext: ct.Bytes()}
	}
	to := "/v1/" + b.Address().String()
	ok := seal(pqRecipient)
	classic, _ := age.GenerateX25519Identity()
	pass := e.pass(a)

	// The pass comes first: with none, nothing of the body is judged.
	e.want(e.do("POST", to, ok, ""), 401, protocol.CodeUnauthorized)
	e.want(e.do("POST", to, []byte("not json"), ""), 401, protocol.CodeUnauthorized)
	e.want(e.do("POST", "/v1/nope", ok, ""), 401, protocol.CodeUnauthorized)

	e.want(e.do("POST", to, []byte("not json"), pass), 400, protocol.CodeBadRequest)
	// The sender is the box the pass names: the body names none, and holds
	// no signature.
	j, _ := json.Marshal(ok)
	for _, member := range []string{`"from":"` + a.Address().String() + `",`, `"signature":"",`} {
		e.want(e.do("POST", to, append([]byte("{"+member), j[1:]...), pass), 400, protocol.CodeBadRequest)
	}
	// Read as every reader reads JSON (PROTOCOL.md §0b), its serials no more
	// than 2^53 - 1 and written as integers.
	serial := regexp.MustCompile(`"prekey_serial":[0-9]+`)
	for name, body := range map[string][]byte{
		"a name in another case":   bytes.Replace(j, []byte(`"ciphertext"`), []byte(`"Ciphertext"`), 1),
		"a name twice":             bytes.Replace(j, []byte(`{`), []byte(`{"prekey_serial":1,`), 1),
		"a bracket after it":       append(append([]byte{}, j...), ']'),
		"a serial above 2^53 - 1":  serial.ReplaceAll(j, []byte(`"prekey_serial":9007199254740992`)),
		"a serial with a fraction": serial.ReplaceAllFunc(j, func(b []byte) []byte { return append(append([]byte{}, b...), ".0"...) }),
		"a serial as a string":     serial.ReplaceAllFunc(j, func(b []byte) []byte { return []byte(`"prekey_serial":"` + string(b[16:]) + `"`) }),
	} {
		if got := e.do("POST", to, body, pass); got.status != 400 || got.code() != protocol.CodeBadRequest {
			t.Errorf("%s: %d %s, want 400 %s", name, got.status, got.code(), protocol.CodeBadRequest)
		}
	}
	e.want(e.do("POST", to, unusedBitsSet(t, j), pass), 400, protocol.CodeBadEncoding)
	e.want(e.do("POST", "/v1/nope", ok, pass), 400, protocol.CodeBadAddress)
	zero := ok
	var z uint64
	zero.PrekeySerial = &z
	e.want(e.do("POST", to, zero, pass), 400, protocol.CodeBadRequest)
	noSerial := ok
	noSerial.PrekeySerial = nil
	e.want(e.do("POST", to, noSerial, pass), 400, protocol.CodeBadRequest)
	// A prekey is named by both serials: its own, and its certificate's.
	zeroCert, noCert := ok, ok
	zeroCert.CertificateSerial, noCert.CertificateSerial = &z, nil
	e.want(e.do("POST", to, zeroCert, pass), 400, protocol.CodeBadRequest)
	e.want(e.do("POST", to, noCert, pass), 400, protocol.CodeBadRequest)
	notAge := ok
	notAge.Ciphertext = []byte("not an age file")
	e.want(e.do("POST", to, notAge, pass), 400, protocol.CodeNotAge)
	e.want(e.do("POST", to, seal(classic.Recipient()), pass), 400, protocol.CodeWrongRecipientType)
	two, _ := age.GenerateHybridIdentity()
	e.want(e.do("POST", to, seal(pqRecipient, two.Recipient()), pass), 400, protocol.CodeWrongRecipientType)
	stale := ok
	s9 := uint64(9)
	stale.PrekeySerial = &s9
	e.want(e.do("POST", to, stale, pass), 409, protocol.CodeStalePrekey)
	staleCert := ok
	staleCert.CertificateSerial = &s9
	e.want(e.do("POST", to, staleCert, pass), 409, protocol.CodeStalePrekey)

	big := relaxed()
	big.MaxSize = 100
	small := newEnv(t, big)
	sa, sb := small.box(protocol.Classic), small.box(protocol.Classic)
	if _, err := sa.Send(ctx, sb.Address(), strings.Repeat("x", 200)); client.Code(err) != protocol.CodeTooLarge {
		t.Fatalf("send over the cap: %v", err)
	}

	// A pass that names no box here, and a recipient that is none.
	unregistered := e.raw()
	unregistered.prekey(1, e.clock.Now().Add(time.Hour), nil)
	e.want(e.do("POST", to, ok, unregistered.pass(1)), 403, protocol.CodeUnknownSender)
	e.want(e.do("POST", "/v1/"+unregistered.id.Address().String(), ok, pass), 404, protocol.CodeNoSuchMailbox)
	// A pass that is not the box's it names: under a certificate the server
	// never saw, and with its signature changed.
	other := e.raw()
	other.signer, other.id = signer(t, a), a.Identity()
	e.want(e.do("POST", to, ok, e.passFor(other.certify(7), a.Address(), e.name())), 401, protocol.CodeCertificateNotCurrent)
	e.clock.Add(-protocol.PassLifetime)
	ranOut := e.pass(a)
	e.clock.Add(protocol.PassLifetime)
	e.want(e.do("POST", to, ok, ranOut), 401, protocol.CodePassExpired)

	// A registered sender that is closed.
	c := e.raw().register(time.Hour)
	e.want(e.do("DELETE", c.path(""), nil, c.pass(1)), 204, "")
	e.want(e.do("POST", to, ok, c.pass(1)), 403, protocol.CodeUnknownSender)

	first := e.do("POST", to, ok, pass)
	e.want(first, 201, "")
	retry := e.do("POST", to, ok, pass)
	e.want(retry, 200, "")
	if !bytes.Equal(first.body, retry.body) {
		t.Fatalf("a retry's receipt %s is not the original %s", retry.body, first.body)
	}
	// The same ciphertext under another box's pass: a conflict, never a
	// receipt.
	d := e.box(protocol.Classic)
	e.want(e.do("POST", to, ok, e.pass(d)), 409, protocol.CodeConflict)
	// What the recipient is handed names the box whose pass the send
	// carried, and holds no signature.
	var rcpt protocol.Receipt
	_ = json.Unmarshal(first.body, &rcpt)
	fetched := e.do("GET", "/v1/"+b.Address().String()+"/messages/"+rcpt.ID, nil, e.pass(b))
	e.want(fetched, 200, "")
	var got map[string]json.RawMessage
	_ = json.Unmarshal(fetched.body, &got)
	if len(got) != 5 || string(got["from"]) != `"`+a.Address().String()+`"` || got["ciphertext"] == nil || got["signature"] != nil {
		t.Fatalf("a fetched message: %s", fetched.body)
	}

	// Revoked boxes, set by hand: this test puts B back afterwards, which no
	// route does. The route itself is TestRevocation.
	for _, box := range []protocol.Address{a.Address(), b.Address()} {
		rec, _ := e.store.Box(ctx, box)
		rec.State = Revoked
		_ = e.store.UpdateBox(ctx, rec)
	}
	e.want(e.do("POST", to, seal(pqRecipient), pass), 403, protocol.CodeSenderRevoked)
	e.want(e.do("POST", to, seal(pqRecipient), e.pass(d)), 410, protocol.CodeRevoked)
	e.want(e.do("GET", "/v1/"+a.Address().String()+"/identity", nil, ""), 410, protocol.CodeRevoked)
	e.want(e.do("GET", "/v1/"+a.Address().String()+"/messages", nil, pass), 410, protocol.CodeRevoked)

	// An expired recipient prekey.
	rec, _ := e.store.Box(ctx, b.Address())
	rec.State = Active
	_ = e.store.UpdateBox(ctx, rec)
	e.clock.Add(protocol.MaxPrekeyLifetime)
	e.want(e.do("POST", to, seal(pqRecipient), e.pass(d)), 409, protocol.CodePrekeyExpired)
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
	serial, under := e.numbers(b.Address())
	req := protocol.SendRequest{PrekeySerial: &serial, CertificateSerial: &under, Ciphertext: ct.Bytes()}
	e.want(e.do("POST", "/v1/"+b.Address().String(), req, e.pass(a)), 201, "")
}

func TestPerIPLimits(t *testing.T) {
	l := relaxed()
	l.SendsPerMinutePerIP = 1
	e := newEnv(t, l)
	a, b := e.box(protocol.Classic), e.box(protocol.Classic)
	send(t, a, b, "1")
	_, err := a.Send(context.Background(), b.Address(), "2")
	var ae *client.APIError
	if !errors.As(err, &ae) || ae.Problem.Code != protocol.CodeRateLimited {
		t.Fatalf("second send in a minute from one IP: %v", err)
	}
	if ae.RetryAfter <= 0 || !strings.Contains(err.Error(), "the server asks to wait "+strconv.Itoa(int(ae.RetryAfter/time.Second))+" seconds") {
		t.Fatalf("the error does not say the wait Retry-After gives (%s): %v", ae.RetryAfter, err)
	}
}

// Behind a proxy every request comes from the proxy's address: per-IP limits
// key on CF-Connecting-IP from a trusted proxy, and on the peer otherwise, so
// no one outside can pick their own bucket. The limit read here is the one on
// sends, which is taken before a send's pass is looked at.
func TestClientIPFromTrustedProxy(t *testing.T) {
	l := relaxed()
	l.SendsPerMinutePerIP = 1
	keys, _ := NewDevKeys()
	clk := time.Now()
	store := NewMemStore(func() time.Time { return clk })
	for _, c := range []struct {
		name    string
		trusted []netip.Prefix
		second  int // the status of a second call from another CF-Connecting-IP
	}{
		{"trusted peer: one bucket per client", []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}, http.StatusUnauthorized},
		{"untrusted peer: the header is ignored", nil, http.StatusTooManyRequests},
	} {
		t.Run(c.name, func(t *testing.T) {
			srv := httptest.NewServer(New(Config{Store: store, Keys: keys, Limits: l, TrustedProxies: c.trusted}).Handler())
			defer srv.Close()
			call := func(ip string) int {
				req, _ := http.NewRequest(http.MethodPost, srv.URL+"/v1/"+protocol.Address{1}.String(), nil)
				req.Header.Set("CF-Connecting-IP", ip)
				resp, err := http.DefaultClient.Do(req)
				if err != nil {
					t.Fatal(err)
				}
				_ = resp.Body.Close()
				return resp.StatusCode
			}
			if got := call("192.0.2.1"); got != http.StatusUnauthorized {
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
	// sealOld seals to the retired classic key, naming serial.
	sealOld := func(body string, serial uint64) protocol.SendRequest {
		var ct bytes.Buffer
		w, _ := age.Encrypt(&ct, oldRecipient)
		_, _ = io.WriteString(w, body)
		_ = w.Close()
		return protocol.SendRequest{PrekeySerial: &serial, CertificateSerial: &serial, Ciphertext: ct.Bytes()}
	}
	to := "/v1/" + b.Address().String()
	current, _ := e.numbers(b.Address())
	e.want(e.do("POST", to, sealOld("named the retired serial", old.Prekey.Serial), e.pass(a)), 409, protocol.CodeStalePrekey)
	e.want(e.do("POST", to, sealOld("sealed to the retired key", current), e.pass(a)), 400, protocol.CodeWrongRecipientType)
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
	// The Go client certifies a new working key with each prekey, so each of
	// its renewals is its identity's act, counted under that limit: a
	// renewal under the current certificate counts under the other
	// (TestTheRemedyRenewsWhenATakerSpentTheDaysRenewals).
	l.RenewalsPerDay, l.CertificatesPerDay, l.RetiredKept = 3, 3, 2
	e := newEnv(t, l)
	ctx := context.Background()
	now := e.clock.Now()
	e.clock.Add(now.Truncate(24 * time.Hour).Add(25 * time.Hour).Sub(now)) // 01:00 UTC, far from a day's end
	b := e.box(protocol.Classic)
	var renewed []uint64
	for i := range 3 {
		p, err := b.Rekey(ctx, "")
		if err != nil {
			t.Fatalf("renewal %d: %v", i+1, err)
		}
		renewed = append(renewed, p.Serial)
	}
	_, err := b.Rekey(ctx, "")
	var ae *client.APIError
	if !errors.As(err, &ae) || ae.Problem.Code != protocol.CodeCertificatesSpent || ae.RetryAfter != 23*time.Hour {
		t.Fatalf("a fourth renewal in a day: %v", err)
	}
	cur, _ := e.store.Box(ctx, b.Address())
	e.want(e.do("PUT", "/v1/"+b.Address().String()+"/prekey", protocol.PrekeyRequest{Prekey: cur.Statement, PrekeySignature: cur.Signature}, e.pass(b)), 200, "")
	if len(cur.Retired) != 2 {
		t.Fatalf("the record keeps %d retired prekeys, want 2", len(cur.Retired))
	}
	for i, n := range renewed[:2] { // the first two renewals: the third is current
		serial := strconv.FormatUint(n, 10)
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

// unusedBitsSet returns body with the unused bits of its last base64 field
// that has padding set: the same bytes to a lax decoder, and not base64 in
// its one encoding.
func unusedBitsSet(t *testing.T, body []byte) []byte {
	t.Helper()
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	i := bytes.LastIndex(body, []byte(`="`))
	for i > 0 && body[i-1] == '=' {
		i--
	}
	if i < 1 {
		t.Fatal("no base64 field with padding in the body")
	}
	c := strings.IndexByte(alphabet, body[i-1])
	if c < 0 || c%4 != 0 {
		t.Fatalf("the last base64 field is not in its one encoding: %q", body[i-1])
	}
	out := append([]byte{}, body...)
	out[i-1] = alphabet[c+1]
	return out
}

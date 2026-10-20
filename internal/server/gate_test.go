package server

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/IronGall-dev/irongall-client/api/apitest"
	"github.com/IronGall-dev/irongall-client/protocol"
)

// recorded is a request body that records whether anything read it.
type recorded struct {
	r    io.Reader
	read bool
}

func (b *recorded) Read(p []byte) (int, error) {
	b.read = true
	return b.r.Read(p)
}

// counts is every series of the counter family name in reg, by its labels.
func counts(t *testing.T, reg *prometheus.Registry, name string) map[string]float64 {
	t.Helper()
	fams, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]float64{}
	for _, f := range fams {
		if f.GetName() != name {
			continue
		}
		for _, m := range f.GetMetric() {
			var labels []string
			for _, l := range m.GetLabel() {
				labels = append(labels, l.GetName()+"="+l.GetValue())
			}
			out[strings.Join(labels, ",")] = m.GetCounter().GetValue()
		}
	}
	return out
}

// moved is what changed between two reads of counts: each series that moved,
// by how much.
func moved(before, after map[string]float64) map[string]float64 {
	d := map[string]float64{}
	for k, v := range after {
		if v != before[k] {
			d[k] = v - before[k]
		}
	}
	return d
}

var passSignature = regexp.MustCompile(`signature="([^"]*)"`)

// respelled is pass with a space put in its signature's armor, after the
// BEGIN line: one pass to a verifier, another value to a hash.
func respelled(t *testing.T, pass string) string {
	t.Helper()
	armored, err := base64.StdEncoding.DecodeString(passSignature.FindStringSubmatch(pass)[1])
	if err != nil {
		t.Fatal(err)
	}
	spaced := strings.Replace(string(armored), "-----\n", "-----\n ", 1)
	return passSignature.ReplaceAllLiteralString(pass, `signature="`+base64.StdEncoding.EncodeToString([]byte(spaced))+`"`)
}

// Every request is counted before anything is done for it: every route is
// put on its router through one gate, and a request no route answers is
// counted by the router's own (LIMITS.md, rule 1;
// IronGall-dev/irongall-client#269, IronGall-dev/irongall-server#67, #69). So
// from an address past its flood budget, every route, the link page, a site's
// page and a request no route answers are refused 429 requests, whatever
// the call carries, with nothing else done: no other count of any limit
// taken, no pass parsed or checked, no box looked up, no body read. A pass
// this process has checked, to a route that checks a pass before anything
// else, is its box's call and goes on, and its body is read only once a
// count of its box's, or of its address's for a lookup, has been taken. A
// new route is held to this by being one of routes().
func TestEveryRequestIsCountedBeforeAnythingIsDone(t *testing.T) {
	l := relaxed()
	l.RequestBurst, l.RequestRefill = 1, time.Hour
	l.MissesPerMinute = 1000
	l.CallBurst, l.CallRefill = 1000, time.Hour
	site, err := LoadSite(writeSite(t, siteFiles))
	if err != nil {
		t.Fatal(err)
	}
	reg := prometheus.NewRegistry()
	e := newEnv(t, l, func(c *Config) { c.Metrics, c.Site = NewMetrics(reg), site })
	b := e.box(protocol.Classic)
	own := "/v1/" + b.Address().String()
	checked := e.pass(b)
	e.want(e.do("GET", own+"/messages", nil, checked), http.StatusOK, "")
	e.clock.Add(time.Second)
	values := []struct{ name, auth string }{
		{"no pass", ""},
		{"5,600 bytes of commas", "irongall-pass " + strings.Repeat(",", protocol.MaxPassAuthorization-len("irongall-pass "))},
		{"a new pass of a registered box", e.pass(b)},
		{"the checked pass, respelled", respelled(t, checked)},
		{"the checked pass", checked},
	}
	nobody := strings.Repeat("ab", 32) // an address the server holds nothing of
	type target struct {
		method, path string
		pass         bool // a route that checks a pass before anything else
		direct       bool // answered by the router or a site, which the API's description does not hold
	}
	var targets []target
	for _, r := range e.server.routes() {
		method, path, _ := strings.Cut(r.pattern, " ")
		path = strings.NewReplacer("{addr}", nobody, "{id}", strings.Repeat("0", 64)).Replace(path)
		targets = append(targets, target{method, path, r.pass, false})
		if r.pass { // the same route on the pass's own box
			targets = append(targets, target{method, strings.Replace(path, nobody, b.Address().String(), 1), true, false})
		}
	}
	targets = append(targets,
		target{"GET", protocol.LinkPath + nobody, false, false},
		target{"GET", "/llms.txt", false, true},
		target{"GET", "/v1/" + nobody + "/nothing/here", false, true},
		target{"POST", protocol.LinkPath + nobody, false, true},
	)
	described, direct := apitest.Handler(t, e.server.Handler()), e.server.Handler()
	n := 0
	for _, tg := range targets {
		for _, v := range values {
			n++
			ip := fmt.Sprintf("10.0.%d.%d", n/200, n%200+1)
			if got := e.caller()(ip, "GET", protocol.LinkPath+nobody, nil, ""); got.status != http.StatusOK { // its one call
				t.Fatalf("the address's one call: %d", got.status)
			}
			body := &recorded{r: strings.NewReader(`{"identity":"` + strings.Repeat("A", 4000) + `"}`)}
			req := httptest.NewRequest(tg.method, tg.path, body)
			req.Host = e.name()
			req.RemoteAddr = net.JoinHostPort(ip, "40000")
			if v.auth != "" {
				req.Header.Set("Authorization", v.auth)
			}
			limits, passes := counts(t, reg, "irongalld_limit_requests_total"), counts(t, reg, "irongalld_passes_total")
			w := httptest.NewRecorder()
			if tg.direct {
				direct.ServeHTTP(w, req)
			} else {
				described.ServeHTTP(w, req)
			}
			got := reply{status: w.Code, header: w.Header(), body: w.Body.Bytes()}
			what := fmt.Sprintf("%s %s with %s", tg.method, tg.path, v.name)
			if tg.pass && v.auth == checked {
				if q, _ := got.quota(); q == protocol.QuotaRequests {
					t.Errorf("%s: refused for the address's flood budget, though its box's pass was checked", what)
				}
				if d := moved(limits, counts(t, reg, "irongalld_limit_requests_total")); body.read && len(d) == 0 {
					t.Errorf("%s: its body was read with no count taken", what)
				}
				continue
			}
			if q, _ := got.quota(); got.status != http.StatusTooManyRequests || q != protocol.QuotaRequests {
				t.Errorf("%s, past the address's flood budget: %d %s, want 429 requests", what, got.status, got.body)
				continue
			}
			if d := moved(limits, counts(t, reg, "irongalld_limit_requests_total")); len(d) != 1 || d["decision=denied,limit=requests,subject=ip"] != 1 {
				t.Errorf("%s: limits taken besides the one refusal: %v", what, d)
			}
			if d := moved(passes, counts(t, reg, "irongalld_passes_total")); len(d) != 0 {
				t.Errorf("%s: passes looked at: %v", what, d)
			}
			if body.read {
				t.Errorf("%s: its body was read", what)
			}
		}
	}
}

// A pass this process has not checked is its address's call until it is: it
// spends the address's flood budget before its signatures are checked, as
// Let's Encrypt limits every endpoint per address in front of its check of
// a request's signature. So a box that signs a new pass for every call has
// at most that budget of them checked from one address
// (IronGall-dev/irongall-server#67), and a pass the process has checked
// spends none of it: another box behind the same address goes on.
func TestANewPassSpendsItsAddresssFloodBudget(t *testing.T) {
	l := relaxed()
	l.RequestBurst, l.RequestRefill = 20, time.Hour
	e, m, _ := metered(t, l)
	b, c := e.box(protocol.Classic), e.box(protocol.Classic)
	call := e.caller()
	kept := e.pass(c)
	e.want(call("198.51.100.8", "GET", "/v1/"+c.Address().String()+"/messages", nil, kept), http.StatusOK, "")
	checked := m.passes.WithLabelValues("checked", "")
	before := testutil.ToFloat64(checked)
	w := worker(t, b)
	const ip = "198.51.100.7"
	answered, refused := 0, 0
	for i := range 150 {
		auth, _, err := protocol.NewPass(w, b.Address(), e.name(), e.clock.Now().Add(time.Duration(i+1)*time.Second))
		if err != nil {
			t.Fatal(err)
		}
		switch r := call(ip, "GET", "/v1/"+b.Address().String()+"/acl", nil, auth); {
		case r.status == http.StatusTooManyRequests:
			e.limited(r, protocol.QuotaRequests)
			refused++
		case r.status < 500:
			answered++
		default:
			t.Fatalf("a new pass: %d %s", r.status, r.body)
		}
	}
	if n := testutil.ToFloat64(checked) - before; n != float64(l.RequestBurst) || answered != l.RequestBurst || refused != 150-l.RequestBurst {
		t.Errorf("150 new passes from one address with a flood budget of %d: %v checked in full, %d answered, %d refused", l.RequestBurst, n, answered, refused)
	}
	e.want(call(ip, "GET", "/v1/"+c.Address().String()+"/messages", nil, kept), http.StatusOK, "")

	// A pass first shown in another form a server reads, the scheme in
	// capitals, is checked in that form too: it goes on from that address.
	d := e.box(protocol.Classic)
	e.clock.Add(time.Second) // not the pass its registration showed
	upper := strings.Replace(e.pass(d), "irongall-pass ", "IRONGALL-PASS ", 1)
	e.want(call("198.51.100.9", "GET", "/v1/"+d.Address().String()+"/messages", nil, upper), http.StatusOK, "")
	e.want(call(ip, "GET", "/v1/"+d.Address().String()+"/messages", nil, upper), http.StatusOK, "")

	// Two passes used in turn are each new when they come back: the gate
	// forgets a box's pass once another is checked.
	first := e.pass(c)
	e.clock.Add(time.Second)
	second := e.pass(c)
	const other = "198.51.100.10"
	for i, auth := range []string{first, second} {
		e.want(call(other+"0", "GET", "/v1/"+c.Address().String()+"/messages", nil, auth), http.StatusOK, "")
		if i == 0 {
			e.want(call(other, "GET", "/v1/"+c.Address().String()+"/messages", nil, auth), http.StatusOK, "") // the flooding address's own
		}
	}
	for range l.RequestBurst {
		call(other, "GET", "/nothing", nil, "")
	}
	e.limited(call(other, "GET", "/v1/"+c.Address().String()+"/messages", nil, first), protocol.QuotaRequests)
}

// One pass written another way that OpenSSH reads as the same signature is
// that one pass to the server: answered from memory, with no second check
// of its signatures, however its armor is spaced and however its SSHSIG blob
// writes its version, a NUL after its namespace or its reserved field,
// which nothing signs (IronGall-dev/irongall-server#69). A signature that
// differs in a bit is checked, and refused.
func TestARespelledPassCostsNoSecondCheck(t *testing.T) {
	e, m, _ := metered(t, relaxed())
	b := e.box(protocol.Classic)
	poll := func(auth string) reply { return e.do("GET", "/v1/"+b.Address().String()+"/messages", nil, auth) }
	e.clock.Add(time.Second) // not the pass the registration showed
	pass := e.pass(b)
	e.want(poll(pass), http.StatusOK, "")
	armored, err := base64.StdEncoding.DecodeString(passSignature.FindStringSubmatch(pass)[1])
	if err != nil {
		t.Fatal(err)
	}
	blob, err := protocol.Dearmor(armored)
	if err != nil {
		t.Fatal(err)
	}
	// rewrite is blob with version v, a NUL after its namespace when nul,
	// and reserved in its reserved field, armored as ssh-keygen does.
	rewrite := func(v uint32, nul bool, reserved []byte) []byte {
		rest := blob[10:]
		str := func() []byte {
			n := binary.BigEndian.Uint32(rest)
			s := rest[4 : 4+n]
			rest = rest[4+n:]
			return s
		}
		key, ns := str(), str()
		_ = str()
		hash, sig := str(), str()
		if nul {
			ns = append(append([]byte{}, ns...), 0)
		}
		out := binary.BigEndian.AppendUint32([]byte("SSHSIG"), v)
		for _, s := range [][]byte{key, ns, reserved, hash, sig} {
			out = binary.BigEndian.AppendUint32(out, uint32(len(s))) //nolint:gosec // a test's own signature
			out = append(out, s...)
		}
		return protocol.Armor(out)
	}
	with := func(a []byte) string {
		return passSignature.ReplaceAllLiteralString(pass, `signature="`+base64.StdEncoding.EncodeToString(a)+`"`)
	}
	forms := map[string][]byte{
		"CRLF after the BEGIN line":    bytes.Replace(armored, []byte("-----\n"), []byte("-----\r\n"), 1),
		"text after the END line":      append(append([]byte{}, armored...), "anything"...),
		"a tab inside the base64":      bytes.Replace(armored, []byte("-----\n"), []byte("-----\n\t"), 1),
		"a NUL before the END line":    bytes.Replace(armored, []byte("\n-----END"), []byte("\x00\n-----END"), 1),
		"the base64 on one line":       []byte("-----BEGIN SSH SIGNATURE-----\n" + base64.StdEncoding.EncodeToString(blob) + "\n-----END SSH SIGNATURE-----\n"),
		"SSHSIG version 0":             rewrite(0, false, nil),
		"a NUL ending the namespace":   rewrite(1, true, nil),
		"a byte in the reserved field": rewrite(1, false, []byte{'x'}),
	}
	at := bytes.IndexByte(armored, '\n') + 1
	for i := 0; i < 40; i++ {
		forms[fmt.Sprintf("a space after byte %d of the base64", i)] = append(append(append([]byte{}, armored[:at+i]...), ' '), armored[at+i:]...)
	}
	checked := m.passes.WithLabelValues("checked", "")
	before := testutil.ToFloat64(checked)
	for name, a := range forms {
		if r := poll(with(a)); r.status != http.StatusOK {
			t.Errorf("%s: %d %s", name, r.status, r.body)
		}
	}
	if n := testutil.ToFloat64(checked) - before; n != 0 {
		t.Errorf("%d ways of writing one pass: %v checked again", len(forms), n)
	}
	flipped := append([]byte{}, blob...)
	flipped[len(flipped)-1] ^= 1
	e.want(poll(with(protocol.Armor(flipped))), http.StatusUnauthorized, protocol.CodeUnauthorized)
}

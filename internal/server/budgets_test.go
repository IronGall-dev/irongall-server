package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/IronGall-dev/irongall-client/api/apitest"
	"github.com/IronGall-dev/irongall-client/client"
	"github.com/IronGall-dev/irongall-client/protocol"
)

// The budgets of LIMITS.md, and the order of checks they come in: every call
// spends from one, a count is taken before the work it guards, and what
// would change nothing is answered before what costs.

// A retry is answered as the first send was, from the dedupe record, though
// the box renewed its prekey since (PROTOCOL.md §4.5 step 6): stored once,
// counted once. A new ciphertext to the retired prekey is still stale.
func TestARetryAfterARenewalGetsItsReceipt(t *testing.T) {
	ctx := context.Background()
	l := relaxed()
	l.SendsPerDay = 1
	e := newEnv(t, l)
	a, b := e.box(protocol.Classic), e.box(protocol.Classic)
	sent := capture(e, "/v1/"+b.Address().String())
	first := send(t, a, b, "sent before the renewal")
	e.setMiddle(nil)
	if _, err := b.Rekey(ctx, ""); err != nil {
		t.Fatal(err)
	}
	r := e.do(http.MethodPost, "/v1/"+b.Address().String()+"/messages", *sent, e.pass(a))
	var again protocol.Receipt
	if r.status != http.StatusOK || json.Unmarshal(r.body, &again) != nil || again != *first {
		t.Fatalf("a retry after the renewal: %d %s, want 200 and %+v", r.status, r.body, *first)
	}
	if n, err := e.store.Count(ctx, b.Address()); err != nil || n != 1 {
		t.Fatalf("the box holds %d messages (%v), want the one", n, err)
	}
	other := *sent
	other.ciphertext = append([]byte{}, sent.ciphertext...)
	other.ciphertext[len(other.ciphertext)-1] ^= 1 // another ciphertext, to the same retired prekey
	e.want(e.do(http.MethodPost, "/v1/"+b.Address().String()+"/messages", other, e.pass(a)), http.StatusConflict, protocol.CodeStalePrekey)
}

// A sender's calls bound what its sends cost before they are checked, the
// dedupe's read among them, and a retry spends from them too
// (Limits.CallBurst): past them a replay is refused before anything is read.
func TestASendersCallsBoundTheDedupeRead(t *testing.T) {
	l := relaxed()
	e := newEnv(t, l)
	a, b := e.box(protocol.Classic), e.box(protocol.Classic)
	sent := capture(e, "/v1/"+b.Address().String())
	send(t, a, b, "once")
	e.setMiddle(nil)
	l.CallBurst, l.CallRefill = 3, time.Minute
	e2, cs := counted(t, e, l)
	pass := e2.pass(a)
	for range 3 {
		e2.want(e2.do(http.MethodPost, "/v1/"+b.Address().String()+"/messages", *sent, pass), http.StatusOK, "")
	}
	before := cs.reads.Load()
	r := e2.do(http.MethodPost, "/v1/"+b.Address().String()+"/messages", *sent, pass)
	e2.want(r, http.StatusTooManyRequests, protocol.CodeRateLimited)
	if r.header.Get("Retry-After") == "" {
		t.Error("no Retry-After")
	}
	if n := cs.reads.Load(); n != before {
		t.Fatalf("%d storage calls for a replay past the sender's calls", n-before)
	}
}

// A box takes new mail at a rate of its own, from every sender together
// (Limits.ReceiveBurst): past it a send is mailbox_busy and waits in its
// sender's outbox. A retry spends none of it, and an account can lift it.
func TestTheReceiveBudget(t *testing.T) {
	ctx := context.Background()
	l := relaxed()
	l.ReceiveBurst, l.ReceiveRefill = 2, time.Minute
	e := newEnv(t, l)
	b := e.box(protocol.Classic)
	s1, s2, s3 := e.box(protocol.Classic), e.box(protocol.Classic), e.box(protocol.Classic)
	sent := capture(e, "/v1/"+b.Address().String())
	send(t, s1, b, "one")
	e.setMiddle(nil)
	send(t, s2, b, "two")
	_, err := s3.Send(ctx, b.Address(), "three")
	var ae *client.APIError
	if client.Code(err) != protocol.CodeMailboxBusy || !errorsAs(err, &ae) || ae.RetryAfter <= 0 || ae.Status != http.StatusTooManyRequests {
		t.Fatalf("a third new message in the burst: %v", err)
	}
	e.want(e.do(http.MethodPost, "/v1/"+b.Address().String()+"/messages", *sent, e.pass(s1)), http.StatusOK, "") // a retry: nothing new
	e.clock.Add(time.Minute)
	if rs, err := s3.Flush(ctx); err != nil || len(rs) != 1 {
		t.Fatalf("the waiting message after a refill: %v, %v", rs, err)
	}
	if n, err := e.store.Count(ctx, b.Address()); err != nil || n != 3 {
		t.Fatalf("the box holds %d messages (%v), want 3", n, err)
	}

	// An unmetered account's box takes mail with no budget.
	_, key := accountEnv(t, e, true, 1)
	echo := e.box(protocol.Classic)
	adopt(t, echo, key)
	for i, s := range []*client.Box{s1, s2, s3, b} {
		if _, err := s.Send(ctx, echo.Address(), "to the unmetered box"); err != nil {
			t.Fatalf("send %d to an unmetered box: %v", i+1, err)
		}
	}
}

func errorsAs(err error, ae **client.APIError) bool {
	for err != nil {
		if e, ok := err.(*client.APIError); ok {
			*ae = e
			return true
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}

// A lookup, the read of a box, is its caller's to pay for, once for each
// read: with a pass, the box's calls (Limits.CallBurst); with none, its
// address's calls with no pass (Limits.PublicBurst), as the page a link
// opens is. A pass that does not verify is refused, not taken as none.
func TestLookupsArePaidByTheirCaller(t *testing.T) {
	t.Run("with a pass", func(t *testing.T) {
		l := relaxed()
		e := newEnv(t, l)
		a, b := e.box(protocol.Classic), e.box(protocol.Classic)
		l.CallBurst, l.CallRefill = 2, time.Minute
		e2, _ := counted(t, e, l)
		pass := e2.pass(a)
		read := "/v1/" + b.Address().String()
		for i := range l.CallBurst {
			if r := e2.do(http.MethodGet, read, nil, pass); r.status != http.StatusOK {
				t.Fatalf("read %d of %d: refused within the box's calls: %d %s", i+1, l.CallBurst, r.status, r.body)
			}
		}
		e2.want(e2.do(http.MethodGet, read, nil, pass), http.StatusTooManyRequests, protocol.CodeRateLimited)
		e2.want(e2.do(http.MethodGet, read, nil, ""), http.StatusOK, "") // the address's calls are its own
		e2.want(e2.do(http.MethodGet, read, nil, "irongall-pass nonsense"), http.StatusUnauthorized, protocol.CodeUnauthorized)
	})
	t.Run("with none", func(t *testing.T) {
		l := relaxed()
		e := newEnv(t, l)
		b := e.box(protocol.Classic)
		l.PublicBurst, l.PublicRefill = 2, time.Minute
		e2, _ := counted(t, e, l)
		read := "/v1/" + b.Address().String()
		e2.want(e2.do(http.MethodGet, read, nil, ""), http.StatusOK, "")
		page := e2.do(http.MethodGet, protocol.LinkPath+b.Address().String(), nil, "")
		if page.status != http.StatusOK {
			t.Fatalf("the link page: %d", page.status)
		}
		e2.want(e2.do(http.MethodGet, read, nil, ""), http.StatusTooManyRequests, protocol.CodeRateLimited)
		if r := e2.do(http.MethodGet, protocol.LinkPath+b.Address().String(), nil, ""); r.status != http.StatusTooManyRequests || r.header.Get("Retry-After") == "" {
			t.Fatalf("the link page past the address's calls: %d", r.status)
		}
	})
}

// A fetch or an ack of an id the box does not hold is answered from memory,
// and is a call like any other: it spends the box's calls. A held message's
// fetch and ack were paid for by its receive.
func TestUnknownIDsSpendTheBoxsCalls(t *testing.T) {
	l := relaxed()
	e := newEnv(t, l)
	a, b := e.box(protocol.Classic), e.box(protocol.Classic)
	send(t, a, b, "held")
	l.CallBurst, l.CallRefill = 2, time.Minute
	e2, _ := counted(t, e, l)
	pass := e2.pass(b)
	if res := receive(t, b); len(res.Delivered) != 1 {
		t.Fatalf("delivered %d", len(res.Delivered))
	}
	unknown := "/v1/" + b.Address().String() + "/messages/" + strings.Repeat("ab", 32)
	e2.want(e2.do(http.MethodDelete, unknown, nil, pass), http.StatusNotFound, protocol.CodeNoSuchMessage)
	e2.want(e2.do(http.MethodGet, unknown, nil, pass), http.StatusNotFound, protocol.CodeNoSuchMessage)
	e2.want(e2.do(http.MethodDelete, unknown, nil, pass), http.StatusTooManyRequests, protocol.CodeRateLimited)
}

// A prekey statement that could not be taken even if it verified is refused
// from its order, read before any signature is checked (PROTOCOL.md §6.4): a
// serial not above the current one under the current certificate is 409 and
// a certificate the floor covers is bad_key, though the signature is not the
// statement's. Nothing is counted against the caller for either.
func TestAStatementOutOfOrderIsRefusedBeforeItsSignature(t *testing.T) {
	l := relaxed()
	l.MissesPerMinute = 1
	e := newEnv(t, l)
	r := e.raw().register(protocol.MaxPrekeyLifetime)
	key, _ := age.GenerateX25519Identity()
	stale := &protocol.Prekey{Address: r.id.Address(), Serial: 1, Key: key.Recipient().String(), NotAfter: e.clock.Now().Add(time.Hour)}
	misSigned := protocol.PrekeyRequest{Prekey: stale.Statement(), PrekeySignature: r.sig[1]} // statement 1's signature, over other bytes
	e.want(e.do("PUT", r.path("/prekey"), misSigned, r.pass(1)), http.StatusConflict, protocol.CodeConflict)
	e.want(e.do("PUT", r.path("/revocations"), r.certs(1), ""), http.StatusOK, "")
	stale.Serial = 2
	misSigned.Prekey = stale.Statement()
	got := e.do("PUT", r.path("/prekey"), misSigned, r.pass(1))
	e.want(got, http.StatusUnauthorized, protocol.CodeCertificateRevoked)
	if !strings.Contains(string(got.body), "revoked") {
		t.Fatalf("a statement under a revoked certificate: %s", got.body)
	}
	var nobody protocol.Address
	e.want(e.do(http.MethodGet, "/v1/"+nobody.String(), nil, ""), http.StatusNotFound, protocol.CodeNoSuchMailbox) // the address's one miss is still there
}

// Registration never changes a box, so a box the process holds is answered
// from its record: anything but the identical registration is 409 with no
// check, and spends nothing of its address's registrations.
func TestAnExistingBoxIsAnsweredFromItsRecord(t *testing.T) {
	l := relaxed()
	l.RegistrationsPerHour = 1
	e := newEnv(t, l)
	r := e.raw().register(protocol.MaxPrekeyLifetime) // the address's one registration
	other := r.registration(1)
	other.PrekeySignature = []byte("not a signature")
	e.want(e.do("PUT", r.path(""), other, ""), http.StatusConflict, protocol.CodeConflict)
	e.want(e.do("PUT", r.path(""), r.registration(1), r.pass(1)), http.StatusOK, "")
}

// A revocation of certificates through a serial no higher than the one held
// changes nothing, and is answered so before its signature is checked: the
// same serial 200, a lower one 409, whatever the signature. Nothing is
// counted against the caller for either.
func TestAFloorNoHigherIsAnsweredWithoutACheck(t *testing.T) {
	l := relaxed()
	l.MissesPerMinute = 1
	e := newEnv(t, l)
	r := e.raw().register(protocol.MaxPrekeyLifetime)
	e.want(e.do("PUT", r.path("/revocations"), r.certs(7), ""), http.StatusOK, "")
	same, lower := r.certs(7), r.certs(5)
	same.RevokedCertificatesSignature, lower.RevokedCertificatesSignature = []byte("junk"), []byte("junk")
	e.want(e.do("PUT", r.path("/revocations"), same, ""), http.StatusOK, "")
	e.want(e.do("PUT", r.path("/revocations"), lower, ""), http.StatusConflict, protocol.CodeConflict)
	higher := r.certs(9)
	higher.RevokedCertificatesSignature = []byte("junk")
	e.want(e.do("PUT", r.path("/revocations"), higher, ""), http.StatusBadRequest, protocol.CodeBadRevocation) // checked, and the address's one miss spent
	e.want(e.do("PUT", r.path("/revocations"), higher, ""), http.StatusTooManyRequests, protocol.CodeRateLimited)
}

// The identity's acts are counted per box, each kind on its own, so neither
// holds back the other: its new certificates (Limits.CertificatesPerDay) and
// its raises of the revocation of certificates
// (Limits.CertificateRevocationsPerDay). A renewal while the box's current
// certificate is revoked is not counted: it replaces what a counted raise
// revoked. The revocation of the address is counted against no box, so
// nothing keeps an owner from ending a box.
func TestTheIdentitysActsAreCountedApart(t *testing.T) {
	l := relaxed()
	l.CertificatesPerDay, l.CertificateRevocationsPerDay = 1, 1
	e := newEnv(t, l)
	now := e.clock.Now()
	e.clock.Add(now.Truncate(24 * time.Hour).Add(25 * time.Hour).Sub(now)) // 01:00 UTC, far from a day's end
	r := e.raw().register(protocol.MaxPrekeyLifetime)
	until := e.clock.Now().Add(protocol.PrekeyLifetime)
	r.prekey(5, until, nil)
	e.want(e.do("PUT", r.path("/prekey"), r.upload(5), r.pass(5)), http.StatusOK, "") // the day's one certificate
	r.prekey(6, until, nil)
	e.want(e.do("PUT", r.path("/prekey"), r.upload(6), r.pass(6)), http.StatusTooManyRequests, protocol.CodeCertificatesSpent)
	e.want(e.do("PUT", r.path("/revocations"), r.certs(5), ""), http.StatusOK, "") // the day's one raise, which no certificate spent
	e.want(e.do("PUT", r.path("/revocations"), r.certs(7), ""), http.StatusTooManyRequests, protocol.CodeCertificateRevocationsSpent)
	e.want(e.do("PUT", r.path("/prekey"), r.upload(6), r.pass(6)), http.StatusOK, "") // replaces certificate 5, which is revoked
	r.prekey(8, until, nil)
	e.want(e.do("PUT", r.path("/prekey"), r.upload(8), r.pass(8)), http.StatusTooManyRequests, protocol.CodeCertificatesSpent) // 6 is not revoked
	rev, err := protocol.SignRevocation(r.signer, r.id.Address())
	if err != nil {
		t.Fatal(err)
	}
	e.want(e.do("PUT", r.path("/revocations"), protocol.Revocations{Identity: r.id.Document(), Revocation: rev}, ""), http.StatusCreated, "")
}

// A taker who holds a box's working key can spend the box's calls with its
// pass, and so hold back a renewal (this repo's #35). It cannot hold back the
// identity's raise of the revocation of certificates, which carries no pass
// and spends a count no renewal spends. Once that is taken, the taken pass is
// refused, the box's calls come back, and the renewal that replaces the
// revoked certificate is taken, with the identity's certificates for the day
// spent.
func TestATakerCannotHoldTheRemedyBack(t *testing.T) {
	l := relaxed()
	l.CallBurst, l.CallRefill = DefaultLimits().CallBurst, DefaultLimits().CallRefill
	l.CertificatesPerDay, l.CertificateRevocationsPerDay = 1, 1
	e := newEnv(t, l)
	now := e.clock.Now()
	e.clock.Add(now.Truncate(24 * time.Hour).Add(25 * time.Hour).Sub(now)) // 01:00 UTC, far from a day's end
	r, other := e.raw().register(protocol.MaxPrekeyLifetime), e.raw().register(protocol.MaxPrekeyLifetime)
	until := e.clock.Now().Add(protocol.PrekeyLifetime)
	r.prekey(1000, until, nil)
	e.want(e.do("PUT", r.path("/prekey"), r.upload(1000), r.pass(1000)), http.StatusOK, "") // the day's one certificate
	taken := r.pass(1000)
	for e.do("GET", other.path(""), nil, taken).status == http.StatusOK {
	}
	r.prekey(2000, until, nil)
	e.want(e.do("PUT", r.path("/prekey"), r.upload(2000), r.pass(2000)), http.StatusTooManyRequests, protocol.CodeRateLimited) // held back by the taker
	e.want(e.do("PUT", r.path("/revocations"), r.certs(1000), ""), http.StatusOK, "")
	e.want(e.do("GET", other.path(""), nil, taken), http.StatusUnauthorized, protocol.CodeCertificateRevoked)
	e.clock.Add(l.CallRefill)
	e.want(e.do("PUT", r.path("/prekey"), r.upload(2000), r.pass(2000)), http.StatusOK, "")
}

// A pass that fails costs signature checks that nothing paid for, so it is
// counted against its caller's address (Limits.MissesPerMinute), reserved
// before the check: past the count a new pass is refused before it is
// checked. A pass the process remembers is answered from memory whatever
// the count.
func TestFailedPassesAreCountedPerCaller(t *testing.T) {
	l := relaxed()
	l.MissesPerMinute = 2
	e := newEnv(t, l)
	b := e.box(protocol.Classic)
	list := "/v1/" + b.Address().String() + "/messages"
	good := e.pass(b)
	e.want(e.do(http.MethodGet, list, nil, good), http.StatusOK, "")
	wrongServer := e.passFor(worker(t, b), b.Address(), "elsewhere.example")
	for range 2 {
		e.want(e.do(http.MethodGet, list, nil, wrongServer), http.StatusUnauthorized, protocol.CodeUnauthorized)
	}
	e.want(e.do(http.MethodGet, list, nil, wrongServer), http.StatusTooManyRequests, protocol.CodeRateLimited)
	e.want(e.do(http.MethodGet, list, nil, good), http.StatusOK, "")
	e.clock.Add(31 * time.Second)
	e.want(e.do(http.MethodGet, list, nil, e.pass(b)), http.StatusOK, "")
}

// A reservation that would be refused only because others of its key are in
// flight waits for one to settle: given back, it is taken; kept, it is
// refused.
func TestAReservationWaitsForOthersInFlight(t *testing.T) {
	now := time.Now()
	clock := func() time.Time { return now }
	bs := newBuckets(1, time.Hour)
	first, ok, _ := bs.reserve(context.Background(), "k", clock)
	if !ok {
		t.Fatal("the first reservation was refused")
	}
	done := make(chan bool)
	go func() {
		_, ok, _ := bs.reserve(context.Background(), "k", clock)
		done <- ok
	}()
	time.Sleep(20 * time.Millisecond)
	first.release(now)
	if !<-done {
		t.Fatal("a reservation waiting on one given back was refused")
	}
	go func() {
		_, ok, _ := bs.reserve(context.Background(), "k", clock)
		done <- ok
	}()
	if <-done {
		t.Fatal("a reservation with no token and none in flight was taken")
	}
}

// slowPut holds each message write, as a store's two writes do, so sends in
// flight at once meet the counts together.
type slowPut struct {
	Store
	d time.Duration
}

func (s slowPut) PutMessage(ctx context.Context, box protocol.Address, h *Header, body []byte) (*Header, error) {
	time.Sleep(s.d)
	return s.Store.PutMessage(ctx, box, h, body)
}

// concurrently posts n sends at once from each of froms to to, through a
// server whose message writes each take a while, and returns how many were
// stored.
func concurrently(t *testing.T, e *env, l Limits, to *raw, froms []*raw, n int) int {
	t.Helper()
	srv := httptest.NewServer(apitest.Handler(t, New(Config{Store: slowPut{e.store, 50 * time.Millisecond}, Keys: e.keys, Limits: l, Now: e.clock.Now}).Handler()))
	t.Cleanup(srv.Close)
	e2 := &env{t: t, clock: e.clock, srv: srv}
	type post struct {
		body []byte
		pass string
	}
	var posts []post
	for _, from := range froms {
		pass := e2.passFor(from.work[1], from.id.Address(), e2.name())
		for range n {
			var ct bytes.Buffer
			w, _ := age.Encrypt(&ct, to.keys[1].Recipient())
			_, _ = io.WriteString(w, `{"v":1}`)
			_ = w.Close()
			posts = append(posts, post{ct.Bytes(), pass})
		}
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	stored := 0
	for _, p := range posts {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req, _ := http.NewRequest(http.MethodPost, srv.URL+to.path("/messages?")+sealedTo(1, 1, nil).Encode(), bytes.NewReader(p.body))
			req.Header.Set("Authorization", p.pass)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				return
			}
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusCreated {
				mu.Lock()
				stored++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	return stored
}

// A sender's daily count is taken before the write: sends in flight at once
// cannot all pass on one count (IronGall-dev/irongall-server#4).
func TestDailySendsAreTakenBeforeTheWrite(t *testing.T) {
	l := relaxed()
	l.SendsPerDay, l.PairCap, l.BoxCap = 5, 0, 0
	e := newEnv(t, l)
	from, to := e.raw().register(protocol.MaxPrekeyLifetime), e.raw().register(protocol.MaxPrekeyLifetime)
	if stored := concurrently(t, e, l, to, []*raw{from}, 20); stored != 5 {
		t.Fatalf("%d of 20 concurrent sends stored, with 5 a day", stored)
	}
}

// The pair and box caps count the sends in flight too, so sends made at once
// cannot all pass on the same counts (IronGall-dev/irongall-server#4).
func TestTheCapsCountSendsInFlight(t *testing.T) {
	l := relaxed()
	l.PairCap, l.BoxCap = 3, 0
	e := newEnv(t, l)
	from, to := e.raw().register(protocol.MaxPrekeyLifetime), e.raw().register(protocol.MaxPrekeyLifetime)
	if stored := concurrently(t, e, l, to, []*raw{from}, 20); stored != 3 {
		t.Fatalf("%d of 20 concurrent sends from one sender stored, with a pair cap of 3", stored)
	}
	l.PairCap, l.BoxCap = 0, 7
	e = newEnv(t, l)
	to = e.raw().register(protocol.MaxPrekeyLifetime)
	froms := []*raw{e.raw().register(protocol.MaxPrekeyLifetime), e.raw().register(protocol.MaxPrekeyLifetime), e.raw().register(protocol.MaxPrekeyLifetime)}
	if stored := concurrently(t, e, l, to, froms, 5); stored != 7 {
		t.Fatalf("%d of 15 concurrent sends stored, with a box cap of 7", stored)
	}
}

// slowBox counts reads of box records, and holds each a while, as a read of
// the table does.
type slowBox struct {
	Store
	reads *atomic.Int64
}

func (s slowBox) Box(ctx context.Context, a protocol.Address) (*Box, error) {
	s.reads.Add(1)
	time.Sleep(50 * time.Millisecond)
	return s.Store.Box(ctx, a)
}

// Lookups of one cold address at once share one read, and only its caller
// is counted for it (IronGall-dev/irongall-server#6): twenty lookups of a box
// that does not exist, from an address with one miss to spend, are each
// answered 404, from one read.
func TestLookupsOfOneAddressShareARead(t *testing.T) {
	l := relaxed()
	l.MissesPerMinute = 1
	e := newEnv(t, l)
	var n atomic.Int64
	srv := httptest.NewServer(apitest.Handler(t, New(Config{Store: slowBox{e.store, &n}, Keys: e.keys, Limits: l, Now: e.clock.Now}).Handler()))
	t.Cleanup(srv.Close)
	var nobody protocol.Address
	nobody[0] = 9
	var wg sync.WaitGroup
	codes := make([]int, 20)
	for i := range codes {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := http.Get(srv.URL + "/v1/" + nobody.String())
			if err != nil {
				return
			}
			_ = resp.Body.Close()
			codes[i] = resp.StatusCode
		}()
	}
	wg.Wait()
	for i, c := range codes {
		if c != http.StatusNotFound {
			t.Fatalf("lookup %d: %d, want 404 (all: %v)", i, c, codes)
		}
	}
	if got := n.Load(); got != 1 {
		t.Fatalf("%d reads for twenty lookups of one address at once", got)
	}
}

// A box takes mail out at a rate of its own (Limits.DrainBurst): its first
// fetch of each held message spends the budget, which only its own calls
// spend. Past it a fetch is rate_limited and the rest waits on the server;
// a fetch that is not a first one gives its token back; an account can lift
// it.
func TestTheDrainBudget(t *testing.T) {
	l := relaxed()
	e := newEnv(t, l)
	a, b := e.box(protocol.Classic), e.box(protocol.Classic)
	for _, body := range []string{"1", "2", "3"} {
		send(t, a, b, body)
	}
	l.DrainBurst, l.DrainRefill = 2, time.Minute
	e2, _ := counted(t, e, l)
	pass := e2.pass(b)
	ids := listOf(t, e2.do(http.MethodGet, "/v1/"+b.Address().String()+"/messages", nil, pass)).Messages
	if len(ids) != 3 {
		t.Fatalf("listed %d", len(ids))
	}
	fetch := func(id string) reply {
		return e2.do(http.MethodGet, "/v1/"+b.Address().String()+"/messages/"+id, nil, pass)
	}
	unknown := strings.Repeat("cd", 32)
	e2.want(fetch(unknown), http.StatusNotFound, protocol.CodeNoSuchMessage) // given back: not new mail
	e2.want(fetch(ids[0].ID), http.StatusOK, "")
	e2.want(fetch(ids[0].ID), http.StatusOK, "") // a repeat: given back, and its own allowance spent
	e2.want(fetch(ids[1].ID), http.StatusOK, "")
	r := fetch(ids[2].ID)
	e2.want(r, http.StatusTooManyRequests, protocol.CodeFetchPaced)
	if r.header.Get("Retry-After") == "" || !strings.Contains(string(r.body), "waits on the server") {
		t.Fatalf("the third first fetch: %s", r.body)
	}
	e.clock.Add(l.DrainRefill)
	e2.want(fetch(ids[2].ID), http.StatusOK, "")

	// An unmetered account's box drains with no budget.
	_, key := accountEnv(t, e, true, 1)
	echo := e.box(protocol.Classic)
	adopt(t, echo, key)
	for range 3 {
		send(t, a, echo, "to the unmetered box")
	}
	epass := e2.pass(echo)
	for _, m := range listOf(t, e2.do(http.MethodGet, "/v1/"+echo.Address().String()+"/messages", nil, epass)).Messages {
		e2.want(e2.do(http.MethodGet, "/v1/"+echo.Address().String()+"/messages/"+m.ID, nil, epass), http.StatusOK, "")
	}
}

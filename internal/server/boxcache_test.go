package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/IronGall-dev/irongall-client/protocol"
	stypes "github.com/aws/aws-sdk-go-v2/service/dynamodbstreams/types"
)

// A copy read before a write is kept out of the record cache where the cache
// did not hold its address: the stream's image of that write was dropped
// there, so the copy may be older than the table
// (IronGall-dev/irongall-server#12). A copy of an address the cache holds
// merges, as a put does.
func TestAFillAfterAWriteItDidNotSeeIsNotKept(t *testing.T) {
	var a protocol.Address
	a[0] = 1
	stale := func() bool { return false }
	c := newBoxCache(10)
	c.refresh(a, 3, func() (*Box, error) { return &Box{Addr: a, Rev: 3}, nil }) // rev 3's image, dropped: a is not held
	c.fill(&Box{Addr: a, Rev: 2}, stale)
	if b, ok := c.get(a); ok {
		t.Fatalf("a copy at rev %d, read before a write it did not see, was kept", b.Rev)
	}
	c.fill(&Box{Addr: a, Rev: 2}, func() bool { return true })
	if b, ok := c.get(a); !ok || b.Rev != 2 {
		t.Fatal("a copy read with no write since was not kept")
	}
	c.put(&Box{Addr: a, Rev: 3})
	c.fill(&Box{Addr: a, Rev: 2}, stale)
	if b, ok := c.get(a); !ok || b.Rev != 3 {
		t.Fatalf("a copy of an address held: %v, %v; want rev 3 held", b, ok)
	}
}

// A registration that raced a revocation of its address leaves no copy
// without the revocation in the record cache (IronGall-dev/irongall-server#41):
// the revocation's image came while the cache did not hold the address, and
// the registration's view is put after it. A registration with no write to
// its address meanwhile is cached, so the box's first call reads nothing.
func TestARegistrationThatRacedARevocationIsNotCachedWithoutIt(t *testing.T) {
	e := newEnv(t, relaxed())
	s := NewDynamoStore(DynamoConfig{BoxCache: 10}) // never started: memory alone
	now := time.Now()
	register := func(r *raw, during func()) {
		a := r.id.Address()
		if missing, seq := s.misses.has(a, now); !missing {
			s.misses.missed(a, seq, now) // the registration's read finds nothing
		}
		during()
		s.applyBox(&Box{Addr: a, Identity: r.id.Document(), State: Active, Rev: 1})
	}
	raced, alone := e.raw(), e.raw()
	register(raced, func() {
		s.applyRevocations(raced.id.Address(), &Revocations{Identity: raced.id.Document(), Address: []byte("the identity's revocation")})
	})
	if b, ok := s.Known(raced.id.Address()); ok && b != nil && b.State != Revoked {
		t.Errorf("after a registration that raced a revocation, memory holds the box %s, without the revocation", b.State)
	}
	register(alone, func() {})
	if b, ok := s.Known(alone.id.Address()); !ok || b == nil || b.State != Active {
		t.Errorf("a registration with no write meanwhile is not cached: %v, %v", b, ok)
	}
}

// Two copies of an address merge to every revocation either holds, whichever
// is the newer record and whether or not a stored revocation of certificates
// parses (IronGall-dev/irongall-server#64): one that does not parse stands in
// place of one that does, so that its next use fails closed.
func TestMergedCopiesKeepEveryRevocation(t *testing.T) {
	e := newEnv(t, relaxed())
	r := e.raw()
	a, doc := r.id.Address(), r.id.Document()
	revocation := []byte("the identity's revocation")
	bad := []byte("not a revocation of certificates\n")
	low, high := r.certs(1), r.certs(5)
	revoked := &Box{Addr: a, Identity: doc, State: Revoked, Rev: 1, Revocation: revocation}
	badList := &Box{Addr: a, Identity: doc, State: Active, Rev: 2, RevokedCerts: bad, RevokedCertsSig: []byte("x")}
	at := func(rev uint64, c protocol.Revocations) *Box {
		return &Box{Addr: a, Identity: doc, State: Active, Rev: rev, RevokedCerts: c.RevokedCertificates, RevokedCertsSig: c.RevokedCertificatesSignature}
	}
	revokedBad := &Box{Addr: a, Identity: doc, State: Revoked, Rev: 1, Revocation: revocation, RevokedCerts: bad, RevokedCertsSig: []byte("x")}
	for _, c := range []struct {
		name     string
		old, cur *Box
		revoked  bool
		certs    []byte
	}{
		{"the newer copy's list does not parse", revoked, badList, true, bad},
		{"the older copy's list does not parse", revokedBad, at(2, low), true, bad},
		{"the older copy's list reaches higher", at(1, high), at(2, low), false, high.RevokedCertificates},
		{"the newer copy's list reaches higher", at(1, low), at(2, high), false, high.RevokedCertificates},
		{"the older copy holds the revocation", revoked, at(2, low), true, low.RevokedCertificates},
	} {
		for _, order := range []string{"older cached", "newer cached"} {
			old, cur := c.old, c.cur
			if order == "newer cached" {
				old, cur = cur, old
			}
			m := mergeViews(old, cur)
			if got := m.State == Revoked && len(m.Revocation) > 0; got != c.revoked {
				t.Errorf("%s, %s: revoked %v, want %v", c.name, order, got, c.revoked)
			}
			if string(m.RevokedCerts) != string(c.certs) {
				t.Errorf("%s, %s: the revocation of certificates kept is not the one that stands", c.name, order)
			}
			if m.Rev != 2 {
				t.Errorf("%s, %s: the record of rev %d, want the newer", c.name, order, m.Rev)
			}
		}
	}
	cache := newBoxCache(10)
	cache.put(revoked)
	cache.put(badList)
	if b, _ := cache.get(a); b.State != Revoked {
		t.Errorf("the cache, given the issue's two copies, holds the box %s", b.State)
	}
}

// On DynamoDB: an image this process applies while a read of the address is
// in flight is not lost to that read's fill, neither a read of what is held
// of the address (Box) nor a box's load (IronGall-dev/irongall-server#12).
func TestAnImageDuringAReadKeepsItsFillOut(t *testing.T) {
	e, s := dynamoEnv(t)
	ctx := context.Background()
	r := e.raw().register(protocol.MaxPrekeyLifetime)
	a := r.id.Address()
	certs := r.certs(1)
	image := func(p string) error {
		if p == "address: after the read" {
			s.applyRevocations(a, &Revocations{Identity: r.id.Document(), Certs: certs.RevokedCertificates, CertsSig: certs.RevokedCertificatesSignature, Through: 1})
		}
		return nil
	}
	for _, c := range []struct {
		name string
		read func() error
	}{
		{"a read of the address", func() error { _, err := s.Box(ctx, a); return err }},
		{"the box's load", func() error { s.idx.forget(a); _, err := s.Count(ctx, a); return err }},
	} {
		s.cache.evict(a)
		s.fault = image
		err := c.read()
		s.fault = nil
		if err != nil {
			t.Fatal(err)
		}
		if b, ok := s.cache.get(a); ok && len(b.RevokedCerts) == 0 {
			t.Errorf("%s: the cache keeps a copy from before an image applied during the read", c.name)
		}
	}
	// A read with no write during it is kept. The stream's echo of the
	// box's own registration, or of another test's write to its shard, can
	// land during one and rightly keep it out, so a few are allowed.
	kept := false
	for range 20 {
		s.cache.evict(a)
		if _, err := s.Box(ctx, a); err != nil {
			t.Fatal(err)
		}
		if _, kept = s.cache.get(a); kept {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !kept {
		t.Error("no read of the address in two seconds is kept")
	}
}

// On DynamoDB: an account's read during which this process saw a change to
// an account keeps its copy out of the account cache, as a box's does.
func TestAnAccountChangeDuringItsReadKeepsTheFillOut(t *testing.T) {
	e, s := dynamoEnv(t)
	ctx := context.Background()
	acc, _ := accountEnv(t, e, false, 1)
	s.accCache.evict(acc.ID)
	s.fault = func(p string) error {
		if p == "account: after the read" {
			s.accWrites.Add(1) // the stream brought a change meanwhile
		}
		return nil
	}
	_, err := s.Account(ctx, acc.ID)
	s.fault = nil
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := s.accCache.get(acc.ID); ok {
		t.Error("the account cache keeps a copy read before a change seen during the read")
	}
	// One with no change during it is kept. The stream brings every
	// account's changes, other tests' among them, and one landing during a
	// read rightly keeps it out, so a few are allowed.
	kept := false
	for range 20 {
		s.accCache.evict(acc.ID)
		if _, err := s.Account(ctx, acc.ID); err != nil {
			t.Fatal(err)
		}
		if _, kept = s.accCache.get(acc.ID); kept {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !kept {
		t.Error("no read of the account in two seconds is kept")
	}
}

// orders calls f with every interleaving of a steps of one actor and b of
// another, as a list of 0s and 1s.
func orders(a, b int, f func(order []int)) {
	var rec func(order []int, i, j int)
	rec = func(order []int, i, j int) {
		if i == a && j == b {
			f(append([]int(nil), order...))
			return
		}
		if i < a {
			rec(append(order, 0), i+1, j)
		}
		if j < b {
			rec(append(order, 1), i, j+1)
		}
	}
	rec(nil, 0, 0)
}

// fillSteps is recCache.fill as it runs: the put under the cache's lock,
// then fresh, then the evict of a copy fresh refuses, each a step, since
// another can come between them.
func fillSteps[K comparable, V any](c *recCache[K, V], v V, fresh func() bool) []func() {
	var held, ok bool
	return []func(){
		func() { c.mu.Lock(); held = c.putLocked(v); c.mu.Unlock() },
		func() { ok = held || fresh() },
		func() {
			if !ok {
				c.evict(c.key(v))
			}
		},
	}
}

// What memory answers of an address with no read never goes back to before
// a write this process has applied, in any order of a fill and the write
// (IronGall-dev/irongall-server#12, #41, #95, #96), nor what it holds of an
// account. Each actor is the code's own calls, a step for each stretch that
// another can come between, and each order of the two actors' steps runs on
// a store of its own, never started: memory alone. Once the write is
// applied, after every step and at the end, memory answers the write or
// nothing: an answer without it at the end is a copy kept, and one after a
// step is a copy shown, which every reader of the cache is given.
func TestEveryOrderOfAFillAndAWrite(t *testing.T) {
	e := newEnv(t, relaxed())
	r := e.raw().register(protocol.MaxPrekeyLifetime)
	a := r.id.Address()
	older, err := e.store.Box(t.Context(), a) // the record a read began before the write finds
	if err != nil {
		t.Fatal(err)
	}
	if older.Rev != 1 {
		t.Fatalf("control: the record is at rev %d", older.Rev)
	}
	newer := cloneBox(older) // the record the write makes
	newer.Rev = 2
	revocation := &Revocations{Identity: older.Identity, Address: []byte("the identity's revocation")}
	const id = "an account"
	account := func(op stypes.OperationType, rev uint64) stypes.Record {
		it := map[string]stypes.AttributeValue{
			"account": &stypes.AttributeValueMemberB{Value: []byte(id)}, "sk": &stypes.AttributeValueMemberB{Value: []byte{skAccount}},
			"unmetered": &stypes.AttributeValueMemberBOOL{Value: true}, "rev": &stypes.AttributeValueMemberN{Value: strconv.FormatUint(rev, 10)},
		}
		return stypes.Record{EventName: op, Dynamodb: &stypes.StreamRecord{Keys: it, NewImage: it}}
	}

	// A read of the address begun before the write, whose copy is v, fills
	// the cache once it has read (DynamoStore.Box, readBox).
	read := func(s *DynamoStore, v *Box) []func() {
		seq := s.misses.seqOf(a)
		return fillSteps(s.cache, v, func() bool { return s.misses.seqOf(a) == seq })
	}
	// applyBox, this process's write of a record whose view, b, it read
	// before the write: its fill, then its record of the write.
	applyBox := func(s *DynamoStore, b *Box) []func() {
		return append(fillSteps(s.cache, b, func() bool { return s.misses.remembered(a) }), func() { s.misses.wrote(a) })
	}
	revoke := func(s *DynamoStore) func() { return func() { s.applyRevocations(a, revocation) } }
	// What memory answers of the address with no read, as a lookup and a
	// send's check of its recipient ask it.
	known := func(s *DynamoStore) (*Box, bool) { return s.Known(a) }
	withoutTheRevocation := func(s *DynamoStore) bool { b, ok := known(s); return ok && (b == nil || b.State != Revoked) }
	withoutTheRecord := func(s *DynamoStore) bool { b, ok := known(s); return ok && (b == nil || b.Rev < 2) }

	type actors struct {
		fill, write []func()
		applied     int // the write is applied once this many of its steps have run
	}
	for _, c := range []struct {
		name  string
		mk    func(s *DynamoStore) actors
		stale func(s *DynamoStore) bool // memory answers without the write
	}{
		{"a read's fill and applyBox of this process's write", func(s *DynamoStore) actors {
			w := applyBox(s, newer)
			return actors{read(s, older), w, len(w)}
		}, withoutTheRecord},
		{"a read's fill and a revocation of the address", func(s *DynamoStore) actors {
			return actors{read(s, older), []func(){revoke(s)}, 1}
		}, withoutTheRevocation},
		{"a read's fill and a revocation with its purge", func(s *DynamoStore) actors {
			return actors{read(s, older), []func(){revoke(s), func() { s.forget(a) }}, 1}
		}, withoutTheRevocation},
		{"a read's fill and the record's removal", func(s *DynamoStore) actors {
			return actors{read(s, older), []func(){func() { s.forget(a) }}, 1}
		}, func(s *DynamoStore) bool { b, ok := known(s); return ok && b != nil && b.hasRecord() }},
		{"a read's fill and the stream's image of a newer record", func(s *DynamoStore) actors {
			return actors{read(s, older), []func(){func() { s.applyBoxImage(item(boxItem(newer))) }}, 1}
		}, withoutTheRecord},
		{"a read that found nothing and a revocation of the address", func(s *DynamoStore) actors {
			_, seq := s.misses.has(a, s.now())
			return actors{[]func(){func() { s.misses.missed(a, seq, s.now()) }}, []func(){revoke(s)}, 1}
		}, func(s *DynamoStore) bool { b, ok := known(s); return ok && b == nil }},
		{"a registration's applyBox and a revocation of the address", func(s *DynamoStore) actors {
			_, seq := s.misses.has(a, s.now()) // the registration's read finds nothing
			s.misses.missed(a, seq, s.now())
			return actors{applyBox(s, older), []func(){revoke(s)}, 1}
		}, withoutTheRevocation},
		{"applyBox of a write whose view predates a revocation the cache did not hold", func(s *DynamoStore) actors {
			return actors{applyBox(s, newer), []func(){revoke(s)}, 1}
		}, withoutTheRevocation},
		{"an account's read and the stream's change to it", func(s *DynamoStore) actors {
			seq := s.accWrites.Load()
			return actors{fillSteps(s.accCache, &Account{ID: id, Rev: 1}, func() bool { return s.accWrites.Load() == seq }),
				[]func(){func() { s.applyAccountRecord(account(stypes.OperationTypeModify, 2)) }}, 1}
		}, func(s *DynamoStore) bool { got, ok := s.accCache.get(id); return ok && got.Rev < 2 }},
		{"an account's read and its removal", func(s *DynamoStore) actors {
			seq := s.accWrites.Load()
			return actors{fillSteps(s.accCache, &Account{ID: id, Rev: 1}, func() bool { return s.accWrites.Load() == seq }),
				[]func(){func() { s.applyAccountRecord(account(stypes.OperationTypeRemove, 1)) }}, 1}
		}, func(s *DynamoStore) bool { _, ok := s.accCache.get(id); return ok }},
	} {
		t.Run(c.name, func(t *testing.T) {
			first := c.mk(NewDynamoStore(DynamoConfig{BoxCache: 10}))
			n, kept, shown := 0, 0, 0
			orders(len(first.fill), len(first.write), func(order []int) {
				n++
				s := NewDynamoStore(DynamoConfig{BoxCache: 10})
				x := c.mk(s)
				i, j, window := 0, 0, false
				for _, who := range order {
					if who == 0 {
						x.fill[i]()
						i++
					} else {
						x.write[j]()
						j++
					}
					if j >= x.applied && c.stale(s) {
						window = true
					}
				}
				switch {
				case c.stale(s):
					kept++
					t.Logf("order %v (0 the fill's steps, 1 the write's) keeps a copy without the write", order)
				case window:
					shown++
					t.Logf("order %v (0 the fill's steps, 1 the write's) shows a copy without the write once it is applied", order)
				}
			})
			t.Logf("%d orders: %d keep a copy without the write, %d more show one for a while", n, kept, shown)
			if kept+shown > 0 {
				t.Errorf("memory answers without a write this process applied: kept in %d of %d orders, shown in %d", kept, n, shown)
			}
		})
	}
}

// heldRead is memory's DynamoStore over a table of one address, held in the
// test: each read of the address answers what the table holds as the read
// begins, as a strongly consistent read does, and the first read is held
// until released.
type heldRead struct {
	*DynamoStore
	mu      sync.Mutex
	table   *Box
	reads   int
	release chan struct{}
}

func (s *heldRead) set(b *Box) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.table = b
}

func (s *heldRead) Box(context.Context, protocol.Address) (*Box, error) {
	s.mu.Lock()
	b := s.table
	s.reads++
	first := s.reads == 1
	s.mu.Unlock()
	if first {
		<-s.release
	}
	if b == nil {
		return nil, ErrNotFound
	}
	return cloneBox(b), nil
}

// A lookup that comes once this process has applied a revocation of the
// address and purged its record, and finds a read of the address in flight
// that began before them, is not answered from that read: it reads again
// (the fifth case of IronGall-dev/irongall-server#95's class). Control: one
// that comes before them shares the read, which costs one read, and is
// answered what it found. The lookups run in a synctest bubble, so the test
// knows each is waiting on the shared read before it lets the read go.
func TestALookupJoinedToAReadBegunBeforeARevocationReadsAgain(t *testing.T) {
	e := newEnv(t, relaxed())
	r := e.raw().register(protocol.MaxPrekeyLifetime)
	a := r.id.Address()
	rec, err := e.store.Box(t.Context(), a)
	if err != nil {
		t.Fatal(err)
	}
	revocation := &Revocations{Identity: rec.Identity, Address: []byte("the identity's revocation")}
	for _, c := range []struct {
		name         string
		revokedFirst bool
		state        State
		reads        int
	}{
		{"a lookup after the revocation and its purge", true, Revoked, 2},
		{"control: a lookup before them", false, Active, 1},
	} {
		t.Run(c.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				s := &heldRead{DynamoStore: NewDynamoStore(DynamoConfig{BoxCache: 10}), table: rec, release: make(chan struct{})}
				srv := New(Config{Store: s, Limits: relaxed()})
				lookup := func() chan *Box {
					got := make(chan *Box, 1)
					go func() {
						b, err := srv.lookup(httptest.NewRequest(http.MethodGet, r.path(""), nil), a)
						if err != nil {
							t.Error(err)
						}
						got <- b
					}()
					return got
				}
				first := lookup()
				synctest.Wait() // its read has begun, and is held
				revoke := func() {
					s.set(view(a, nil, revocation))   // the table: the revocation kept, the record deleted
					s.applyRevocations(a, revocation) // as Revoke applies it
					s.forget(a)                       // as the purge's DeleteBox does
				}
				if c.revokedFirst {
					revoke()
				}
				second := lookup()
				synctest.Wait() // it waits on the read in flight
				if !c.revokedFirst {
					revoke()
				}
				close(s.release)
				if b := <-first; b == nil || b.State != Active {
					t.Errorf("the lookup whose read began before the revocation: %v", b)
				}
				b := <-second
				switch {
				case b == nil:
					t.Errorf("the second lookup found nothing; want the box %s", c.state)
				case b.State != c.state:
					t.Errorf("the second lookup was answered the box %s; want %s", b.State, c.state)
				}
				if s.reads != c.reads {
					t.Errorf("%d reads of the address; want %d", s.reads, c.reads)
				}
			})
		})
	}
}

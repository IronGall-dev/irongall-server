package server

import (
	"context"
	"testing"
	"time"

	"github.com/IronGall-dev/irongall-client/protocol"
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
	s.cache.evict(a)
	if _, err := s.Box(ctx, a); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.cache.get(a); !ok {
		t.Error("a read with no write during it is not kept")
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
	if _, err := s.Account(ctx, acc.ID); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.accCache.get(acc.ID); !ok {
		t.Error("an account read with no change during it is not kept")
	}
}

package server

// What a write AWS answered with an error is taken to have done: applied,
// or possibly so, and the count reserved for it is kept; or refused, as AWS
// or the store stated, and the count is given back (LIMITS.md rule 4;
// IronGall-dev/irongall-server#14, #89). awsfake_test.go has the fake.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/IronGall-dev/irongall-client/protocol"
)

const (
	codeISE  = "InternalServerError"
	codeCCF  = "ConditionalCheckFailedException"
	codePTEE = "ProvisionedThroughputExceededException"
)

var (
	answer500  = answer{status: http.StatusInternalServerError, body: dynErr(codeISE, "")}
	answerCCF  = answer{status: http.StatusBadRequest, body: dynErr(codeCCF, "")}
	answerPTEE = answer{status: http.StatusBadRequest, body: dynErr(codePTEE, "")}
)

// scripted answers the n-th call of op with answers[n-1], and every other
// call, and each past the script, with a fault of AWS's own.
func scripted(op string, answers ...answer) func(string, int, []byte) answer {
	return func(o string, n int, _ []byte) answer {
		if o != op || n > len(answers) {
			return answer500
		}
		return answers[n-1]
	}
}

// applied is a, with the call's write applied.
func applied(a answer) answer { a.apply = true; return a }

// A write the SDK retried after an attempt whose answer leaves open whether
// it was applied (a fault of AWS's own, a lost answer) may have been applied
// whatever its last attempt answered, a failed condition or a throttle among
// them (IronGall-dev/irongall-server#89): the fake applies the first
// UpdateItem and answers it with a 500, or drops its answer, and the retry is
// answered as DynamoDB answers a retry of an applied conditional write, or
// throttled. The controls: every attempt a fault; a failed condition or
// throttles alone, nothing applied.
func TestAWriteRetriedAfterAnAmbiguousAttemptMayHaveBeenApplied(t *testing.T) {
	_, _, box := heldRecord(t)
	cases := []struct {
		name    string
		answers []answer // the n-th UpdateItem's
		want    bool     // mayHaveApplied
	}{
		{"applied and answered 500, then the retry's failed condition", []answer{applied(answer500), answerCCF}, true},
		{"applied and its answer lost, then the retry's failed condition", []answer{applied(answer{drop: true}), answerCCF}, true},
		{"applied and answered 500, then throttled twice", []answer{applied(answer500), answerPTEE, answerPTEE}, true},
		{"control: applied and answered 500 three times", []answer{applied(answer500), answer500, answer500}, true},
		{"control: a failed condition, nothing applied", []answer{answerCCF}, false},
		{"control: throttled three times, nothing applied", []answer{answerPTEE, answerPTEE, answerPTEE}, false},
	}
	fakes, errs := make([]*fakeAWS, len(cases)), make([]error, len(cases))
	var wg sync.WaitGroup // every write at once, each on a fake of its own, then each judged
	for i, c := range cases {
		fakes[i] = newFakeAWS()
		fakes[i].dynamo = scripted("UpdateItem", c.answers...)
		s := fakeStore(t, fakes[i])
		wg.Go(func() { errs[i] = s.UpdateBox(context.WithoutCancel(t.Context()), cloneBox(box)) })
	}
	wg.Wait()
	for i, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := errs[i]
			calls, applied := fakes[i].count("UpdateItem")
			got := mayHaveApplied(err)
			t.Logf("%d UpdateItem calls, %d applied; err %v (ErrStale %v, %s, throttle %v); mayHaveApplied %v",
				calls, applied, err, errors.Is(err, ErrStale), faultOf(err), IsThrottle(err), got)
			if got != c.want {
				t.Errorf("mayHaveApplied %v for a write the fake applied %d times: the count would be %s", got, applied, map[bool]string{true: "kept", false: "given back"}[got])
			}
		})
	}
}

// The same for a raise of a revocation of certificates (Revoke, with its
// condition on through): applied and answered 500, then the retry's failed
// condition, and the raise is counted.
func TestARaiseRetriedAfterAnAmbiguousAttemptMayHaveBeenApplied(t *testing.T) {
	_, r, _ := heldRecord(t)
	f := newFakeAWS()
	f.dynamo = scripted("UpdateItem", applied(answer500), answerCCF)
	s := fakeStore(t, f)
	err := s.Revoke(context.WithoutCancel(t.Context()), r.id.Address(), &Revocations{Identity: r.id.Document(), Certs: []byte("c"), CertsSig: []byte("s"), Through: 7})
	calls, applied := f.count("UpdateItem")
	t.Logf("%d UpdateItem calls, %d applied; err %v (ErrStale %v); mayHaveApplied %v", calls, applied, err, errors.Is(err, ErrStale), mayHaveApplied(err))
	if !mayHaveApplied(err) {
		t.Errorf("a raise the fake applied is taken for a refusal AWS stated: its count would be given back")
	}
}

// The SDK draws on its retry quota only after an attempt failed with an
// error it retries, a 500 among them, and once the quota is out it returns
// that attempt's error joined with the quota's, which reads as a throttle: a
// write the fake applied and answered 500 on a client whose quota is drained
// may have been applied all the same. The control is the same write on a
// fresh client: three attempts.
func TestADrainedRetryQuotaHidesNoAppliedWrite(t *testing.T) {
	_, _, box := heldRecord(t)
	for _, drained := range []bool{false, true} {
		t.Run(fmt.Sprintf("drained=%v", drained), func(t *testing.T) {
			f := newFakeAWS()
			var phase atomic.Int32 // 0 draining, 1 the write
			f.dynamo = func(string, int, []byte) answer {
				if phase.Load() == 0 {
					return answerPTEE
				}
				return applied(answer500)
			}
			s := fakeStore(t, f)
			ctx := context.WithoutCancel(t.Context())
			if drained {
				var wg sync.WaitGroup
				for range 60 {
					wg.Go(func() { _ = s.UpdateBox(ctx, cloneBox(box)) })
				}
				wg.Wait()
			}
			phase.Store(1)
			before, _ := f.count("UpdateItem")
			err := s.UpdateBox(ctx, cloneBox(box))
			after, _ := f.count("UpdateItem")
			got := mayHaveApplied(err)
			t.Logf("%d attempts of the write, the first applied; err %v; throttle %v; mayHaveApplied %v", after-before, err, IsThrottle(err), got)
			if !got {
				t.Errorf("a write the fake applied and answered 500 is taken for a refusal AWS stated (%v)", err)
			}
		})
	}
}

// putItemOfItsOwn answers the first PutItem as applied with first, and every
// later one with a failed condition that returns, as ALL_OLD, the item the
// first wrote: what DynamoDB answers a retry of a conditional put it applied.
func putItemOfItsOwn(first answer) func(string, int, []byte) answer {
	var mu sync.Mutex
	var item json.RawMessage
	return func(op string, n int, body []byte) answer {
		if op != "PutItem" {
			return answer{status: http.StatusBadRequest, body: dynErr("ValidationException", "")}
		}
		mu.Lock()
		defer mu.Unlock()
		if n == 1 {
			var in struct{ Item json.RawMessage }
			_ = json.Unmarshal(body, &in)
			item = in.Item
			return applied(first)
		}
		return answer{status: http.StatusBadRequest, body: dynErr(codeCCF, `,"Item":`+string(item))}
	}
}

// A send's PutItem applied and answered 500 meets, retried, its own item:
// the failed condition returns the item this write made (its sender, its
// time), so the message is stored, and memory has its mark
// (IronGall-dev/irongall-server#89). The control is the same write answered
// 200.
func TestAPutRetriedOntoItsOwnItemIsStored(t *testing.T) {
	_, from, _ := heldRecord(t)
	to := protocol.Address{1, 2, 3}
	for _, retried := range []bool{false, true} {
		t.Run(fmt.Sprintf("retried=%v", retried), func(t *testing.T) {
			f := newFakeAWS()
			f.dynamo = putItemOfItsOwn(answer500)
			if !retried {
				f.dynamo = scripted("PutItem", applied(answer{status: http.StatusOK, body: "{}"}))
			}
			s := fakeStore(t, f)
			if err := s.idx.ensure(t.Context(), to, func() (boxRead, error) { return boxRead{exists: true, st: Standing{State: Active}, rev: 1}, nil }); err != nil {
				t.Fatal(err)
			}
			now := s.now().UTC().Truncate(time.Millisecond)
			h := &Header{ID: [32]byte{9}, From: from.id.Address(), Size: 10, ReceivedAt: now, ExpiresAt: now.Add(protocol.Retention)}
			orig, err := s.PutMessage(context.WithoutCancel(t.Context()), to, h, []byte("0123456789"))
			calls, applied := f.count("PutItem")
			marks := s.idx.count(to, s.nowMs())
			t.Logf("%d PutItem calls, %d applied; orig %v; err %v; marks in memory %d", calls, applied, orig != nil, err, marks)
			if orig != nil || err != nil || marks != 1 {
				t.Errorf("a write the fake applied is answered as orig %v, err %v, with %d marks in memory; want stored, with its mark", orig != nil, err, marks)
			}
		})
	}
}

// A write to what is held of an address whose answer leaves open whether it
// was applied is counted by the record cache as a write is, and leaves
// nothing cached of the address: a read begun before it puts nothing after
// it, and the next read reads the table (recCache.write;
// IronGall-dev/irongall-server#89). The controls: a refusal AWS stated
// changes nothing cached; a failed condition with nothing applied evicts the
// copy and counts no write, as before.
func TestAWriteThatMayHaveBeenAppliedIsCountedByTheCache(t *testing.T) {
	_, r, box := heldRecord(t)
	notFound := answer{status: http.StatusBadRequest, body: dynErr("ResourceNotFoundException", "")}
	raise := func(ctx context.Context, s *DynamoStore) error {
		return s.Revoke(ctx, box.Addr, &Revocations{Identity: r.id.Document(), Certs: []byte("c"), CertsSig: []byte("s"), Through: 7})
	}
	update := func(ctx context.Context, s *DynamoStore) error { return s.UpdateBox(ctx, cloneBox(box)) }
	cases := []struct {
		name            string
		op              string
		answers         []answer
		write           func(context.Context, *DynamoStore) error
		evicted, counts bool
	}{
		{"UpdateBox answered 500 every attempt", "UpdateItem", []answer{applied(answer500), answer500, answer500}, update, true, true},
		{"UpdateBox applied, answered 500, then the retry's failed condition", "UpdateItem", []answer{applied(answer500), answerCCF}, update, true, true},
		{"UpdateBox's answer lost every attempt", "UpdateItem", []answer{applied(answer{drop: true}), {drop: true}, {drop: true}}, update, true, true},
		{"a raise answered 500 every attempt", "UpdateItem", []answer{applied(answer500), answer500, answer500}, raise, true, true},
		{"a raise applied, answered 500, then the retry's failed condition", "UpdateItem", []answer{applied(answer500), answerCCF}, raise, true, true},
		{"CreateBox answered 500 every attempt", "PutItem", []answer{applied(answer500), answer500, answer500},
			func(ctx context.Context, s *DynamoStore) error { return s.CreateBox(ctx, cloneBox(box)) }, true, true},
		{"DeleteBox answered 500 every attempt", "DeleteItem", []answer{applied(answer500), answer500, answer500},
			func(ctx context.Context, s *DynamoStore) error { return s.DeleteBox(ctx, box.Addr) }, true, true},
		{"Adopt answered 500 every attempt", "TransactWriteItems", []answer{applied(answer500), answer500, answer500},
			func(ctx context.Context, s *DynamoStore) error {
				return s.Adopt(ctx, cloneBox(box), "acct", [32]byte{1})
			}, true, true},
		{"Leave answered 500 every attempt", "UpdateItem", []answer{applied(answer500), answer500, answer500},
			func(ctx context.Context, s *DynamoStore) error { return s.Leave(ctx, cloneBox(box)) }, true, true},
		{"control: UpdateBox refused, a ResourceNotFoundException", "UpdateItem", []answer{notFound}, update, false, false},
		{"control: UpdateBox's failed condition, nothing applied", "UpdateItem", []answer{answerCCF}, update, true, false},
	}
	// Every write at once, each on a fake of its own, then each judged.
	type outcome struct {
		err          error
		held, filled bool
		cachedFirst  bool
	}
	outs := make([]outcome, len(cases))
	var wg sync.WaitGroup
	for i, c := range cases {
		f := newFakeAWS()
		f.dynamo = scripted(c.op, c.answers...)
		s := fakeStore(t, f)
		s.cache.fill(cloneBox(box), s.cache.begin(box.Addr))
		_, outs[i].cachedFirst = s.cache.get(box.Addr)
		wg.Go(func() {
			tok := s.cache.begin(box.Addr) // a read of the address begun before the write
			outs[i].err = c.write(context.WithoutCancel(t.Context()), s)
			_, outs[i].held = s.cache.get(box.Addr)
			s.cache.fill(cloneBox(box), tok) // that read's copy, from before the write
			_, outs[i].filled = s.cache.get(box.Addr)
		})
	}
	wg.Wait()
	for i, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err, held, filled := outs[i].err, outs[i].held, outs[i].filled
			if !outs[i].cachedFirst {
				t.Fatal("the cache does not hold the record put in it")
			}
			t.Logf("err %v (mayHaveApplied %v); after it the record is held %v; the read begun before it puts its copy %v", err, mayHaveApplied(err), held, filled)
			if err == nil {
				t.Fatal("the write did not fail")
			}
			if held == c.evicted {
				t.Errorf("after the write the cache holds the record read before it %v; want %v", held, !c.evicted)
			}
			if filled == c.counts && c.evicted {
				t.Errorf("a read begun before the write puts its copy after it %v; want %v: the write is counted %v", filled, !c.counts, !filled)
			}
		})
	}
}

// overFake makes the next write of the suite's store, then answers it as a
// DynamoStore answers the same write when AWS answers as the fake scripts
// it: its error, made by the SDK, so a handler meets the store's own
// statement of a write AWS applied and then answered with a fault. hook runs
// first.
type overFake struct {
	Store
	t      *testing.T
	armed  atomic.Bool
	hook   func()
	dynamo func(string, int, []byte) answer
}

func (s *overFake) fake() *DynamoStore {
	f := newFakeAWS()
	f.dynamo = s.dynamo
	return fakeStore(s.t, f)
}

func (s *overFake) UpdateBox(ctx context.Context, b *Box) error {
	if !s.armed.Swap(false) {
		return s.Store.UpdateBox(ctx, b)
	}
	read := cloneBox(b)
	if err := s.Store.UpdateBox(ctx, b); err != nil {
		return err
	}
	return s.fake().UpdateBox(ctx, read)
}

func (s *overFake) PutMessage(ctx context.Context, box protocol.Address, h *Header, body []byte) (*Header, error) {
	if !s.armed.Swap(false) {
		return s.Store.PutMessage(ctx, box, h, body)
	}
	if s.hook != nil {
		s.hook()
	}
	if orig, err := s.Store.PutMessage(ctx, box, h, body); err != nil || orig != nil {
		return orig, err
	}
	return s.fake().PutMessage(ctx, box, h, body)
}

// A renewal the store applied, whose first attempt AWS answered with a
// fault and whose retry met its own write's failed condition, is counted:
// with one renewal a day, the next is refused (IronGall-dev/irongall-server#89).
// The control: a renewal answered with a fault every attempt.
func TestARenewalTheStoreMayHaveAppliedIsCounted(t *testing.T) {
	for _, c := range []struct {
		name    string
		answers []answer
	}{
		{"applied and answered 500, then the retry's failed condition", []answer{applied(answer500), answerCCF}},
		{"control: applied and answered 500 every attempt", []answer{applied(answer500), answer500, answer500}},
	} {
		t.Run(c.name, func(t *testing.T) {
			l := relaxed()
			l.RenewalsPerDay = 1
			s := &overFake{t: t, dynamo: scripted("UpdateItem", c.answers...)}
			e := newEnv(t, l, func(cfg *Config) { s.Store, cfg.Store = cfg.Store, s })
			r := e.raw().register(protocol.MaxPrekeyLifetime)
			r.prekeyUnder(r.work[1], 2, e.clock.Now().Add(protocol.MaxPrekeyLifetime), nil)
			s.armed.Store(true)
			first := e.do("PUT", r.path("/prekey"), r.upload(2), r.pass(1))
			b, _ := e.store.Box(t.Context(), r.id.Address())
			again := e.do("PUT", r.path("/prekey"), r.upload(2), r.pass(1))
			r.prekeyUnder(r.work[1], 3, e.clock.Now().Add(protocol.MaxPrekeyLifetime), nil)
			next := e.do("PUT", r.path("/prekey"), r.upload(3), r.pass(1))
			t.Logf("renewal %d %s, the box at prekey %d; identical retry %d; next renewal %d %s", first.status, first.code(), b.Prekey.Serial, again.status, next.status, next.code())
			if next.status != http.StatusTooManyRequests {
				t.Errorf("a renewal the store applied was not counted: the next one is %d %s", next.status, next.code())
			}
		})
	}
}

// A send whose PutItem the store applied, whose first attempt AWS answered
// with a fault and whose retry met its own item, is stored: answered 201
// and counted, with one send a day; and where its recipient's address was
// revoked before the write, what it wrote is deleted and it is answered
// 410 (IronGall-dev/irongall-server#89, #15). The controls are the same
// sends whose write AWS answered 200.
func TestASendWhoseWriteWasRetriedIsStored(t *testing.T) {
	for _, retried := range []bool{false, true} {
		dynamo := func() func(string, int, []byte) answer {
			if retried {
				return putItemOfItsOwn(answer500)
			}
			return scripted("PutItem", applied(answer{status: http.StatusOK, body: "{}"}))
		}
		t.Run(fmt.Sprintf("counted/retried=%v", retried), func(t *testing.T) {
			l := relaxed()
			l.SendsPerDay = 1
			s := &overFake{t: t, dynamo: dynamo()}
			e := newEnv(t, l, func(cfg *Config) { s.Store, cfg.Store = cfg.Store, s })
			from, to := e.raw().register(protocol.MaxPrekeyLifetime), e.raw().register(protocol.MaxPrekeyLifetime)
			s.armed.Store(true)
			first := e.sendTo(to, 1, 1, from, 1)
			n, _ := e.store.Count(t.Context(), to.id.Address())
			next := e.sendTo(to, 1, 1, from, 1)
			t.Logf("send %d %s, the box holds %d; next send %d %s", first.status, first.code(), n, next.status, next.code())
			if first.status != http.StatusCreated || next.status != http.StatusTooManyRequests {
				t.Errorf("a stored send answered %d, and the next one %d: want 201, then 429", first.status, next.status)
			}
		})
		t.Run(fmt.Sprintf("revoked/retried=%v", retried), func(t *testing.T) {
			s := &overFake{t: t, dynamo: dynamo()}
			e := newEnv(t, relaxed(), func(cfg *Config) { s.Store, cfg.Store = cfg.Store, s })
			owner, from := e.raw().register(protocol.MaxPrekeyLifetime), e.raw().register(protocol.MaxPrekeyLifetime)
			sig, err := protocol.SignRevocation(owner.signer, owner.id.Address())
			if err != nil {
				t.Fatal(err)
			}
			s.hook = func() {
				e.want(e.do("PUT", owner.path("/revocations"), protocol.Revocations{Identity: owner.id.Document(), Revocation: sig}, ""), http.StatusCreated, "")
			}
			s.armed.Store(true)
			got := e.sendTo(owner, 1, 1, from, 1)
			n, _ := e.store.Count(t.Context(), owner.id.Address())
			t.Logf("a send that wrote after its recipient's revocation: %d %s; the revoked box holds %d", got.status, got.code(), n)
			if got.status != http.StatusGone || n != 0 {
				t.Errorf("a send that wrote after its recipient's revocation is answered %d and leaves %d messages; want 410 and none", got.status, n)
			}
		})
	}
}

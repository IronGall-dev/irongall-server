package server

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/IronGall-dev/irongall-client/protocol"
)

// Limits are the server's numbers. Decided ones are marked; the rest are
// tunables, and a zero turns that limit off.
type Limits struct {
	MaxSize        int           // the cap on the decoded ciphertext; nothing may depend on its value
	PairCap        int           // unacked per (sender → box) [tunable]
	BoxCap         int           // total per box, a storage ceiling [tunable]
	SendsPerDay    int           // per sender, per UTC day (decided: 20)
	PollBurst      int           // polls a box may make at once (decided: 10); also the fetches of messages already fetched
	PollRefill     time.Duration // one more poll each (decided: 50 s; once a minute is stated); also one more such fetch
	PollAfter      int           // seconds, told to clients (decided: 60)
	AccountMaxSize int           // the most an account lifts MaxSize to, so what a send reads first; up to MaxSize, nothing
	RenewalsPerDay int           // prekey renewals per box, per UTC day (decided: 10), so no box can spend the boxes table's write capacity
	RetiredKept    int           // retired prekeys a box record keeps for the new-key rule, newest first (decided: 10), so a record stays small

	RegistrationsPerHour int // per IPv4 address or IPv6 /64 [tunable]
	SendsPerMinutePerIP  int // the pre-auth send rate per IP [tunable]
	MissesPerMinute      int // per IP: reads of the boxes table that find no box, and checks that fail (decided: 10 for now)

	// Budgets: a burst at once and one more each refill (LIMITS.md).
	ReceiveBurst       int           // per box: new messages it takes, from all senders together (decided: 50); an account lifts it
	ReceiveRefill      time.Duration // (decided: 6 s, ten a minute)
	CallBurst          int           // per box: its calls with its pass that no other budget counts [tunable]; an account lifts it
	CallRefill         time.Duration // [tunable]
	PublicBurst        int           // per IP: calls with no pass [tunable]
	PublicRefill       time.Duration // [tunable]
	IdentityActsPerDay int           // per box, per UTC day: renewals under a later certificate and raises of the floor (decided: 10, as renewals)
}

// DefaultLimits are the decided numbers, and the proposed values of the
// tunables that have one. Tunables with no proposed value are off.
func DefaultLimits() Limits {
	return Limits{
		MaxSize:              64 << 10,
		PairCap:              10,
		BoxCap:               1000,
		SendsPerDay:          20,
		PollBurst:            10,
		PollRefill:           50 * time.Second,
		PollAfter:            60,
		RenewalsPerDay:       10,
		RetiredKept:          10,
		RegistrationsPerHour: 10,
		MissesPerMinute:      10,
		ReceiveBurst:         50,
		ReceiveRefill:        6 * time.Second,
		CallBurst:            50,
		CallRefill:           6 * time.Second,
		PublicBurst:          10,
		PublicRefill:         50 * time.Second,
		IdentityActsPerDay:   10,
	}
}

// ceiling is the largest ciphertext any sender may send.
func (l Limits) ceiling() int { return max(l.MaxSize, l.AccountMaxSize) }

// uncappedPages is how many list pages a box is taken to hold when no box
// cap bounds it.
const uncappedPages = 1000

// continuations is the allowance for list pages after the first, per box. A
// page after the first is not a poll (PROTOCOL.md §5.1), so it has its own:
// two full boxes' worth of pages at once, and a full box's worth back each
// poll interval. A drain is never refused, and a cursor is no way around the
// poll rate. With no poll limit there is none.
func (l Limits) continuations() *buckets {
	if l.PollBurst == 0 || l.PollRefill <= 0 {
		return newBuckets(0, 0)
	}
	pages := (l.BoxCap + pageSize - 1) / pageSize
	if l.BoxCap == 0 {
		pages = uncappedPages
	}
	return newBuckets(2*pages, l.PollRefill/time.Duration(pages))
}

// buckets is a set of token buckets by key: n tokens, one back each
// interval. A key's bucket starts full, on its first use and after a
// restart. Each is kept as the time it is full again (the GCRA form of a
// token bucket), in whole durations, so no rounding refuses a token that is
// due. A key whose bucket is full again is the same as no key, and is
// dropped (prune).
type buckets struct {
	mu    sync.Mutex
	n     int
	every time.Duration
	full  map[string]time.Time
	sweep time.Time // when prune next runs
	// held counts each key's reservations not yet kept or released, and
	// settled is closed and replaced each time one is (reserve).
	held    map[string]int
	settled chan struct{}
}

// newBuckets is buckets of n, refilled one every interval.
func newBuckets(n int, every time.Duration) *buckets {
	return &buckets{n: n, every: every, full: map[string]time.Time{}, held: map[string]int{}, settled: make(chan struct{})}
}

// reserveWait bounds how long a reservation waits for others of its key to
// settle. What they wait on is a table read or a signature check, which
// takes milliseconds.
const reserveWait = time.Second

// reservation is a token taken before work whose outcome says whether it
// counts: kept if it does, given back if not.
type reservation struct {
	bs   *buckets
	key  string
	done bool
}

// reserve takes a token for key before the work it guards. When none is
// left only because reservations of the same key are still in flight, it
// waits for one to settle, up to reserveWait or the end of ctx: so calls
// that would all be given back, made at once, are not refused for each
// other. It returns how long until a token is due when it refuses. A nil
// reservation with ok true is a bucket set that never limits.
func (bs *buckets) reserve(ctx context.Context, key string, now func() time.Time) (r *reservation, ok bool, wait time.Duration) {
	if bs.n == 0 || bs.every <= 0 {
		return nil, true, 0
	}
	var give *time.Timer // made only once there is something to wait for
	for {
		bs.mu.Lock()
		t := now()
		bs.prune(t)
		next, over := bs.next(key, t)
		if over <= 0 {
			bs.full[key] = next
			bs.held[key]++
			bs.mu.Unlock()
			return &reservation{bs: bs, key: key}, true, 0
		}
		inFlight, settled := bs.held[key] > 0, bs.settled
		bs.mu.Unlock()
		if !inFlight {
			return nil, false, over
		}
		if give == nil {
			give = time.NewTimer(reserveWait)
			defer give.Stop()
		}
		select {
		case <-settled:
		case <-give.C:
			return nil, false, over
		case <-ctx.Done():
			return nil, false, over
		}
	}
}

// keep settles the reservation as counted: its token stays taken.
func (r *reservation) keep() { r.settle(false, time.Time{}) }

// release settles the reservation as not counted: its token goes back.
func (r *reservation) release(now time.Time) { r.settle(true, now) }

func (r *reservation) settle(back bool, now time.Time) {
	if r == nil || r.done {
		return
	}
	r.done = true
	bs := r.bs
	bs.mu.Lock()
	if bs.held[r.key]--; bs.held[r.key] <= 0 {
		delete(bs.held, r.key)
	}
	if back {
		bs.giveLocked(r.key, now)
	}
	close(bs.settled)
	bs.settled = make(chan struct{})
	bs.mu.Unlock()
}

// perPeriod is buckets of n, refilled n per period.
func perPeriod(n int, period time.Duration) *buckets {
	if n == 0 {
		return newBuckets(0, 0)
	}
	return newBuckets(n, period/time.Duration(n))
}

// take takes one token for key at now. When none is left it returns how
// long until one is. A bucket set with n == 0, or no interval, never
// limits.
func (bs *buckets) take(key string, now time.Time) (ok bool, wait time.Duration) {
	if bs.n == 0 || bs.every <= 0 {
		return true, 0
	}
	bs.mu.Lock()
	defer bs.mu.Unlock()
	bs.prune(now)
	next, over := bs.next(key, now)
	if over > 0 {
		return false, over
	}
	bs.full[key] = next
	return true, 0
}

// giveLocked puts back a token taken for key, for a call that turned out not
// to count: a reservation released. It never fills a bucket past full. The
// caller holds bs.mu.
func (bs *buckets) giveLocked(key string, now time.Time) {
	full, ok := bs.full[key]
	if !ok {
		return
	}
	if full = full.Add(-bs.every); full.After(now) {
		bs.full[key] = full
	} else {
		delete(bs.full, key)
	}
}

// ready reports whether key has a token at now, and takes none: for a limit
// that counts an outcome known only after the work it guards.
func (bs *buckets) ready(key string, now time.Time) (ok bool, wait time.Duration) {
	if bs.n == 0 || bs.every <= 0 {
		return true, 0
	}
	bs.mu.Lock()
	defer bs.mu.Unlock()
	if _, over := bs.next(key, now); over > 0 {
		return false, over
	}
	return true, 0
}

// next is when key's bucket would be full again were a token taken at now,
// and how far that is past a full bucket: over zero, no token is left. Each
// token taken puts full one interval later; a full bucket is n intervals'
// worth.
func (bs *buckets) next(key string, now time.Time) (next time.Time, over time.Duration) {
	full := bs.full[key]
	if full.Before(now) {
		full = now
	}
	next = full.Add(bs.every)
	return next, next.Sub(now) - time.Duration(bs.n)*bs.every
}

// prune drops every key whose bucket is full again, once each time an empty
// bucket would have filled: the map holds only keys used within the last two
// such periods, not every key ever seen.
func (bs *buckets) prune(now time.Time) {
	if now.Before(bs.sweep) {
		return
	}
	for k, full := range bs.full {
		if !full.After(now) {
			delete(bs.full, k)
		}
	}
	bs.sweep = now.Add(time.Duration(bs.n) * bs.every)
}

// daily counts an action per box per UTC day: sends per sender, prekey
// renewals per box.
type daily struct {
	mu  sync.Mutex
	day string
	n   map[protocol.Address]int
}

// take counts one for a at now if a is under limit, and otherwise returns how
// long until the next UTC day. A count is taken before the work it guards
// and given back if that work does not happen (give), so calls in flight at
// once cannot all pass on one count. limit == 0 never limits.
func (d *daily) take(a protocol.Address, now time.Time, limit int) (ok bool, wait time.Duration) {
	if limit == 0 {
		return true, 0
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	day := now.UTC().Format(time.DateOnly)
	if d.day != day {
		d.day, d.n = day, map[protocol.Address]int{}
	}
	if d.n[a] >= limit {
		next := now.UTC().Truncate(24 * time.Hour).Add(24 * time.Hour)
		return false, next.Sub(now)
	}
	d.n[a]++
	return true, 0
}

// give takes back a count take took at now under limit, for work that did
// not happen. A count from a day already past is gone with its day.
func (d *daily) give(a protocol.Address, now time.Time, limit int) {
	if limit == 0 {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.day == now.UTC().Format(time.DateOnly) && d.n[a] > 0 {
		d.n[a]--
	}
}

// ipKey keys a per-IP limit on a client address: the IPv4 address, or the
// IPv6 /64, since every IPv6 end site holds at least a /64.
func ipKey(host string) string {
	ip := net.ParseIP(host)
	if ip == nil {
		return host
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	return ip.Mask(net.CIDRMask(64, 128)).String() + "/64"
}

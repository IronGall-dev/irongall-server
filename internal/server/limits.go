package server

import (
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
	TokensPerMinute      int // POST …/token per IP [tunable]
	SendsPerMinutePerIP  int // the pre-auth send rate per IP [tunable]
	MissesPerMinute      int // reads of the boxes table that find no box, per IP (decided: 10 for now)
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
}

// newBuckets is buckets of n, refilled one every interval.
func newBuckets(n int, every time.Duration) *buckets {
	return &buckets{n: n, every: every, full: map[string]time.Time{}}
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

// add checks a send by a at now is under limit, and counts it if commit;
// otherwise it returns how long until the next UTC day. limit == 0 never
// limits.
func (d *daily) add(a protocol.Address, now time.Time, limit int, commit bool) (ok bool, wait time.Duration) {
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
	if commit {
		d.n[a]++
	}
	return true, 0
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

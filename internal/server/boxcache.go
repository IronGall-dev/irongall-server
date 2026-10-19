package server

import (
	"container/list"
	"sync"
	"time"

	"github.com/IronGall-dev/irongall-client/protocol"
)

// recCache is a bounded LRU of records, each at a rev. The stream replaces or
// evicts an entry when its record changes; a record never moves back to an
// older rev. Two are kept: what is held of each address, a box's record with
// its identity's revocations (ARCHITECTURE.md § Memory, for sends and reads
// of a box), and account records (for a sender's limits).
type recCache[K comparable, V any] struct {
	mu  sync.Mutex
	max int // 0: no cache
	ll  *list.List
	m   map[K]*list.Element // value: V

	key   func(V) K
	rev   func(V) uint64
	clone func(V) V
	// merge, if set, is what two copies of an entry hold together, old the
	// cached one: put and refresh keep it in place of the newer copy alone.
	merge func(old, cur V) V
	// note, if set, is told of each hit, miss and eviction (Metrics).
	note func(event string)
}

type boxCache = recCache[protocol.Address, *Box]

func newBoxCache(size int) *boxCache {
	c := newRecCache(size, func(b *Box) protocol.Address { return b.Addr }, func(b *Box) uint64 { return b.Rev }, cloneBox)
	c.merge = mergeViews // revocations are never taken away, so neither copy's are lost
	return c
}

type accountCache = recCache[string, *Account]

func newAccountCache(size int) *accountCache {
	return newRecCache(size, func(a *Account) string { return a.ID }, func(a *Account) uint64 { return a.Rev }, cloneAccount)
}

func newRecCache[K comparable, V any](size int, key func(V) K, rev func(V) uint64, clone func(V) V) *recCache[K, V] {
	return &recCache[K, V]{max: size, ll: list.New(), m: map[K]*list.Element{}, key: key, rev: rev, clone: clone}
}

func (c *recCache[K, V]) get(k K) (V, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.m[k]
	if !ok {
		c.noted("miss")
		var zero V
		return zero, false
	}
	c.noted("hit")
	c.ll.MoveToFront(e)
	return c.clone(e.Value.(V)), true
}

func (c *recCache[K, V]) noted(event string) {
	if c.note != nil {
		c.note(event)
	}
}

// put caches v, unless the cache holds a newer rev of it.
func (c *recCache[K, V]) put(v V) {
	if c.max == 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	k := c.key(v)
	if e, ok := c.m[k]; ok {
		switch {
		case c.merge != nil:
			e.Value = c.merge(e.Value.(V), v)
		case c.rev(e.Value.(V)) <= c.rev(v):
			e.Value = c.clone(v)
		}
		c.ll.MoveToFront(e)
		return
	}
	c.m[k] = c.ll.PushFront(c.clone(v))
	for c.ll.Len() > c.max {
		old := c.ll.Back()
		c.ll.Remove(old)
		delete(c.m, c.key(old.Value.(V)))
		c.noted("eviction")
	}
}

// refresh replaces a cached record with a newer rev from the stream; one not
// cached stays uncached. A record that fails to decode is evicted.
func (c *recCache[K, V]) refresh(k K, rev uint64, decode func() (V, error)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.m[k]
	if !ok || c.rev(e.Value.(V)) >= rev {
		return
	}
	v, err := decode()
	if err != nil {
		c.ll.Remove(e)
		delete(c.m, k)
		return
	}
	if c.merge != nil {
		v = c.merge(e.Value.(V), v)
	}
	e.Value = v
}

// modify replaces a cached entry with what f makes of it, or evicts it when
// f says not to keep it; one not cached stays uncached.
func (c *recCache[K, V]) modify(k K, f func(V) (V, bool)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.m[k]
	if !ok {
		return
	}
	v, keep := f(c.clone(e.Value.(V)))
	if !keep {
		c.ll.Remove(e)
		delete(c.m, k)
		return
	}
	e.Value = v
}

func (c *recCache[K, V]) evict(k K) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e, ok := c.m[k]; ok {
		c.ll.Remove(e)
		delete(c.m, k)
	}
}

// missTTL is how long a box the table did not hold is remembered as missing.
// A write to the box, by this process or seen on the stream, ends it sooner.
const missTTL = 30 * time.Second

// missCache remembers the boxes a read found missing, briefly, so that naming
// the same missing box again costs no read. At most max are held; over that,
// the expired go, and if none has, all of them.
type missCache struct {
	mu    sync.Mutex
	max   int // 0: no cache
	until map[protocol.Address]time.Time
	// seq counts the writes seen to the boxes of each shard (the address's
	// first byte): a miss read before a write is not recorded after it.
	seq [256]uint64
	// note, if set, is told of each hit, miss and eviction (Metrics).
	note func(event string)
}

func newMissCache(size int) *missCache {
	return &missCache{max: size, until: map[protocol.Address]time.Time{}}
}

// has reports whether a is remembered as missing at now. If not, it returns
// the shard's write count, for missed.
func (c *missCache) has(a protocol.Address, now time.Time) (missing bool, seq uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if t, ok := c.until[a]; ok {
		if now.Before(t) {
			c.noted("hit")
			return true, 0
		}
		delete(c.until, a)
	}
	c.noted("miss")
	return false, c.seq[a[0]]
}

func (c *missCache) noted(event string) {
	if c.note != nil {
		c.note(event)
	}
}

// missed records that a read begun at seq found no box a.
func (c *missCache) missed(a protocol.Address, seq uint64, now time.Time) {
	if c.max == 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.seq[a[0]] != seq {
		return
	}
	if len(c.until) >= c.max {
		for k, t := range c.until {
			if !now.Before(t) {
				delete(c.until, k)
			}
		}
		if len(c.until) >= c.max {
			for range c.until {
				c.noted("eviction")
			}
			clear(c.until)
		}
	}
	c.until[a] = now.Add(missTTL)
}

// wrote records that box a has a record.
func (c *missCache) wrote(a protocol.Address) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.seq[a[0]]++
	delete(c.until, a)
}

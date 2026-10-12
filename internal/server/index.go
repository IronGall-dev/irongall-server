package server

import (
	"context"
	"encoding/binary"
	"slices"
	"sync"

	"github.com/IronGall-dev/irongall-client/protocol"
)

// index is what a process holds in memory so that a poll never leaves it
// (ARCHITECTURE.md § Memory): for each box this
// process has used, its standing and one mark per live message.
//
// A box is loaded on its first use (ensure), from the tables, and kept
// current after that by this process's own writes and by the streams. A
// change to a box memory does not hold is dropped, since its first use reads
// it; a change that arrives while the box loads waits, and is applied after
// the load, in order. Applying a change twice, or late, is harmless:
// messages are a set keyed by (id, expiry), a count is the size of the set,
// and a standing only moves to a newer rev.
type index struct {
	shards [256]indexShard // by the address's first byte
}

type indexShard struct {
	mu    sync.Mutex
	boxes map[protocol.Address]*boxMem
}

// mark is one live message (ARCHITECTURE.md § Memory).
type mark struct {
	id   uint64 // first 8 bytes of the message id, which is already a SHA-256
	from uint64 // first 8 bytes of the sender's address, for the per-pair cap
	exp  uint64 // expiry in unix ms: received_at + TTL
	n    uint8  // fetches of it this process has served, to 255: a second one is a repeat
}

// boxMem is one box in memory.
type boxMem struct {
	loading *boxLoad // set while the box's first load is in flight
	exists  bool     // the box has a record
	st      Standing
	rev     uint64
	marks   []mark
	// tombs are messages this process removed whose removal the stream has
	// not echoed yet: the stream's late insert must not bring them back. The
	// echo clears one; so does its expiry, in case the echo came first.
	tombs []mark
}

// boxLoad is a box's first load: the changes that arrive meanwhile, and its
// outcome for the callers waiting on it.
type boxLoad struct {
	queued []func(*boxMem)
	done   chan struct{}
	err    error
}

// boxRead is what a load reads of a box: whether it has a record, its
// standing at rev, and its live messages.
type boxRead struct {
	exists bool
	st     Standing
	rev    uint64
	marks  []mark
}

func newIndex() *index {
	x := &index{}
	for i := range x.shards {
		x.shards[i].boxes = map[protocol.Address]*boxMem{}
	}
	return x
}

func (x *index) shard(a protocol.Address) *indexShard { return &x.shards[a[0]] }

func prefix8(b []byte) uint64 { return binary.BigEndian.Uint64(b[:8]) }

func newMark(id [32]byte, from protocol.Address, exp uint64) mark {
	return mark{id: prefix8(id[:]), from: prefix8(from[:]), exp: exp}
}

// ensure loads box a unless memory holds it. read runs once however many
// callers ask at the same time; if it fails, the box stays unloaded and the
// next caller reads again.
func (x *index) ensure(ctx context.Context, a protocol.Address, read func() (boxRead, error)) error {
	sh := x.shard(a)
	sh.mu.Lock()
	if m := sh.boxes[a]; m != nil {
		l := m.loading
		sh.mu.Unlock()
		if l == nil {
			return nil
		}
		select {
		case <-l.done:
			return l.err
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	l := &boxLoad{done: make(chan struct{})}
	m := &boxMem{loading: l}
	sh.boxes[a] = m
	sh.mu.Unlock()

	r, err := read()
	sh.mu.Lock()
	if err != nil {
		delete(sh.boxes, a) // and its queued changes: the next read sees them
	} else {
		m.exists, m.st, m.rev, m.marks = r.exists, r.st, r.rev, r.marks
		for _, op := range l.queued {
			op(m)
		}
		m.loading = nil
	}
	l.err = err
	sh.mu.Unlock()
	close(l.done)
	return err
}

// apply runs op on box a: now if memory holds it, after its load if it is
// loading, and not at all if memory does not hold it.
func (x *index) apply(a protocol.Address, op func(*boxMem)) {
	sh := x.shard(a)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	switch m := sh.boxes[a]; {
	case m == nil:
	case m.loading != nil:
		m.loading.queued = append(m.loading.queued, op)
	default:
		op(m)
	}
}

// held returns box a if memory holds it, loaded.
func (sh *indexShard) held(a protocol.Address) *boxMem {
	if m := sh.boxes[a]; m != nil && m.loading == nil {
		return m
	}
	return nil
}

// prune drops marks and tombs that have expired at now (unix ms): a message
// is live while now < its expiry.
func (m *boxMem) prune(now uint64) {
	m.marks = slices.DeleteFunc(m.marks, func(k mark) bool { return k.exp <= now })
	m.tombs = slices.DeleteFunc(m.tombs, func(k mark) bool { return k.exp <= now })
}

func same(a, b mark) bool { return a.id == b.id && a.exp == b.exp }

// insert adds a live message, from this process's write or the stream. A
// message with a tomb stays removed.
func (x *index) insert(box protocol.Address, k mark, now uint64) {
	x.apply(box, func(m *boxMem) {
		if k.exp <= now {
			return
		}
		m.prune(now)
		if slices.ContainsFunc(m.tombs, func(t mark) bool { return same(t, k) }) ||
			slices.ContainsFunc(m.marks, func(t mark) bool { return same(t, k) }) {
			return
		}
		m.marks = append(m.marks, k)
	})
}

// remove removes a message. A removal by this process leaves a tomb until
// the stream echoes it (echo true) or the message would have expired.
func (x *index) remove(box protocol.Address, id, exp, now uint64, echo bool) {
	x.apply(box, func(m *boxMem) {
		m.prune(now)
		k := mark{id: id, exp: exp}
		m.marks = slices.DeleteFunc(m.marks, func(t mark) bool { return same(t, k) })
		switch {
		case echo:
			m.tombs = slices.DeleteFunc(m.tombs, func(t mark) bool { return same(t, k) })
		case exp > now && !slices.ContainsFunc(m.tombs, func(t mark) bool { return same(t, k) }):
			m.tombs = append(m.tombs, k)
		}
	})
}

// count returns the number of live messages in a box and its version: the
// XOR of their id marks, identical on every process.
func (x *index) count(box protocol.Address, now uint64) (n int, version uint64) {
	sh := x.shard(box)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	m := sh.held(box)
	if m == nil {
		return 0, 0
	}
	m.prune(now)
	for _, k := range m.marks {
		version ^= k.id
	}
	return len(m.marks), version
}

// pair returns how many live messages from one sender a box holds, and the
// earliest expiry among them.
func (x *index) pair(box protocol.Address, from uint64, now uint64) (n int, oldest uint64) {
	sh := x.shard(box)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	m := sh.held(box)
	if m == nil {
		return 0, 0
	}
	m.prune(now)
	for _, k := range m.marks {
		if k.from == from {
			n++
			if oldest == 0 || k.exp < oldest {
				oldest = k.exp
			}
		}
	}
	return n, oldest
}

// after returns how many live messages a box holds past a list position: the
// list is oldest first, by receipt time (so by expiry) and then id.
func (x *index) after(box protocol.Address, exp, id, now uint64) (n int) {
	sh := x.shard(box)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	m := sh.held(box)
	if m == nil {
		return 0
	}
	m.prune(now)
	for _, k := range m.marks {
		if k.exp > exp || (k.exp == exp && k.id > id) {
			n++
		}
	}
	return n
}

// holds reports whether a box holds a live message whose id starts with id.
func (x *index) holds(box protocol.Address, id, now uint64) bool {
	sh := x.shard(box)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	m := sh.held(box)
	if m == nil {
		return false
	}
	m.prune(now)
	return slices.ContainsFunc(m.marks, func(k mark) bool { return k.id == id })
}

// fetched is holds for a fetch: it also reports whether this process has
// served the message before, and counts this serving.
func (x *index) fetched(box protocol.Address, id, now uint64) (held, again bool) {
	sh := x.shard(box)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	m := sh.held(box)
	if m == nil {
		return false, false
	}
	m.prune(now)
	for i := range m.marks {
		if k := &m.marks[i]; k.id == id {
			again = k.n > 0
			if k.n < 255 {
				k.n++
			}
			return true, again
		}
	}
	return false, false
}

// setStanding records a box's standing at rev, unless memory holds a newer
// one.
func (x *index) setStanding(a protocol.Address, st Standing, rev uint64) {
	x.apply(a, func(m *boxMem) {
		if m.rev > rev {
			return
		}
		m.exists, m.st, m.rev = true, st, rev
	})
}

// dropStanding records that a box's record was deleted.
func (x *index) dropStanding(a protocol.Address) {
	x.apply(a, func(m *boxMem) { m.exists, m.st, m.rev = false, Standing{}, 0 })
}

// standing returns a loaded box's standing, and whether it has a record.
func (x *index) standing(a protocol.Address) (Standing, bool) {
	sh := x.shard(a)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	m := sh.held(a)
	if m == nil || !m.exists {
		return Standing{}, false
	}
	return m.st, true
}

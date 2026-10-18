package server

import (
	"bytes"
	"context"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/IronGall-dev/irongall-client/protocol"
)

// MemStore is the dev server's store: everything in memory, nothing
// persisted. Expired messages and dedupe records vanish at their ExpiresAt.
// A box's record stays past its Expires, as one in DynamoDB does until the
// TTL deletes it, which may be days after: a test stands in for the TTL with
// DeleteBox, which is the delete the TTL makes.
type MemStore struct {
	now func() time.Time

	mu          sync.Mutex
	boxes       map[protocol.Address]*Box         // each box's record, with none of its revocations
	revocations map[protocol.Address]*Revocations // each address's revocations item
	messages    map[protocol.Address]map[[32]byte]*memMessage
	dedupe      map[protocol.Address]map[[32]byte]Header
	accounts    map[string]*Account
	keys        map[adoptKeyRef]*AdoptKey
}

type adoptKeyRef struct {
	account string
	id      [16]byte
}

type memMessage struct {
	h       Header
	body    []byte
	fetched bool // served to a fetch before
}

// NewMemStore returns an empty store on the given clock.
func NewMemStore(now func() time.Time) *MemStore {
	return &MemStore{
		now:         now,
		boxes:       map[protocol.Address]*Box{},
		revocations: map[protocol.Address]*Revocations{},
		messages:    map[protocol.Address]map[[32]byte]*memMessage{},
		dedupe:      map[protocol.Address]map[[32]byte]Header{},
		accounts:    map[string]*Account{},
		keys:        map[adoptKeyRef]*AdoptKey{},
	}
}

func cloneBox(b *Box) *Box {
	c := *b
	c.Retired = slices.Clone(b.Retired)
	c.SenderKeyTypes = slices.Clone(b.SenderKeyTypes)
	c.RevokedCerts, c.RevokedCertsSig = slices.Clone(b.RevokedCerts), slices.Clone(b.RevokedCertsSig)
	c.ACL = cloneACL(b.ACL)
	if b.Prekey != nil {
		p := *b.Prekey
		c.Prekey = &p
	}
	return &c
}

// cloneACL copies an ACL, which a box record holds and nothing changes in
// place: it is replaced whole.
func cloneACL(a *protocol.ACL) *protocol.ACL {
	if a == nil {
		return nil
	}
	c := *a
	c.Allow.Addrs, c.Deny.Addrs = slices.Clone(a.Allow.Addrs), slices.Clone(a.Deny.Addrs)
	return &c
}

// record returns a's record, or nil.
func (s *MemStore) record(a protocol.Address) *Box { return s.boxes[a] }

func (s *MemStore) viewLocked(a protocol.Address) *Box {
	var rv *Revocations
	if r, ok := s.revocations[a]; ok {
		c := *r
		rv = &c
	}
	return view(a, s.record(a), rv)
}

// Held implements Store: the dev store holds every box in memory.
func (s *MemStore) Held(a protocol.Address) (Standing, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b := s.viewLocked(a)
	if b == nil {
		return Standing{}, false
	}
	st, ok, err := b.standing()
	return st, ok && err == nil
}

// Box implements Store.
func (s *MemStore) Box(_ context.Context, a protocol.Address) (*Box, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if b := s.viewLocked(a); b != nil {
		return b, nil
	}
	return nil, ErrNotFound
}

// Known implements Store: every box is in memory, and nothing remembers a
// missing one, so each call naming one counts as a read would.
func (s *MemStore) Known(a protocol.Address) (*Box, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b := s.viewLocked(a)
	return b, b != nil
}

// CreateBox implements Store.
func (s *MemStore) CreateBox(_ context.Context, b *Box) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.record(b.Addr) != nil {
		return ErrExists
	}
	if err := b.writable(); err != nil {
		return err
	}
	if _, err := identityWire(b.Identity); err != nil {
		return fmt.Errorf("the identity: %w", err)
	}
	b.Rev = 1
	s.boxes[b.Addr] = storedRecord(b)
	return nil
}

// UpdateBox implements Store.
func (s *MemStore) UpdateBox(_ context.Context, b *Box) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := b.writable(); err != nil {
		return err
	}
	cur := s.record(b.Addr)
	if cur == nil || cur.Rev != b.Rev {
		return ErrStale
	}
	b.Rev++
	s.boxes[b.Addr] = storedRecord(b)
	return nil
}

// storedRecord is what a store keeps of b as its record: none of what its
// identity revoked, which is kept apart, and the state the record says.
func storedRecord(b *Box) *Box {
	c := cloneBox(b)
	c.Revocation, c.RevokedCerts, c.RevokedCertsSig = nil, nil, nil
	return c
}

// DeleteBox implements Store.
func (s *MemStore) DeleteBox(_ context.Context, a protocol.Address) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.boxes, a)
	return nil
}

// Revoke implements Store.
func (s *MemStore) Revoke(_ context.Context, a protocol.Address, rv *Revocations) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cur, ok := s.revocations[a]
	if !ok {
		cur = &Revocations{}
	}
	if rv.Through > 0 && cur.Through >= rv.Through {
		return ErrStale
	}
	c := *cur
	c.merge(rv)
	s.revocations[a] = &c
	return nil
}

func (s *MemStore) live(box protocol.Address) map[[32]byte]*memMessage {
	now := s.now()
	m := s.messages[box]
	for id, msg := range m {
		if !now.Before(msg.h.ExpiresAt) {
			delete(m, id)
		}
	}
	return m
}

// Dedupe implements Store.
func (s *MemStore) Dedupe(_ context.Context, box protocol.Address, id [32]byte) (*Header, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.dedupeLocked(box, id)
}

func (s *MemStore) dedupeLocked(box protocol.Address, id [32]byte) (*Header, error) {
	h, ok := s.dedupe[box][id]
	if !ok || !s.now().Before(h.ExpiresAt) {
		return nil, ErrNotFound
	}
	return &h, nil
}

// PutMessage implements Store.
func (s *MemStore) PutMessage(_ context.Context, box protocol.Address, h *Header, body []byte) (*Header, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if orig, err := s.dedupeLocked(box, h.ID); err == nil {
		return orig, nil
	}
	if s.dedupe[box] == nil {
		s.dedupe[box] = map[[32]byte]Header{}
	}
	if s.messages[box] == nil {
		s.messages[box] = map[[32]byte]*memMessage{}
	}
	s.dedupe[box][h.ID] = *h
	s.messages[box][h.ID] = &memMessage{h: *h, body: bytes.Clone(body)}
	return nil, nil
}

func less(a, b Header) int {
	if c := a.ReceivedAt.Compare(b.ReceivedAt); c != 0 {
		return c
	}
	return bytes.Compare(a.ID[:], b.ID[:])
}

// List implements Store.
func (s *MemStore) List(_ context.Context, box protocol.Address, after *Cursor, limit int) ([]Header, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var all []Header
	for _, m := range s.live(box) {
		if after != nil && less(m.h, Header{ReceivedAt: after.ReceivedAt, ID: after.ID}) <= 0 {
			continue
		}
		all = append(all, m.h)
	}
	slices.SortFunc(all, less)
	if len(all) > limit {
		all = all[:limit]
	}
	return all, nil
}

// Message implements Store.
func (s *MemStore) Message(_ context.Context, box protocol.Address, id [32]byte) (*Header, []byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, ok := s.live(box)[id]
	if !ok {
		return nil, nil, ErrNotFound
	}
	h := m.h
	return &h, bytes.Clone(m.body), nil
}

// DeleteMessage implements Store.
func (s *MemStore) DeleteMessage(_ context.Context, box protocol.Address, id [32]byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	m := s.live(box)
	if _, ok := m[id]; !ok {
		return ErrNotFound
	}
	delete(m, id)
	return nil
}

// DeleteMessages implements Store.
func (s *MemStore) DeleteMessages(ctx context.Context, box protocol.Address) error {
	return s.DeleteFrom(ctx, box, func(protocol.Address) bool { return true })
}

// DeleteFrom implements Store.
func (s *MemStore) DeleteFrom(_ context.Context, box protocol.Address, from func(protocol.Address) bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	m := s.messages[box]
	for id, msg := range m {
		if from(msg.h.From) {
			delete(m, id)
		}
	}
	if len(m) == 0 {
		delete(s.messages, box)
	}
	return nil
}

// UseMarkKey implements Store. This store keeps each message by its whole
// id, and tags none.
func (s *MemStore) UseMarkKey([32]byte) {}

// Count implements Store.
func (s *MemStore) Count(_ context.Context, box protocol.Address) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.live(box)), nil
}

// PairCount implements Store.
func (s *MemStore) PairCount(_ context.Context, box, from protocol.Address) (int, time.Time, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var n int
	var oldest time.Time
	for _, m := range s.live(box) {
		if m.h.From != from {
			continue
		}
		n++
		if oldest.IsZero() || m.h.ExpiresAt.Before(oldest) {
			oldest = m.h.ExpiresAt
		}
	}
	return n, oldest, nil
}

// After implements Store.
func (s *MemStore) After(_ context.Context, box protocol.Address, c *Cursor) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, m := range s.live(box) {
		if less(m.h, Header{ReceivedAt: c.ReceivedAt, ID: c.ID}) > 0 {
			n++
		}
	}
	return n, nil
}

// Holds implements Store.
func (s *MemStore) Holds(_ context.Context, box protocol.Address, id [32]byte) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.live(box)[id]
	return ok, nil
}

// Fetched implements Store.
func (s *MemStore) Fetched(_ context.Context, box protocol.Address, id [32]byte) (held, again bool, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, ok := s.live(box)[id]
	if !ok {
		return false, false, nil
	}
	again, m.fetched = m.fetched, true
	return true, again, nil
}

func cloneAccount(a *Account) *Account {
	c := *a
	return &c
}

// Account implements Store.
func (s *MemStore) Account(_ context.Context, id string) (*Account, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.accounts[id]
	if !ok {
		return nil, ErrNotFound
	}
	return cloneAccount(a), nil
}

// CreateAccount implements Store.
func (s *MemStore) CreateAccount(_ context.Context, a *Account) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.accounts[a.ID]; ok {
		return ErrExists
	}
	a.Rev = 1
	s.accounts[a.ID] = cloneAccount(a)
	return nil
}

// PutAdoptKey implements Store.
func (s *MemStore) PutAdoptKey(_ context.Context, k *AdoptKey) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	ref := adoptKeyRef{k.Account, k.ID}
	if _, ok := s.keys[ref]; ok {
		return ErrExists
	}
	c := *k
	s.keys[ref] = &c
	return nil
}

// Adopt implements Store.
func (s *MemStore) Adopt(_ context.Context, b *Box, account string, key [16]byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cur := s.record(b.Addr)
	if cur == nil || cur.Rev != b.Rev {
		return ErrStale
	}
	k, ok := s.keys[adoptKeyRef{account, key}]
	if !ok || k.Uses < 1 || !s.now().Before(k.Expires) {
		return ErrKeyRefused
	}
	k.Uses--
	cur.Account, cur.Rev = account, cur.Rev+1
	b.Account, b.Rev = account, cur.Rev
	return nil
}

// Leave implements Store.
func (s *MemStore) Leave(_ context.Context, b *Box) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cur := s.record(b.Addr)
	if cur == nil || cur.Rev != b.Rev {
		return ErrStale
	}
	cur.Account, cur.Rev = "", cur.Rev+1
	b.Account, b.Rev = "", cur.Rev
	return nil
}

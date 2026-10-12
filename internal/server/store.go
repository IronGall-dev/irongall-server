package server

import (
	"context"
	"errors"
	"time"

	"github.com/IronGall-dev/irongall-client/protocol"
)

// State is a box's state (PROTOCOL.md §3a).
type State string

// The box states. The epoch never resets across them.
const (
	Pending State = "pending"
	Active  State = "active"
	Closed  State = "closed"
	Revoked State = "revoked"
)

// Box is a box's record.
type Box struct {
	Addr     protocol.Address
	Identity []byte // the identity document, exactly as registered
	State    State
	// The current prekey: its statement, the identity's signature over it,
	// and the statement parsed.
	Statement []byte
	Signature []byte
	Prekey    *protocol.Prekey
	// Retired holds the newest retired prekeys (Limits.RetiredKept), each
	// until its not_after: its key may not come back.
	Retired []Retired
	Epoch   uint32 // bumps on every prekey change and token rotation; never resets
	Rev     uint64 // the record's revision; a write must name the one it read
	Created time.Time
	// Account is the account the box belongs to, or "" (PROTOCOL.md §6.5).
	// Only Adopt and Leave change it.
	Account string
}

// Account is an account's record (PROTOCOL.md §6.5). An account pays,
// from prepaid credit, for its boxes' sends past the free limits and for
// size over the cap; with no credit they have the free limits. An unmetered
// account's boxes have no daily limit and the largest cap, and are never
// charged: the echo account. Credit is not built yet, so a metered account's
// boxes have the free limits.
type Account struct {
	ID        string
	Unmetered bool
	Rev       uint64
}

// AdoptKey is the state of an adopt key: the key itself is an HMAC, never
// stored (token.go).
type AdoptKey struct {
	Account string
	ID      [16]byte
	Uses    int // left
	Expires time.Time
}

// Retired is what is kept of a retired prekey while it is live.
type Retired struct {
	Type     protocol.KeyType
	NotAfter time.Time
	KeyHash  [32]byte // SHA-256 of the age recipient
}

// Header is one message's metadata: everything but its body.
type Header struct {
	ID         [32]byte // SHA-256 of the ciphertext
	From       protocol.Address
	Size       int
	ReceivedAt time.Time // to the millisecond
	ExpiresAt  time.Time
	Signature  []byte
}

// Standing is what an owner call needs of a box: its state and its epoch.
type Standing struct {
	State State
	Epoch uint32
}

// Store errors.
var (
	ErrNotFound = errors.New("not found")
	ErrExists   = errors.New("already exists")
	ErrStale    = errors.New("the record changed since it was read")
	// ErrKeyRefused is an adopt key that is spent, expired or gone.
	ErrKeyRefused = errors.New("the adopt key is spent, expired or revoked")
)

// Store is the server's state: box records, message headers with their
// dedupe records, and bodies. MemStore keeps it in memory (the dev server);
// DynamoStore keeps it in DynamoDB + S3 Express, with what a poll needs in
// memory.
type Store interface {
	// Standing returns a box's standing, or ErrNotFound. A store with memory
	// reads the box on its first use, then answers from memory
	// (ARCHITECTURE.md § Memory).
	Standing(ctx context.Context, a protocol.Address) (Standing, error)
	// Box returns a box's record, or ErrNotFound.
	Box(ctx context.Context, a protocol.Address) (*Box, error)
	// Known returns what memory holds of a box, with no read: its record, or
	// nil for an address it holds as missing. ok is false when only a read
	// can tell, which is what Box then does.
	Known(a protocol.Address) (b *Box, ok bool)
	// CreateBox stores a new box at Rev 1, or returns ErrExists.
	CreateBox(ctx context.Context, b *Box) error
	// UpdateBox stores b if the stored record is still at b.Rev, and bumps
	// b.Rev; otherwise ErrStale.
	UpdateBox(ctx context.Context, b *Box) error

	// Dedupe returns the header of the message box already holds with this
	// id, acked or not, until it expires; or ErrNotFound.
	Dedupe(ctx context.Context, box protocol.Address, id [32]byte) (*Header, error)
	// PutMessage stores a message: its body, then its header, which is also
	// its dedupe record. If a live record for the id appeared first, it
	// returns that record's header instead.
	PutMessage(ctx context.Context, box protocol.Address, h *Header, body []byte) (*Header, error)
	// List returns up to limit live headers, oldest first by (ReceivedAt,
	// ID), after the given key (nil: from the start).
	List(ctx context.Context, box protocol.Address, after *Cursor, limit int) ([]Header, error)
	// Message returns a live message and its body, or ErrNotFound.
	Message(ctx context.Context, box protocol.Address, id [32]byte) (*Header, []byte, error)
	// DeleteMessage acks a message: its body goes, then it leaves the list;
	// its dedupe record stays until it expires. ErrNotFound if it is not
	// live.
	DeleteMessage(ctx context.Context, box protocol.Address, id [32]byte) error
	// DeleteMessages deletes every live message in a box (close).
	DeleteMessages(ctx context.Context, box protocol.Address) error

	// Account returns an account's record, or ErrNotFound. A store with
	// memory reads it on its first use, then answers from memory.
	Account(ctx context.Context, id string) (*Account, error)
	// CreateAccount stores a new account at Rev 1, or returns ErrExists.
	CreateAccount(ctx context.Context, a *Account) error
	// PutAdoptKey stores a new adopt key's state, or returns ErrExists.
	PutAdoptKey(ctx context.Context, k *AdoptKey) error
	// Adopt moves box b, as read, into account, spending a use of the adopt
	// key id of that account, in one write: ErrStale if the record changed,
	// ErrKeyRefused if the key is spent, expired or gone. It sets b.Account
	// and bumps b.Rev.
	Adopt(ctx context.Context, b *Box, account string, key [16]byte) error
	// Leave takes box b, as read, out of its account, or returns ErrStale.
	// It clears b.Account and bumps b.Rev.
	Leave(ctx context.Context, b *Box) error

	// Count returns the number of live messages in a box and its version:
	// the XOR of the first 8 bytes of their ids, identical on every process.
	// Count and PairCount answer from memory as Standing does.
	Count(ctx context.Context, box protocol.Address) (n int, version uint64, err error)
	// PairCount returns how many live messages from one sender a box holds,
	// and when the oldest of them expires.
	PairCount(ctx context.Context, box, from protocol.Address) (n int, oldest time.Time, err error)
	// After returns how many live messages a box holds past a list position,
	// from memory as Count does: what a list from that cursor would return.
	After(ctx context.Context, box protocol.Address, c *Cursor) (int, error)
	// Holds reports whether a box holds a live message with this id, from
	// memory as Count does. False is certain; true may be another message
	// whose id starts alike, so the caller still reads it.
	Holds(ctx context.Context, box protocol.Address, id [32]byte) (bool, error)
	// Fetched is Holds for a fetch: it also reports whether this process has
	// served the message before, and counts this serving. The count lives
	// with the message in memory, so a restart forgets it.
	Fetched(ctx context.Context, box protocol.Address, id [32]byte) (held, again bool, err error)
}

// Cursor is a position in a box's list: the last key returned.
type Cursor struct {
	ReceivedAt time.Time
	ID         [32]byte
}

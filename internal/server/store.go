package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/IronGall-dev/irongall-client/protocol"
)

// State is a box's state (PROTOCOL.md §3a).
type State string

// The box states.
const (
	Active  State = "active"
	Closed  State = "closed"
	Revoked State = "revoked"
)

// Box is a box's record.
type Box struct {
	Addr     protocol.Address
	Identity []byte // the identity document, exactly as registered
	State    State
	// The current prekey: its statement, the working key's signature over it,
	// which carries the key's certificate, and the statement parsed.
	Statement []byte
	Signature []byte
	Prekey    *protocol.Prekey
	// The certificate Signature carries, which is the box's current one: its
	// serial, and the SHA-256 of its bytes. A pass is taken only under it,
	// and a prekey only under it or a later one (PROTOCOL.md §2b).
	CertSerial uint64
	Cert       [32]byte
	// SenderKeyTypes is what the box declared with its current prekey: the
	// identity key types of the senders it takes mail from, or
	// protocol.AnySender (PROTOCOL.md §2). Only names this build verifies
	// are kept (declared): a box of any other type cannot send here.
	SenderKeyTypes []string
	// Retired holds the newest retired prekeys (Limits.RetiredKept), each
	// until its not_after: its key may not come back.
	Retired []Retired
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
// stored (keys.go).
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
}

// Standing is what checking a box's pass needs of it (PROTOCOL.md §6.1b):
// its state, its identity's public key, and which certificate is its current
// one.
type Standing struct {
	State State
	Key   string   // the identity's key in SSH wire form, of whatever type: what line 2 of its document holds
	Cert  [32]byte // Box.Cert
}

// standing is b's standing.
func (b *Box) standing() (Standing, error) {
	key, err := identityWire(b.Identity)
	if err != nil {
		return Standing{}, fmt.Errorf("the stored identity: %w", err)
	}
	return Standing{State: b.State, Key: key, Cert: b.Cert}, nil
}

// identityWire is the key of a stored identity document, in SSH wire form:
// the base64 of its second line, decoded. The document was parsed when its
// box registered, so this reads it and checks nothing.
func identityWire(doc []byte) (string, error) {
	_, line, _ := bytes.Cut(doc, []byte("\n"))
	_, b64, _ := bytes.Cut(bytes.TrimSuffix(line, []byte("\n")), []byte(" "))
	wire, err := base64.StdEncoding.Strict().DecodeString(string(b64))
	if err != nil || len(wire) == 0 {
		return "", errors.New("its key is not base64")
	}
	return string(wire), nil
}

// declared is what the server keeps of a box's declaration of sender key
// types: the names this build verifies, or protocol.AnySender alone if that
// was among them. A name it does not know is dropped, not refused: a client
// may verify more types than this server registers.
func declared(types []string) []string {
	if slices.Contains(types, protocol.AnySender) {
		return []string{protocol.AnySender}
	}
	var kept []string
	for _, t := range protocol.IdentityTypes() {
		if slices.Contains(types, t) {
			kept = append(kept, t)
		}
	}
	return kept
}

// identityType is the key type of a stored identity document: the first word
// of its second line. The document was parsed when its box registered.
func identityType(doc []byte) string {
	_, line, _ := bytes.Cut(doc, []byte("\n"))
	name, _, _ := bytes.Cut(line, []byte(" "))
	return string(name)
}

// certHash names a certificate by the SHA-256 of its bytes.
func certHash(c *protocol.Certificate) [32]byte { return sha256.Sum256(c.Marshal()) }

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
	// Held returns the standing of a box memory holds, with no read. ok is
	// false for a box this process has not loaded, which only its record
	// answers for: Known, then Box (ARCHITECTURE.md § Memory).
	Held(a protocol.Address) (st Standing, ok bool)
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
	// Count and PairCount answer from memory: a store with memory loads the
	// box on its first use, then answers from memory.
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

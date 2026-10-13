package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/http"
	"regexp"

	"github.com/IronGall-dev/irongall-client/protocol"
)

// Accounts (PROTOCOL.md §6.5): a box may belong to one account, which
// may lift its limits. A box joins with an adopt key the account minted, and
// leaves on its own, or the account drops it.

// accountID is an account id: a minted one is 32 hex characters, and a few
// names are ours (echo).
var accountID = regexp.MustCompile(`\A[a-z0-9][a-z0-9-]{0,31}\z`)

func validAccountID(s string) bool { return accountID.MatchString(s) }

// NewAccountID returns a minted account id: 16 random bytes, in hex.
func NewAccountID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

// NewAccount checks an account id and returns its record.
func NewAccount(id string, unmetered bool) (*Account, error) {
	if !validAccountID(id) {
		return nil, errors.New("an account id is 1-32 of a-z, 0-9 and -, starting with a letter or digit")
	}
	return &Account{ID: id, Unmetered: unmetered}, nil
}

func keyRefused() *problem {
	return fail(protocol.CodeAdoptKeyRefused, "ask the account for a new adopt key", "the adopt key is spent, expired, revoked or not this server's")
}

// adopt is PUT /v1/<address>/account (with the pass): the box joins the account its
// adopt key names, spending one of the key's uses. Naming the account the
// box is already in spends none.
func (s *Server) adopt(w http.ResponseWriter, r *http.Request) error {
	a, err := s.owner(r)
	if err != nil {
		return err
	}
	var req protocol.AdoptRequest
	if err := decodeBody(w, r, 4<<10, &req); err != nil {
		return err
	}
	account, id, err := s.keys.VerifyAdopt(req.Key)
	if err != nil {
		return keyRefused()
	}
	b, err := s.box(r.Context(), a)
	if err != nil {
		return err
	}
	if b == nil {
		return noSuchMailbox
	}
	if b.Account != account {
		switch err := s.store.Adopt(r.Context(), b, account, id); {
		case errors.Is(err, ErrKeyRefused):
			return keyRefused()
		case errors.Is(err, ErrStale):
			return fail(protocol.CodeConflict, "retry: irongall adopt", "the box changed during the request")
		case err != nil:
			return err
		}
	}
	writeJSON(w, http.StatusOK, protocol.AccountResponse{Account: account})
	return nil
}

// leave is DELETE /v1/<address>/account (with the pass): the box leaves its
// account, and has the server's limits again. A box in no account is
// already there.
func (s *Server) leave(w http.ResponseWriter, r *http.Request) error {
	a, err := s.owner(r)
	if err != nil {
		return err
	}
	b, err := s.box(r.Context(), a)
	if err != nil {
		return err
	}
	if b == nil {
		return noSuchMailbox
	}
	if b.Account != "" {
		switch err := s.store.Leave(r.Context(), b); {
		case errors.Is(err, ErrStale):
			return fail(protocol.CodeConflict, "retry: irongall adopt --leave", "the box changed during the request")
		case err != nil:
			return err
		}
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

// limitsFor returns the limits a sender gets: the server's, unless it is in
// an unmetered account, whose boxes have no daily limit and the largest cap.
// A box whose account is gone has the server's.
func (s *Server) limitsFor(ctx context.Context, b *Box) (Limits, error) {
	l := s.limits
	if b.Account == "" {
		return l, nil
	}
	acc, err := s.store.Account(ctx, b.Account)
	if errors.Is(err, ErrNotFound) {
		return l, nil
	}
	if err != nil {
		return l, err
	}
	if acc.Unmetered {
		l.SendsPerDay, l.MaxSize = 0, l.ceiling()
	}
	return l, nil
}

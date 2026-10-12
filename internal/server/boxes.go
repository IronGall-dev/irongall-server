package server

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"net/http"
	"slices"
	"time"

	"github.com/IronGall-dev/irongall-client/protocol"
)

// registerLimit bounds a registration or prekey body: a post-quantum prekey
// statement is ~2 KB, so this is generous.
const registerLimit = 64 << 10

// register is PUT /v1/<address> (PROTOCOL.md §3).
func (s *Server) register(w http.ResponseWriter, r *http.Request) error {
	h, err := pathAddr(r)
	if err != nil {
		return err
	}
	var req protocol.RegisterRequest
	if err := decodeBody(w, r, registerLimit, &req); err != nil {
		return err
	}
	if err := required("identity", req.Identity, "prekey", req.Prekey, "prekey_signature", req.PrekeySignature); err != nil {
		return err
	}
	if protocol.Address(sha256.Sum256(req.Identity)) != h {
		return fail(protocol.CodeIdentityMismatch, "the identity document is \"irongall-v1\", LF, the ssh-ed25519 key with no comment, LF: look for a comment, CRLF or a missing final newline",
			"the identity document does not hash to the address")
	}
	id, err := protocol.ParseIdentity(req.Identity)
	switch {
	case errors.Is(err, protocol.ErrIdentityFormat):
		return fail(protocol.CodeIdentityMismatch, "the identity document is \"irongall-v1\", LF, the ssh-ed25519 key with no comment, LF: look for a comment, CRLF or a missing final newline", "%v", err)
	case err != nil:
		return fail(protocol.CodeBadKey, "make a new identity: irongall init in a new box", "%v", err)
	}
	p, err := s.checkPrekey(id, req.Prekey, req.PrekeySignature)
	if err != nil {
		return err
	}
	if ok, wait := s.regs.take(ipKey(s.clientIP(r)), s.now()); !ok {
		return rateLimited(wait, "too many registrations from this address")
	}

	b := &Box{
		Addr:      h,
		Identity:  req.Identity,
		State:     Pending,
		Statement: req.Prekey,
		Signature: req.PrekeySignature,
		Prekey:    p,
		Created:   s.now(),
	}
	err = s.store.CreateBox(r.Context(), b)
	if err == nil {
		return s.writeToken(w, http.StatusCreated, b)
	}
	if !errors.Is(err, ErrExists) {
		return err
	}
	// An existing box: registration never changes it.
	cur, err := s.box(r.Context(), h)
	if err != nil {
		return err
	}
	switch {
	case cur == nil: // a read that does not see the record yet
		p := fail(protocol.CodeUnavailable, "retry", "this box is being registered")
		p.retryAfter = time.Second
		return p
	case cur.State == Revoked:
		return revoked()
	case cur.State == Closed:
		return fail(protocol.CodeConflict, "closed: reopen it with a new prekey, irongall rekey", "this box is closed")
	case bytes.Equal(cur.Identity, req.Identity) && bytes.Equal(cur.Statement, req.Prekey) && bytes.Equal(cur.Signature, req.PrekeySignature):
		return s.writeToken(w, http.StatusOK, cur) // an identical retry
	}
	return fail(protocol.CodeConflict, "registered: to replace its prekey, irongall rekey", "this address is registered with another prekey")
}

// checkPrekey verifies a prekey statement against the identity, and that it
// could be published now: not expired, valid for at most 33 days.
func (s *Server) checkPrekey(id *protocol.Identity, statement, sig []byte) (*protocol.Prekey, error) {
	p, err := protocol.VerifyPrekey(id, statement, sig)
	if err != nil {
		return nil, fail(protocol.CodeBadKey, "sign a new prekey statement: irongall rekey", "%v", err)
	}
	if err := p.CheckLifetime(s.now()); err != nil {
		return nil, fail(protocol.CodeBadKey, "a prekey is valid for at most 33 days: irongall rekey", "%v", err)
	}
	return p, nil
}

// prekey is PUT /v1/<address>/prekey (PROTOCOL.md §6.4). The authority is the
// identity's signature on a higher serial; no token is needed.
func (s *Server) prekey(w http.ResponseWriter, r *http.Request) error {
	h, err := pathAddr(r)
	if err != nil {
		return err
	}
	var req protocol.PrekeyRequest
	if err := decodeBody(w, r, registerLimit, &req); err != nil {
		return err
	}
	if err := required("prekey", req.Prekey, "prekey_signature", req.PrekeySignature); err != nil {
		return err
	}
	b, err := s.lookup(r, h)
	switch {
	case err != nil:
		return err
	case b == nil:
		return noSuchMailbox
	case b.State == Revoked:
		return revoked()
	}
	id, err := protocol.ParseIdentity(b.Identity)
	if err != nil {
		return err
	}
	p, err := s.checkPrekey(id, req.Prekey, req.PrekeySignature)
	if err != nil {
		return err
	}
	if bytes.Equal(req.Prekey, b.Statement) && bytes.Equal(req.PrekeySignature, b.Signature) {
		return s.writeToken(w, http.StatusOK, b) // an identical retry
	}
	if p.Serial <= b.Prekey.Serial {
		return fail(protocol.CodeConflict, "a newer prekey is already published: irongall rekey takes the next serial", "the serial must be above %d", b.Prekey.Serial)
	}
	now := s.now()
	if ok, wait := s.renewals.add(h, now, s.limits.RenewalsPerDay, false); !ok {
		return rateLimited(wait, "this box has renewed its prekey %d times today", s.limits.RenewalsPerDay)
	}
	keyHash := sha256.Sum256([]byte(p.Key))
	retired := slices.DeleteFunc(b.Retired, func(x Retired) bool { return !now.Before(x.NotAfter) })
	if keyHash == sha256.Sum256([]byte(b.Prekey.Key)) || slices.ContainsFunc(retired, func(x Retired) bool { return x.KeyHash == keyHash }) {
		return fail(protocol.CodeBadKey, "every prekey must be a NEW key: irongall rekey makes one", "this key was already published")
	}
	if now.Before(b.Prekey.NotAfter) {
		retired = append(retired, Retired{Type: b.Prekey.Type(), NotAfter: b.Prekey.NotAfter, KeyHash: sha256.Sum256([]byte(b.Prekey.Key))})
	}
	if n := s.limits.RetiredKept; n > 0 && len(retired) > n {
		retired = retired[len(retired)-n:]
	}
	b.Retired = retired
	b.Statement, b.Signature, b.Prekey = req.Prekey, req.PrekeySignature, p
	b.Epoch++
	if b.State == Closed {
		b.State = Pending // reopened
	}
	if err := s.store.UpdateBox(r.Context(), b); err != nil {
		if errors.Is(err, ErrStale) {
			return fail(protocol.CodeConflict, "retry: irongall rekey", "the box changed during the request")
		}
		return err
	}
	s.renewals.add(h, now, s.limits.RenewalsPerDay, true)
	return s.writeToken(w, http.StatusOK, b)
}

// token is POST /v1/<address>/token: the CURRENT token, encrypted to the
// current prekey. Useless to anyone but the owner, and it never rotates
// anything, so it is limited per IP, never per box.
func (s *Server) token(w http.ResponseWriter, r *http.Request) error {
	h, err := pathAddr(r)
	if err != nil {
		return err
	}
	if ok, wait := s.tokenReqs.take(ipKey(s.clientIP(r)), s.now()); !ok {
		return rateLimited(wait, "too many token requests from this address")
	}
	b, err := s.lookup(r, h)
	switch {
	case err != nil:
		return err
	case b == nil, b.State == Closed:
		return noSuchMailbox
	case b.State == Revoked:
		return revoked()
	}
	return s.writeToken(w, http.StatusOK, b)
}

// identity is GET /v1/<address>/identity. It answers for closed boxes too, so
// an owner can read its own serial to reopen.
func (s *Server) identity(w http.ResponseWriter, r *http.Request) error {
	h, err := pathAddr(r)
	if err != nil {
		return err
	}
	b, err := s.lookup(r, h)
	switch {
	case err != nil:
		return err
	case b == nil:
		return noSuchMailbox
	case b.State == Revoked:
		return revoked()
	}
	writeJSON(w, http.StatusOK, protocol.IdentityResponse{Identity: b.Identity, Prekey: b.Statement, PrekeySignature: b.Signature})
	return nil
}

// closeBox is DELETE /v1/<address> (Bearer): unacked mail is deleted and the
// box marked closed. The identity reopens it with a new prekey.
func (s *Server) closeBox(w http.ResponseWriter, r *http.Request) error {
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
	if err := s.store.DeleteMessages(r.Context(), b.Addr); err != nil {
		return err
	}
	b.State = Closed
	if err := s.store.UpdateBox(r.Context(), b); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

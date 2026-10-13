package server

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/IronGall-dev/irongall-client/protocol"
)

// registerLimit bounds a registration or prekey body: a post-quantum prekey
// statement is ~2 KB, so this is generous.
const registerLimit = 64 << 10

// hintDocument is what to do about an identity document the server does not
// take as one.
const hintDocument = "the identity document is \"irongall-v1\", LF, one SSH public key with no comment, LF: look for a comment, CRLF or a missing final newline"

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
		return fail(protocol.CodeIdentityMismatch, hintDocument, "the identity document does not hash to the address")
	}
	// The document's form, then its key's type, then its key (PROTOCOL.md §3).
	// A well-formed document of a type the protocol does not define, or that
	// this server does not register, is neither malformed nor a bad key.
	id, err := protocol.ParseIdentity(req.Identity)
	switch {
	case errors.Is(err, protocol.ErrIdentityFormat):
		return fail(protocol.CodeIdentityMismatch, hintDocument, "%v", err)
	case errors.Is(err, protocol.ErrIdentityType), err == nil && !slices.Contains(s.identityTypes, id.Type()):
		return fail(protocol.CodeUnsupportedKeyType, "make a box whose identity is an ssh-ed25519 key, as irongall init does unless told otherwise",
			"this server registers identities of these key types: %s", strings.Join(s.identityTypes, ", "))
	case err != nil:
		return fail(protocol.CodeBadKey, "make a new identity: irongall init in a new box", "%v", err)
	}
	p, cert, err := s.checkPrekey(id, req.Prekey, req.PrekeySignature)
	if err != nil {
		return err
	}
	// The pass, under the certificate the statement is signed under: the
	// certificate shows the identity chose this working key, and a pass
	// minutes old that its holder is here now.
	if err := s.checkPass(r, h, string(id.PublicKey().Marshal()), certHash(cert), nil); err != nil {
		return err
	}
	if ok, wait := s.regs.take(ipKey(s.clientIP(r)), s.now()); !ok {
		return rateLimited(wait, "too many registrations from this address")
	}

	b := &Box{
		Addr:           h,
		Identity:       req.Identity,
		State:          Active,
		Statement:      req.Prekey,
		Signature:      req.PrekeySignature,
		Prekey:         p,
		CertSerial:     cert.Serial(),
		Cert:           certHash(cert),
		SenderKeyTypes: declared(req.SenderKeyTypes),
		Created:        s.now(),
	}
	err = s.store.CreateBox(r.Context(), b)
	if err == nil {
		writeJSON(w, http.StatusCreated, struct{}{})
		return nil
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
		writeJSON(w, http.StatusOK, struct{}{}) // an identical retry
		return nil
	}
	return fail(protocol.CodeConflict, "registered: to replace its prekey, irongall rekey", "this address is registered with another prekey")
}

// checkPrekey verifies a prekey statement: signed by a working key under a
// certificate of the identity that is valid now, and one that could be
// published now, not expired and ending at most protocol.MaxPrekeyLifetime
// from now, which is an hour past what a client asks for. It returns the
// certificate too.
//
// A refusal for a time states what this clock reads: a client makes its
// certificate and its statement with an hour of room (PROTOCOL.md §0), so
// one of these is nearly always the caller's clock, and a new statement
// signed by the same clock would be refused the same way.
func (s *Server) checkPrekey(id *protocol.Identity, statement, sig []byte) (*protocol.Prekey, *protocol.Certificate, error) {
	const ahead = "this machine's clock reads more than an hour ahead of the server's: check it, then irongall init for a new box, irongall rekey for one in use"
	p, cert, err := protocol.VerifyPrekey(id, statement, sig, s.now())
	switch {
	case errors.Is(err, protocol.ErrCertificateNotBegun):
		return nil, nil, fail(protocol.CodeBadKey, "a certificate starts an hour before it is made, so "+ahead, "%v; %s", err, s.clock())
	case errors.Is(err, protocol.ErrCertificateTime):
		return nil, nil, fail(protocol.CodeBadKey, "sign a new prekey statement: irongall rekey", "%v; %s", err, s.clock())
	case err != nil:
		return nil, nil, fail(protocol.CodeBadKey, "sign a new prekey statement: irongall rekey", "%v", err)
	}
	if err := p.CheckLifetime(s.now()); err != nil {
		if p.Expired(s.now()) {
			return nil, nil, fail(protocol.CodeBadKey, "sign a new prekey statement: irongall rekey", "%v; %s", err, s.clock())
		}
		return nil, nil, fail(protocol.CodeBadKey, "a client signs a prekey for 33 days, so "+ahead, "%v; %s", err, s.clock())
	}
	return p, cert, nil
}

// prekey is PUT /v1/<address>/prekey (PROTOCOL.md §6.4). The authority is a
// statement ordered after the current one, signed under a certificate of the
// identity, with a pass under that same certificate: no pass under the box's
// current one is needed, which is how a box that lost its working key comes
// back.
//
// A box's statements are ordered by their certificate's serial first and by
// their own serial second (PROTOCOL.md §2b). So a prekey published at the
// highest serial there is, by whoever took a working key, holds nothing: the
// box's next certificate passes it.
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
	p, cert, err := s.checkPrekey(id, req.Prekey, req.PrekeySignature)
	if err != nil {
		return err
	}
	// A certificate the identity has revoked signs nothing this server
	// takes: not the statement, and not the pass that comes with it
	// (PROTOCOL.md §6.3a). That holds for the box's current statement sent
	// again, too.
	if listed, err := b.listed(cert.Serial()); err != nil {
		return err
	} else if listed {
		return fail(protocol.CodeBadKey, "certify a new working key at a higher serial: irongall rekey", "the statement is signed under a certificate this box's identity revoked")
	}
	under := certHash(cert)
	if err := s.checkPass(r, h, string(id.PublicKey().Marshal()), under, nil); err != nil {
		return err
	}
	if bytes.Equal(req.Prekey, b.Statement) && bytes.Equal(req.PrekeySignature, b.Signature) {
		writeJSON(w, http.StatusOK, struct{}{}) // an identical retry: nothing changes
		return nil
	}
	// The box moves to a later certificate, at any prekey serial, or stays
	// under its current one at a higher serial: never back to an older
	// certificate, and never to another of the same serial.
	if cert.Serial() < b.CertSerial || (cert.Serial() == b.CertSerial && under != b.Cert) {
		return fail(protocol.CodeBadKey, "certify a new working key at a higher serial: irongall rekey", "the certificate's serial must be above %d, or the certificate be the box's current one", b.CertSerial)
	}
	if cert.Serial() == b.CertSerial && p.Serial <= b.Prekey.Serial {
		return fail(protocol.CodeConflict, "a newer prekey is already published: irongall rekey takes the next serial", "under the box's current certificate the serial must be above %d", b.Prekey.Serial)
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
	b.CertSerial, b.Cert = cert.Serial(), under
	b.SenderKeyTypes = declared(req.SenderKeyTypes) // the declaration that comes with this prekey, in place of the one before
	b.State = Active                                // a closed box reopens
	if err := s.store.UpdateBox(r.Context(), b); err != nil {
		if errors.Is(err, ErrStale) {
			return fail(protocol.CodeConflict, "retry: irongall rekey", "the box changed during the request")
		}
		return err
	}
	s.renewals.add(h, now, s.limits.RenewalsPerDay, true)
	writeJSON(w, http.StatusOK, struct{}{})
	return nil
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
	writeJSON(w, http.StatusOK, protocol.IdentityResponse{Identity: b.Identity, Prekey: b.Statement, PrekeySignature: b.Signature, SenderKeyTypes: b.SenderKeyTypes})
	return nil
}

// What to do about a body that is not a revocation, or not a list.
const (
	hintRevocation   = "a revocation is the identity key's own signature over its fixed statement, with the identity document: irongall revocation makes the record"
	hintRevokedCerts = "a list of revoked certificates is signed by the identity key itself, and sent with the identity document: irongall rekey --revoke-earlier makes and publishes one"
)

// revoke is PUT /v1/<address>/revocations: the identity document with what
// the identity itself has signed about the address. No pass: a working key
// can be stolen without the identity and must not be able to end the address
// or to revoke a certificate, and an owner who lost the box holds no working
// key at all. The signature is the whole authority, and it may have been made
// long ago.
//
// A revocation of the address (PROTOCOL.md §6.3): the box is revoked for
// good, its mail is deleted, and the signature is kept and served
// (revocations). A second revocation of a revoked box is answered 200 and
// changes nothing.
//
// A list of revoked certificates (PROTOCOL.md §6.3a): the address goes on.
// It is the whole list each time, and the highest version stands: a list
// that is not above the one held is refused, and the same list again changes
// nothing. From then on no pass and no prekey statement under a listed
// certificate is taken, and nobody is told to encrypt to a prekey under one.
//
// A body may carry both. Everything in it is checked before anything is
// changed. A body that does not verify counts against the caller's address
// as a lookup of a box that does not exist does (-misses-per-minute): each
// costs the server a signature check that nothing else has paid for.
func (s *Server) revoke(w http.ResponseWriter, r *http.Request) error {
	h, err := pathAddr(r)
	if err != nil {
		return err
	}
	var req protocol.Revocations
	if err := decodeBody(w, r, registerLimit, &req); err != nil {
		return err
	}
	if err := required("identity", req.Identity); err != nil {
		return err
	}
	hasList := req.RevokedCertificates != nil || req.RevokedCertificatesSignature != nil
	if hasList {
		err = required("revoked_certificates", req.RevokedCertificates, "revoked_certificates_signature", req.RevokedCertificatesSignature)
	} else {
		err = required("revocation", req.Revocation)
	}
	if err != nil {
		return err
	}
	if protocol.Address(sha256.Sum256(req.Identity)) != h {
		return fail(protocol.CodeIdentityMismatch, hintDocument, "the identity document does not hash to the address")
	}
	b, err := s.lookup(r, h)
	switch {
	case err != nil:
		return err
	case b == nil:
		return noSuchMailbox
	}
	ip, now := ipKey(s.clientIP(r)), s.now()
	if ok, wait := s.misses.ready(ip, now); !ok {
		return rateLimited(wait, "too many requests from this address that named no box or carried no revocation")
	}
	var list *protocol.RevokedCertificates
	if hasList {
		if list, err = protocol.VerifyRevokedCertificates(h, req.Identity, req.RevokedCertificates, req.RevokedCertificatesSignature); err != nil {
			s.misses.take(ip, now)
			return fail(protocol.CodeBadRevocation, hintRevokedCerts, "this is not a list of this address's revoked certificates")
		}
	}
	if req.Revocation != nil {
		if _, err := protocol.VerifyRevocation(h, req.Identity, req.Revocation); err != nil {
			s.misses.take(ip, now)
			return fail(protocol.CodeBadRevocation, hintRevocation, "this is not a revocation of this address")
		}
	}
	// A revoked box takes no list: its address is ended, and the list says
	// which of its certificates still stand.
	if b.State == Revoked && req.Revocation == nil {
		return revoked()
	}
	status, changed := http.StatusOK, false
	if list != nil && b.State != Revoked && !bytes.Equal(req.RevokedCertificates, b.RevokedCerts) {
		if len(b.RevokedCerts) > 0 {
			held, err := protocol.ParseRevokedCertificates(b.RevokedCerts)
			if err != nil {
				return fmt.Errorf("the stored list of revoked certificates: %w", err)
			}
			if list.Version <= held.Version {
				return fail(protocol.CodeConflict, "sign the whole list again under a version above the one held", "a list of version %d is held, and a later one must be above it", held.Version)
			}
		}
		b.RevokedCerts, b.RevokedCertsSig, changed = req.RevokedCertificates, req.RevokedCertificatesSignature, true
	}
	if req.Revocation != nil && b.State != Revoked {
		b.State, b.Revocation = Revoked, req.Revocation
		status, changed = http.StatusCreated, true
	}
	if changed {
		if err := s.store.UpdateBox(r.Context(), b); err != nil {
			if errors.Is(err, ErrStale) {
				return fail(protocol.CodeConflict, "retry", "the box changed during the request")
			}
			return err
		}
	}
	// After the record says revoked, and again on every retry: mail that
	// arrived around the write is never served, and this deletes it sooner
	// than its expiry would.
	if b.State == Revoked {
		if err := s.store.DeleteMessages(r.Context(), b.Addr); err != nil {
			return err
		}
	}
	writeJSON(w, status, struct{}{})
	return nil
}

// revocations is GET /v1/<address>/revocations: what this server holds that
// the address's identity signed about it, which is its revocation, its list
// of revoked certificates, both or neither. It asks for no pass and tells
// nothing a 410 or a refused pass does not already tell; what it adds is the
// proof.
func (s *Server) revocations(w http.ResponseWriter, r *http.Request) error {
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
	}
	rec := protocol.Revocations{Identity: b.Identity, RevokedCertificates: b.RevokedCerts, RevokedCertificatesSignature: b.RevokedCertsSig}
	if b.State == Revoked {
		rec.Revocation = b.Revocation
	}
	if len(rec.Revocation) == 0 && len(rec.RevokedCertificates) == 0 {
		return fail(protocol.CodeNotRevoked, "nothing to do: this server holds no revocation of that address", "no revocation of this address is held here")
	}
	writeJSON(w, http.StatusOK, rec)
	return nil
}

// closeBox is DELETE /v1/<address> (with the pass): unacked mail is deleted
// and the box marked closed. A new prekey reopens it.
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

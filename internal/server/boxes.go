package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"time"

	"github.com/IronGall-dev/irongall-client/protocol"
)

// registerLimit bounds a registration or prekey body: a post-quantum prekey
// statement is ~2 KB, so this is generous.
const registerLimit = 64 << 10

// hintDocument is what to do about an identity document the server does not
// take as one.
const hintDocument = "the identity document is \"irongall-v1\", LF, one SSH public key with no comment, LF: look for a comment, CRLF or a missing final newline"

// register is PUT /v1/<address> (PROTOCOL.md §3). It is a call of a box that
// does not exist yet, so its address pays for it: the statement and the pass
// it carries are checked only for a box this process does not already hold,
// after the address's count of registrations.
//
// A registration is held to what is kept of the address, box or none: 410
// while the address is revoked, nothing under a certificate its identity
// revoked, and, while a deleted box's record is kept, a later certificate
// than its last and a key it never published, which undoes the delete.
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
		return failErr(protocol.CodeIdentityMismatch, hintDocument, err)
	case errors.Is(err, protocol.ErrIdentityType), err == nil && !slices.Contains(s.identityTypes, id.Type()):
		return fail(protocol.CodeUnsupportedKeyType, "make a box whose identity is an ssh-ed25519 key, as irongall init does unless told otherwise",
			"this server registers identities of these key types: %s", keyTypesValue(s.identityTypes))
	case err != nil:
		return failErr(protocol.CodeBadKey, "make a new identity: irongall init in a new box", err)
	}
	// Registration never changes a box, so a box this process holds is
	// answered from its record, before anything that costs is checked; so is
	// an address its identity revoked.
	if cur, ok := s.store.Known(h); ok && settled(cur) {
		return s.registered(w, r, id, cur, &req)
	}
	if ok, wait := s.regs.take(ipKey(s.clientIP(r)), s.now()); !ok {
		return rateLimited(wait, "too many registrations from this address")
	}
	// The count just taken bounds what follows: no count of misses is needed.
	p, cert, err := s.checkPrekey(id, req.Prekey, req.PrekeySignature)
	if err != nil {
		return err
	}
	cur, err := s.box(r.Context(), h)
	switch {
	case err != nil:
		return err
	case settled(cur):
		return s.registered(w, r, id, cur, &req)
	case cur != nil:
		if listed, err := cur.listed(cert.Serial()); err != nil {
			return err
		} else if listed {
			return fail(protocol.CodeCertificateRevoked, "certify a new working key at a higher serial: irongall prekey renew", "the statement is signed under a certificate this address's identity revoked")
		}
	}
	if cur != nil && cur.State == Deleted && cert.Serial() <= cur.CertSerial {
		return fail(protocol.CodeCertificateNotCurrent, "certify a new working key at a higher serial: irongall prekey renew", "the certificate's serial must be above %d, the last this deleted box had", certificateSerialValue(cur.CertSerial))
	}
	// The pass, under the certificate the statement is signed under: the
	// certificate shows the identity chose this working key, and a pass
	// minutes old that its holder is here now.
	if err := s.checkPassBounded(r, h, string(id.PublicKey().Marshal()), certHash(cert)); err != nil {
		return err
	}
	now := s.now()
	if cur != nil && cur.State == Deleted {
		return s.undelete(w, r, cur, &req, p, cert, now)
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
		Created:        now,
		Expires:        expiry(p, cert),
	}
	if cur != nil { // an address whose identity revoked certificates: what it revoked is kept with the box
		b.RevokedCerts, b.RevokedCertsSig = cur.RevokedCerts, cur.RevokedCertsSig
	}
	err = s.store.CreateBox(r.Context(), b)
	if err == nil {
		writeJSON(w, http.StatusCreated, struct{}{})
		return nil
	}
	if !errors.Is(err, ErrExists) {
		return err
	}
	if cur, err = s.box(r.Context(), h); err != nil {
		return err
	}
	if !settled(cur) { // a read that does not see the record yet, or a box deleted meanwhile
		p := fail(protocol.CodeUnavailable, "retry", "this box is being registered")
		p.retryAfter = time.Second
		return p
	}
	return s.registered(w, r, id, cur, &req)
}

// settled reports whether what is held of an address answers a registration
// from itself: a box that is registered, or an address that is revoked.
func settled(b *Box) bool { return b.open() || b != nil && b.State == Revoked }

// registered answers a registration of a box that is registered, or of an
// address that is revoked, from its record: registration never changes it.
// An identical retry is answered 200 once its pass, under the box's current
// certificate, is checked; nothing else is. A pass the server remembers costs
// no check, and one that does not verify counts against the caller's address
// (checkPassBounded).
func (s *Server) registered(w http.ResponseWriter, r *http.Request, id *protocol.Identity, cur *Box, req *protocol.RegisterRequest) error {
	switch {
	case cur.State == Revoked:
		return revoked()
	case !bytes.Equal(cur.Identity, req.Identity) || !bytes.Equal(cur.Statement, req.Prekey) || !bytes.Equal(cur.Signature, req.PrekeySignature):
		return fail(protocol.CodeConflict, "registered: to replace its prekey, irongall prekey renew", "this address is registered with another prekey")
	}
	if err := s.checkPassBounded(r, cur.Addr, string(id.PublicKey().Marshal()), cur.Cert); err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, struct{}{}) // an identical retry
	return nil
}

// undelete is a registration of deleted box b while its record is kept
// (PROTOCOL.md §3 step 5): it undoes the delete. The box comes back as it
// was, its ACL and its account with it, under the new statement, which is
// taken as a renewal's is: under a later certificate than the box's last
// (register checked that), and with a key it never published.
func (s *Server) undelete(w http.ResponseWriter, r *http.Request, b *Box, req *protocol.RegisterRequest, p *protocol.Prekey, cert *protocol.Certificate, now time.Time) error {
	if err := s.take(b, req.Prekey, req.PrekeySignature, p, cert, req.SenderKeyTypes, now); err != nil {
		return err
	}
	b.State = Active
	if err := s.store.UpdateBox(r.Context(), b); err != nil {
		if errors.Is(err, ErrStale) {
			return fail(protocol.CodeBoxChanged, "retry: irongall init", "the box changed during the request")
		}
		return err
	}
	writeJSON(w, http.StatusCreated, struct{}{})
	return nil
}

// take makes p, under cert, box b's current prekey statement (PROTOCOL.md
// §6.4): a key the box published before, its current one or a live retired
// one, is refused; the statement it replaces retires while it is live, and
// only the newest retired are kept. The record's expiry moves to when
// nothing of the new statement is valid.
func (s *Server) take(b *Box, statement, sig []byte, p *protocol.Prekey, cert *protocol.Certificate, senders []string, now time.Time) error {
	keyHash := sha256.Sum256([]byte(p.Key))
	retired := slices.DeleteFunc(b.Retired, func(x Retired) bool { return !now.Before(x.NotAfter) })
	if keyHash == sha256.Sum256([]byte(b.Prekey.Key)) || slices.ContainsFunc(retired, func(x Retired) bool { return x.KeyHash == keyHash }) {
		return fail(protocol.CodePrekeyNotNew, "every prekey must be a NEW key: irongall prekey renew makes one", "this key was already published")
	}
	if now.Before(b.Prekey.NotAfter) {
		retired = append(retired, Retired{Type: b.Prekey.Type(), NotAfter: b.Prekey.NotAfter, KeyHash: sha256.Sum256([]byte(b.Prekey.Key))})
	}
	if n := s.limits.RetiredKept; n > 0 && len(retired) > n {
		retired = retired[len(retired)-n:]
	}
	b.Retired = retired
	b.Statement, b.Signature, b.Prekey = statement, sig, p
	b.CertSerial, b.Cert = cert.Serial(), certHash(cert)
	b.SenderKeyTypes = declared(senders) // the declaration that comes with this prekey, in place of the one before
	b.Expires = expiry(p, cert)
	return nil
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
	const ahead = "this machine's clock reads more than an hour ahead of the server's: check it, then irongall init for a new box, irongall prekey renew for one in use"
	p, cert, err := protocol.VerifyPrekey(id, statement, sig, s.now())
	switch {
	case errors.Is(err, protocol.ErrCertificateNotBegun):
		return nil, nil, failErr(protocol.CodePrekeyTime, "a certificate starts an hour before it is made, so "+ahead, err)
	case errors.Is(err, protocol.ErrCertificateTime):
		return nil, nil, failErr(protocol.CodePrekeyTime, "sign a new prekey statement: irongall prekey renew", err)
	case err != nil:
		return nil, nil, failErr(protocol.CodeBadKey, "sign a new prekey statement: irongall prekey renew", err)
	}
	if err := p.CheckLifetime(s.now()); err != nil {
		if p.Expired(s.now()) {
			return nil, nil, failErr(protocol.CodePrekeyTime, "sign a new prekey statement: irongall prekey renew", err)
		}
		return nil, nil, failErr(protocol.CodePrekeyTime, "a client signs a prekey for 33 days, so "+ahead, err)
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
//
// What could not be taken even if it verified is refused before any
// signature is checked: the statement's place in that order is read from it
// unverified (protocol.PrekeyOrder), and a statement the box holds already is
// answered from its record.
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
	case b != nil && b.State == Revoked:
		return revoked()
	case !b.open(): // a deleted box comes back by a registration
		return noSuchMailbox
	}
	id, err := protocol.ParseIdentity(b.Identity)
	if err != nil {
		return err
	}
	key := string(id.PublicKey().Marshal())
	refusedRevoked := fail(protocol.CodeCertificateRevoked, "certify a new working key at a higher serial: irongall prekey renew", "the statement is signed under a certificate this box's identity revoked")
	// An identical retry: it was verified when it was stored, so only its
	// pass is checked, and nothing changes. A certificate the identity has
	// revoked signs nothing this server takes, the box's current statement
	// sent again included (PROTOCOL.md §6.3a).
	if bytes.Equal(req.Prekey, b.Statement) && bytes.Equal(req.PrekeySignature, b.Signature) {
		if listed, err := b.listed(b.CertSerial); err != nil {
			return err
		} else if listed {
			return refusedRevoked
		}
		if err := s.checkPass(r, h, key, b.Cert, nil); err != nil {
			return err
		}
		if err := s.spendOwner(r.Context(), h); err != nil {
			return err
		}
		writeJSON(w, http.StatusOK, struct{}{})
		return nil
	}
	// Where it would stand, read before anything is verified. The box moves
	// to a later certificate, at any prekey serial, or stays under its
	// current one at a higher serial: never back to an older certificate,
	// never to another of the same serial, and never to one its identity
	// has revoked.
	o, err := protocol.PrekeyOrder(req.Prekey, req.PrekeySignature)
	if err != nil {
		if err := s.failed(r); err != nil {
			return err
		}
		return failErr(protocol.CodeBadKey, "sign a new prekey statement: irongall prekey renew", err)
	}
	if listed, err := b.listed(o.CertSerial); err != nil {
		return err
	} else if listed {
		return refusedRevoked
	}
	if o.CertSerial < b.CertSerial || (o.CertSerial == b.CertSerial && o.Cert != b.Cert) {
		return fail(protocol.CodeCertificateNotCurrent, "certify a new working key at a higher serial: irongall prekey renew", "the certificate's serial must be above %d, or the certificate be the box's current one", certificateSerialValue(b.CertSerial))
	}
	if o.CertSerial == b.CertSerial && o.Serial <= b.Prekey.Serial {
		return fail(protocol.CodeConflict, "a newer prekey is already published: irongall prekey renew takes the next serial", "under the box's current certificate the serial must be above %d", prekeySerialValue(b.Prekey.Serial))
	}
	m, err := s.miss(r)
	if err != nil {
		return err
	}
	p, cert, err := s.checkPrekey(id, req.Prekey, req.PrekeySignature)
	if err == nil && (cert.Serial() != o.CertSerial || certHash(cert) != o.Cert || p.Serial != o.Serial) {
		err = fail(protocol.CodeBadKey, "sign a new prekey statement: irongall prekey renew", "the statement does not read the same verified as unverified")
	}
	if err != nil {
		m.keep()
		return err
	}
	m.release(s.now())
	under := certHash(cert)
	if err := s.checkPass(r, h, key, under, nil); err != nil {
		return err
	}
	if err := s.spendOwner(r.Context(), h); err != nil {
		return err
	}
	// A renewal under the box's current certificate counts against the
	// box's renewals; one under a later certificate is its identity's act,
	// counted apart, so whoever holds the current working key and spends the
	// day's renewals does not hold back the identity's. One while the box's
	// current certificate is revoked is not counted: it replaces what the
	// identity revoked, each raise of which is counted (revoke), as Let's
	// Encrypt exempts a renewal that names the certificate it replaces.
	now := s.now()
	count, limit, code, what := &s.renewals, s.limits.RenewalsPerDay, protocol.CodeRenewalsSpent, "this box has renewed its prekey %d times today"
	if cert.Serial() > b.CertSerial {
		count, limit, code, what = &s.certs, s.limits.CertificatesPerDay, protocol.CodeCertificatesSpent, "this box's identity has certified %d new working keys today"
		if replaces, err := b.listed(b.CertSerial); err != nil {
			return err
		} else if replaces {
			limit = 0 // never limits, and nothing is taken to give back
		}
	}
	if ok, wait := count.take(h, now, limit); !ok {
		return spent(code, wait, what, limitValue(limit))
	}
	stored := false
	defer func() {
		if !stored {
			count.give(h, now, limit)
		}
	}()
	if err := s.take(b, req.Prekey, req.PrekeySignature, p, cert, req.SenderKeyTypes, now); err != nil {
		return err
	}
	if err := s.store.UpdateBox(r.Context(), b); err != nil {
		if errors.Is(err, ErrStale) {
			return fail(protocol.CodeBoxChanged, "retry: irongall prekey renew", "the box changed during the request")
		}
		return err
	}
	stored = true
	writeJSON(w, http.StatusOK, struct{}{})
	return nil
}

// getBox is GET /v1/<address>, the one read of a box: everything a sender
// needs before it posts, which is the identity document, the current prekey
// statement with its signature, the key types the box declared with it, and
// the revocation of its certificates held (PROTOCOL.md §4.1). A revoked
// address is 410 with its record, which proves itself: a client takes
// "revoked" on nothing less, and needs no second call for it. A deleted box,
// and an address with no box whose identity revoked certificates, are 404.
// Like every lookup it takes a pass or none (spendLookup).
func (s *Server) getBox(w http.ResponseWriter, r *http.Request) error {
	if err := s.spendLookup(r); err != nil {
		return err
	}
	h, err := pathAddr(r)
	if err != nil {
		return err
	}
	b, err := s.lookup(r, h)
	switch {
	case err != nil:
		return err
	case b != nil && b.State == Revoked:
		return revokedWith(&protocol.Revocations{Identity: b.Identity, Revocation: b.Revocation, RevokedCertificates: b.RevokedCerts, RevokedCertificatesSignature: b.RevokedCertsSig})
	case !b.open():
		return noSuchMailbox
	}
	writeJSON(w, http.StatusOK, protocol.BoxResponse{
		Identity: b.Identity, Prekey: b.Statement, PrekeySignature: b.Signature, SenderKeyTypes: b.SenderKeyTypes,
		RevokedCertificates: b.RevokedCerts, RevokedCertificatesSignature: b.RevokedCertsSig,
	})
	return nil
}

// getRevocations is GET /v1/<address>/revocations, a revocation server's read
// (PROTOCOL.md §6.3): the record this server holds of the address, or 404
// not_revoked. Every mailbox server is a revocation server. A box learns the
// same of the boxes it writes to from their read (getBox); this route is for
// a client that lists this server as one of its revocation servers. It takes
// no pass, as the PUT beside it takes none.
func (s *Server) getRevocations(w http.ResponseWriter, r *http.Request) error {
	h, err := pathAddr(r)
	if err != nil {
		return err
	}
	b, err := s.lookup(r, h)
	switch {
	case err != nil:
		return err
	case b == nil || len(b.Revocation) == 0 && len(b.RevokedCerts) == 0:
		return fail(protocol.CodeNotRevoked, "nothing to do: this server holds no revocation of that address. That is its word, and another server or the box's owner may hold one", "no revocation of this address is held here")
	}
	writeJSON(w, http.StatusOK, &protocol.Revocations{Identity: b.Identity, Revocation: b.Revocation, RevokedCertificates: b.RevokedCerts, RevokedCertificatesSignature: b.RevokedCertsSig})
	return nil
}

// What to do about a body that is not a revocation of the address, or not
// one of its certificates.
const (
	hintRevocation   = "a revocation is the identity key's own signature over its fixed statement, with the identity document: irongall revocation make prints the record"
	hintRevokedCerts = "a revocation of certificates is signed by the identity key itself, and sent with the identity document: irongall cert revoke-earlier makes and publishes one"
)

// revoke is PUT /v1/<address>/revocations: the identity document with what
// the identity itself has signed about the address. No pass: a working key
// can be stolen without the identity and must not be able to end the address
// or to revoke a certificate, and an owner who lost the box holds no working
// key at all. The signature is the whole authority, and it may have been made
// long ago. So the call is its address's to pay for, as every call with no
// pass is.
//
// What is revoked is kept with or without a box, in the address's
// revocations item, for good: for a box that is registered, deleted, swept
// by the TTL or never registered. Keeping it for an address this server
// holds nothing of is a record kept for good, so that one is counted as a
// registration is, against its caller's address.
//
// A revocation of the address (PROTOCOL.md §6.3): the address is revoked
// for good, its box's mail and record are deleted, and the signature is kept
// and served (revocations).
//
// A revocation of certificates (PROTOCOL.md §6.3a): the address goes on.
// It revokes every certificate through a serial, and the highest stands: one
// through a lower serial than the one held is refused, and the same one again
// changes nothing. From then on no pass and no prekey statement under a
// revoked certificate is taken, and nobody is told to encrypt to a prekey
// under one. A raise of it is the identity's act, counted per box on its own
// (Limits.CertificateRevocationsPerDay), so no renewal holds it back; the
// renewal that replaces the certificate it revokes is then not counted
// (prekey). The revocation of the address is counted against no box.
//
// A body may carry both. What could change nothing is answered from the
// record before any signature is checked: anything for a box already
// revoked, and a revocation of certificates through a serial no higher than
// the one held. Both kinds of statement are public, and more than one set of
// bytes verifies for each, so one sent back must cost no signature check.
// Everything else in the body is checked before anything is changed, and a
// check that fails counts against the caller's address (s.miss).
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
	hasCerts := req.RevokedCertificates != nil || req.RevokedCertificatesSignature != nil
	if hasCerts {
		err = required("revoked_certificates", req.RevokedCertificates, "revoked_certificates_signature", req.RevokedCertificatesSignature)
	} else {
		err = required("revocation_signature", req.Revocation)
	}
	if err != nil {
		return err
	}
	if protocol.Address(sha256.Sum256(req.Identity)) != h {
		return fail(protocol.CodeIdentityMismatch, hintDocument, "the identity document does not hash to the address")
	}
	b, err := s.lookup(r, h)
	if err != nil {
		return err
	}
	// A revoked address takes nothing more: it is ended, and that says which
	// of its certificates still stand. Its box's mail and record are deleted
	// again while memory shows them, as they are when the first delete
	// failed: a revocation sent back must not draw a read of the messages
	// table each time.
	if b != nil && b.State == Revoked {
		if err := s.deleteHeld(r.Context(), b); err != nil {
			return err
		}
		return revoked()
	}
	var held *protocol.RevokedCertificates
	if b != nil && len(b.RevokedCerts) > 0 {
		if held, err = protocol.ParseRevokedCertificates(b.RevokedCerts); err != nil {
			return fmt.Errorf("the stored revocation of certificates: %w", err)
		}
	}
	// A revocation of certificates that reaches no higher than the one held
	// changes nothing, whether or not it verifies: read before it is checked.
	if hasCerts && held != nil {
		if f, err := protocol.ParseRevokedCertificates(req.RevokedCertificates); err == nil && f.Address == h && f.Through <= held.Through {
			switch {
			case req.Revocation != nil:
				hasCerts = false // the revocation of the address is the body's one change
			case f.Through == held.Through:
				writeJSON(w, http.StatusOK, struct{}{})
				return nil
			default:
				return fail(protocol.CodeConflict, "GET the same path for the one held: it covers every certificate yours does", "a revocation of this address's certificates through serial %d is held, and nothing revokes fewer", throughValue(held.Through))
			}
		}
	}
	if b == nil {
		if ok, wait := s.regs.take(ipKey(s.clientIP(r)), s.now()); !ok {
			return rateLimited(wait, "too many registrations from this address: keeping a revocation of an address this server holds nothing of is counted as one")
		}
	}
	m, err := s.miss(r)
	if err != nil {
		return err
	}
	var certs *protocol.RevokedCertificates
	if hasCerts {
		if certs, err = protocol.VerifyRevokedCertificates(h, req.Identity, req.RevokedCertificates, req.RevokedCertificatesSignature); err != nil {
			m.keep()
			return fail(protocol.CodeBadRevocation, hintRevokedCerts, "this is not a revocation of this address's certificates")
		}
	}
	if req.Revocation != nil {
		if _, err := protocol.VerifyRevocation(h, req.Identity, req.Revocation); err != nil {
			m.keep()
			return fail(protocol.CodeBadRevocation, hintRevocation, "this is not a revocation of this address")
		}
	}
	m.release(s.now())
	now := s.now()
	rv := &Revocations{Identity: req.Identity}
	status, raised := http.StatusOK, false
	if certs != nil && (held == nil || certs.Through > held.Through) {
		rv.Certs, rv.CertsSig, rv.Through, raised = req.RevokedCertificates, req.RevokedCertificatesSignature, certs.Through, true
	}
	if req.Revocation != nil {
		rv.Address, status = req.Revocation, http.StatusCreated
	} else if raised {
		if ok, wait := s.raises.take(h, now, s.limits.CertificateRevocationsPerDay); !ok {
			return spent(protocol.CodeCertificateRevocationsSpent, wait, "this box's identity has raised its revocation of certificates %d times today", limitValue(s.limits.CertificateRevocationsPerDay))
		}
	}
	if raised || req.Revocation != nil {
		if err := s.store.Revoke(r.Context(), h, rv); err != nil {
			if raised && req.Revocation == nil {
				s.raises.give(h, now, s.limits.CertificateRevocationsPerDay)
			}
			if errors.Is(err, ErrStale) {
				return fail(protocol.CodeBoxChanged, "retry", "the box changed during the request")
			}
			return err
		}
	}
	// Once the address is revoked: mail that arrived around the write is
	// never served, this deletes it sooner than its expiry would, and then
	// the box's record goes.
	if req.Revocation != nil && b.hasRecord() {
		if err := s.store.DeleteMessages(r.Context(), h); err != nil {
			return err
		}
		if err := s.store.DeleteBox(r.Context(), h); err != nil {
			return err
		}
	}
	writeJSON(w, status, struct{}{})
	return nil
}

// deleteHeld deletes what is left of revoked address b's box: its mail
// while memory shows the box holding any, and a record left beside the
// revocation, by a delete that failed or a registration that raced it.
func (s *Server) deleteHeld(ctx context.Context, b *Box) error {
	if n, err := s.store.Count(ctx, b.Addr); err != nil {
		return err
	} else if n > 0 {
		if err := s.store.DeleteMessages(ctx, b.Addr); err != nil {
			return err
		}
	}
	if b.hasRecord() {
		return s.store.DeleteBox(ctx, b.Addr)
	}
	return nil
}

// deleteBox is DELETE /v1/<address> (with the pass), the owner's delete
// (PROTOCOL.md §6.2): the box is answered as if it had never been
// registered, and its unacked mail is deleted at once. Its record is kept,
// marked, until its newest certificate ends, so that a registration until
// then is held to it; DynamoDB's TTL takes it after. A registration while it
// is kept undoes the delete (undelete).
func (s *Server) deleteBox(w http.ResponseWriter, r *http.Request) error {
	a, err := s.owner(r)
	if err != nil {
		return err
	}
	if err := s.spendOwner(r.Context(), a); err != nil {
		return err
	}
	b, err := s.box(r.Context(), a)
	switch {
	case err != nil:
		return err
	case b != nil && b.State == Revoked:
		return revoked()
	case !b.open():
		return noSuchMailbox
	}
	id, err := protocol.ParseIdentity(b.Identity)
	if err != nil {
		return err
	}
	_, cert, err := protocol.VerifyPrekeyRecord(id, b.Statement, b.Signature)
	if err != nil {
		return fmt.Errorf("the stored prekey: %w", err)
	}
	if err := s.store.DeleteMessages(r.Context(), a); err != nil {
		return err
	}
	b.State, b.Expires = Deleted, cert.NotAfter()
	if err := s.store.UpdateBox(r.Context(), b); err != nil {
		if errors.Is(err, ErrStale) {
			return fail(protocol.CodeBoxChanged, "retry", "the box changed during the request")
		}
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

package server

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"io"
	"net/http"
	"regexp"
	"time"

	"filippo.io/age"
	"github.com/IronGall-dev/irongall-client/protocol"
)

// send is POST /v1/<recipient> (PROTOCOL.md §4, the server pipeline):
// cheapest check first, and only the last step writes.
func (s *Server) send(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	now := s.now()

	// 1. Size and shape. A body is read before the sender is known, so up
	// to the largest cap any sender has; the sender's own cap is checked
	// once it is (step 4). Past the free cap's size, a read waits for the
	// one allowance for large reads, so junk from anyone cannot fill memory.
	free, limit := readLimit(s.limits.MaxSize), readLimit(s.limits.ceiling())
	if r.ContentLength > limit {
		return fail(protocol.CodeTooLarge, "send less", "the request body is over %d bytes", limit)
	}
	body := http.MaxBytesReader(w, r.Body, limit)
	data, err := io.ReadAll(io.LimitReader(body, free+1))
	if err != nil {
		return readProblem(err, limit)
	}
	if int64(len(data)) > free {
		select {
		case s.largeRead <- struct{}{}:
			defer func() { <-s.largeRead }()
		case <-ctx.Done():
			p := fail(protocol.CodeUnavailable, "retry later", "another large send is being read")
			p.retryAfter = retryLater
			return p
		}
		rest, err := io.ReadAll(body)
		if err != nil {
			return readProblem(err, limit)
		}
		data = append(data, rest...)
	}
	var req protocol.SendRequest
	if err := decodeJSON(data, &req); err != nil {
		return err
	}
	if req.From == "" {
		return fail(protocol.CodeBadRequest, "", "missing field %q", "from")
	}
	if err := required("ciphertext", req.Ciphertext, "signature", req.Signature); err != nil {
		return err
	}
	if len(req.Ciphertext) > s.limits.ceiling() {
		return fail(protocol.CodeTooLarge, "send less", "the ciphertext is over %d bytes", s.limits.ceiling())
	}

	// 2. Addresses, the serial, and the pre-auth rate per IP.
	to, err := pathAddr(r)
	if err != nil {
		return err
	}
	from, err := protocol.ParseAddress(req.From)
	if err != nil {
		return fail(protocol.CodeBadAddress, "from is this box's address in lowercase", "from is not 64 lowercase hex characters")
	}
	if req.PrekeySerial == nil || *req.PrekeySerial < 1 || *req.PrekeySerial > protocol.MaxSerial {
		return fail(protocol.CodeBadRequest, "name the serial of the prekey the ciphertext is encrypted to: irongall send does", "prekey_serial is missing or not a serial")
	}
	if ok, wait := s.sendIPs.take(ipKey(s.clientIP(r)), now); !ok {
		return rateLimited(wait, "too many sends from this address")
	}

	// 3. It is an age file.
	stanzas, err := stanzasOf(req.Ciphertext)
	if err != nil {
		return fail(protocol.CodeNotAge, "encrypt with age to the box's prekey", "the ciphertext is not an age file")
	}

	// 4. Both boxes are registered and active.
	rcpt, err := s.lookup(r, to)
	if err != nil {
		return err
	}
	switch {
	case rcpt == nil, rcpt.State == Closed:
		return noSuchMailbox
	case rcpt.State == Pending:
		return fail(protocol.CodeNoSuchMailbox, "not activated yet: the owner must poll once", "this box is not activated yet")
	case rcpt.State == Revoked:
		return revoked()
	case rcpt.Prekey.Expired(now):
		return fail(protocol.CodePrekeyExpired, "the box's owner must publish a new prekey (irongall rekey); retry later", "this box's prekey has expired")
	}
	sender, err := s.lookup(r, from)
	if err != nil {
		return err
	}
	switch {
	case sender == nil, sender.State != Active && sender.State != Revoked:
		return fail(protocol.CodeUnknownSender, "register your own box and poll it once: irongall init", "the sender is not a registered, active box")
	case sender.State == Revoked:
		return fail(protocol.CodeSenderRevoked, "your box is revoked: make a new one, irongall init", "the sending box is revoked")
	}
	lim, err := s.limitsFor(ctx, sender)
	if err != nil {
		return err
	}
	if len(req.Ciphertext) > lim.MaxSize {
		return fail(protocol.CodeTooLarge, "send less", "the ciphertext is over %d bytes", lim.MaxSize)
	}

	// 5. The prekey and the stanza.
	if *req.PrekeySerial != rcpt.Prekey.Serial {
		return fail(protocol.CodeStalePrekey, "a newer prekey exists: fetch GET /v1/<address>/identity and re-encrypt the same envelope (irongall does this)", "the box's current prekey serial is %d", rcpt.Prekey.Serial)
	}
	if p := checkStanzas(stanzas, rcpt); p != nil {
		return p
	}

	// 6. The signature, against the sender's REGISTERED identity, for this
	// recipient only.
	id, err := protocol.ParseIdentity(sender.Identity)
	if err != nil {
		return err
	}
	if err := protocol.Verify(id, req.Ciphertext, req.Signature, protocol.MessageNamespace(to)); err != nil {
		return fail(protocol.CodeBadSignature, "sign the ciphertext with your identity, namespace irongall-msg-v1:<recipient>", "the signature does not verify for the sender")
	}

	// 7. Dedupe, before any quota: a retry gets the original receipt.
	msgID := sha256.Sum256(req.Ciphertext)
	if orig, err := s.store.Dedupe(ctx, to, msgID); err == nil {
		return s.duplicate(w, orig, from)
	} else if !errors.Is(err, ErrNotFound) {
		return err
	}

	// 8. Quotas, counted only for verified sends.
	if ok, wait := s.sends.add(from, now, lim.SendsPerDay, false); !ok {
		return rateLimited(wait, "this box has sent its %d messages for the day", lim.SendsPerDay)
	}
	if s.limits.PairCap > 0 {
		n, oldest, err := s.store.PairCount(ctx, to, from)
		if err != nil {
			return err
		}
		if n >= s.limits.PairCap {
			p := fail(protocol.CodePairFull, "the box holds the most unacked mail it takes from you: retry after it reads some", "%d unacked messages from this sender", n)
			p.retryAfter = time.Duration(s.limits.PollAfter) * time.Second
			p.unacked, p.oldest = &n, oldest
			return p
		}
	}
	if s.limits.BoxCap > 0 {
		n, _, err := s.store.Count(ctx, to)
		if err != nil {
			return err
		}
		if n >= s.limits.BoxCap {
			p := fail(protocol.CodeMailboxFull, "the box is full: retry later", "the box holds %d messages", n)
			p.retryAfter = time.Duration(s.limits.PollAfter) * time.Second
			return p
		}
	}

	// 9. Write, then count the send.
	h := &Header{
		ID:         msgID,
		From:       from,
		Size:       len(req.Ciphertext),
		ReceivedAt: now.UTC().Truncate(time.Millisecond),
		ExpiresAt:  now.UTC().Truncate(time.Millisecond).Add(protocol.TTL),
		Signature:  req.Signature,
	}
	orig, err := s.store.PutMessage(ctx, to, h, req.Ciphertext)
	if err != nil {
		return err
	}
	if orig != nil {
		return s.duplicate(w, orig, from) // a concurrent send won the dedupe record
	}
	s.sends.add(from, now, lim.SendsPerDay, true)
	writeJSON(w, http.StatusCreated, receipt(h))
	return nil
}

// readLimit is the request body that carries a ciphertext of size bytes:
// base64 plus JSON overhead.
func readLimit(size int) int64 { return int64((size*4+2)/3) + 4<<10 }

func receipt(h *Header) protocol.Receipt {
	return protocol.Receipt{ID: hexID(h.ID), ReceivedAt: formatTime(h.ReceivedAt), ExpiresAt: formatTime(h.ExpiresAt)}
}

// duplicate answers a send whose ciphertext the box already holds, acked or
// not (its dedupe record): the same sender's retry gets the original
// receipt, and another sender a conflict, which claims no delivery.
func (s *Server) duplicate(w http.ResponseWriter, orig *Header, from protocol.Address) error {
	if orig.From != from {
		return fail(protocol.CodeConflict, "", "this ciphertext was already sent by another box")
	}
	writeJSON(w, http.StatusOK, receipt(orig))
	return nil
}

// stanzaRecorder is an age identity that records the header's stanzas and
// matches none: age parses the header, and nothing here parses it again.
type stanzaRecorder struct{ stanzas []*age.Stanza }

func (s *stanzaRecorder) Unwrap(stanzas []*age.Stanza) ([]byte, error) {
	s.stanzas = stanzas
	return nil, age.ErrIncorrectIdentity
}

// stanzasOf returns the stanzas of an age file's header, parsed by age.
func stanzasOf(ciphertext []byte) ([]*age.Stanza, error) {
	hdr, err := age.ExtractHeader(bytes.NewReader(ciphertext))
	if err != nil {
		return nil, err
	}
	rec := &stanzaRecorder{}
	_, err = age.DecryptHeader(hdr, rec)
	var noMatch *age.NoIdentityMatchError
	if !errors.As(err, &noMatch) {
		return nil, errors.New("the header did not parse")
	}
	return rec.stanzas, nil
}

// grease is a stanza type rage, the Rust age crate and pyrage add to every
// file; the age spec says to ignore stanzas it does not recognise.
var grease = regexp.MustCompile(`\A[!-~]{1,8}-grease\z`)

// checkStanzas requires exactly one native stanza, of the current prekey's
// type: a send names the current serial, so no retired prekey is live.
// Grease stanzas are ignored. Which KEY it is encrypted to cannot be checked,
// by design of native age.
func checkStanzas(stanzas []*age.Stanza, b *Box) *problem {
	var native []protocol.KeyType
	for _, st := range stanzas {
		switch {
		case st.Type == string(protocol.PostQuantum) || st.Type == string(protocol.Classic):
			native = append(native, protocol.KeyType(st.Type))
		case grease.MatchString(st.Type) && len(st.Args) <= 4:
		default:
			return fail(protocol.CodeWrongRecipientType, "encrypt to the box's prekey", "the file has a %q stanza", st.Type)
		}
	}
	if len(native) != 1 {
		return fail(protocol.CodeWrongRecipientType, "encrypt to one recipient only", "the file has %d native stanzas", len(native))
	}
	if native[0] == b.Prekey.Type() {
		return nil
	}
	if b.Prekey.Type() == protocol.PostQuantum {
		return fail(protocol.CodeWrongRecipientType, "this box needs age >= 1.3 or age-plugin-pq", "this box is post-quantum and the file is X25519 only")
	}
	return fail(protocol.CodeWrongRecipientType, "this box is --no-pq (X25519 only): re-fetch its prekey", "this box is --no-pq (X25519 only) and the file is post-quantum")
}

package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"net/http"
	"regexp"
	"sync"
	"time"

	"filippo.io/age"
	"github.com/IronGall-dev/irongall-client/protocol"
)

// send is POST /v1/<recipient> (PROTOCOL.md §4.5, the server pipeline):
// cheapest check first, and only the last step writes. Every count is taken
// before the work it guards and given back if that work does not happen.
func (s *Server) send(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	now := s.now()

	// 1. Who is sending: the pass, before the body is read, and then the
	// sender's own budget for calls, which every send spends, a retry
	// included: it bounds everything after it, the dedupe's read among them.
	// The pre-auth rate is per IP, and comes before anything is checked.
	if ok, wait := s.sendIPs.take(ipKey(s.clientIP(r)), now); !ok {
		return rateLimited(wait, "too many sends from this address")
	}
	from, err := s.sender(r)
	if err != nil {
		return err
	}
	if err := s.spendOwner(ctx, from); err != nil {
		return err
	}
	// The pass showed the box exists, so reading its record is no guess at
	// an address: it is not a read lookup would count or refuse.
	sender, err := s.box(ctx, from)
	if err != nil {
		return err
	}
	if sender == nil {
		return fail(protocol.CodeUnknownSender, "register your own box first: irongall init", "the box the pass names is not registered, or is closed")
	}
	lim, err := s.limitsFor(ctx, sender)
	if err != nil {
		return err
	}

	// 2. Size and shape, to the sender's own cap. Past the free cap's size,
	// a read waits for the one allowance for large reads, which only a
	// sender whose cap is larger ever takes.
	free, limit := readLimit(s.limits.MaxSize), readLimit(lim.MaxSize)
	tooLarge := fail(protocol.CodeTooLarge, "send less", "the ciphertext is over %d bytes", limitValue(lim.MaxSize))
	if r.ContentLength > limit {
		return tooLarge
	}
	body := http.MaxBytesReader(w, r.Body, limit)
	readProblem := func(err error) error {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			return tooLarge
		}
		return fail(protocol.CodeBadRequest, "", "the request body could not be read")
	}
	data, err := io.ReadAll(io.LimitReader(body, free+1))
	if err != nil {
		return readProblem(err)
	}
	if int64(len(data)) > free {
		// The wait is bounded as a body is: a send that holds the one large
		// read is cut off by its own deadline (paced), and one waiting for
		// it gives up after BodyTimeout.
		var wait <-chan time.Time // nil, so never, with no bound set
		if s.limits.BodyTimeout > 0 {
			tm := time.NewTimer(s.limits.BodyTimeout)
			defer tm.Stop()
			wait = tm.C
		}
		select {
		case s.largeRead <- struct{}{}:
			defer func() { <-s.largeRead }()
		case <-wait:
			p := fail(protocol.CodeUnavailable, "retry later", "another large send is being read")
			p.retryAfter = retryLater
			return p
		case <-ctx.Done():
			p := fail(protocol.CodeUnavailable, "retry later", "another large send is being read")
			p.retryAfter = retryLater
			return p
		}
		rest, err := io.ReadAll(body)
		if err != nil {
			return readProblem(err)
		}
		data = append(data, rest...)
	}
	var req protocol.SendRequest
	if err := decodeJSON(data, &req); err != nil {
		return err
	}
	if err := required("ciphertext", req.Ciphertext); err != nil {
		return err
	}
	if len(req.Ciphertext) > lim.MaxSize {
		return tooLarge
	}

	// 3. The recipient's address, and the serials.
	to, err := pathAddr(r)
	if err != nil {
		return err
	}
	if req.PrekeySerial == nil || *req.PrekeySerial < 1 || *req.PrekeySerial > protocol.MaxSerial {
		return fail(protocol.CodeBadRequest, "name the serial of the prekey the ciphertext is encrypted to: irongall send does", "%s is missing or not a serial", memberValue("prekey_serial"))
	}
	if req.CertificateSerial == nil || *req.CertificateSerial < 1 || *req.CertificateSerial > protocol.MaxSerial {
		return fail(protocol.CodeBadRequest, "name the serial of the certificate that prekey's statement is signed under: irongall send does", "%s is missing or not a serial", memberValue("certificate_serial"))
	}

	// 4. It is an age file.
	stanzas, err := stanzasOf(req.Ciphertext)
	if err != nil {
		return fail(protocol.CodeNotAge, "encrypt with age to the box's prekey", "the ciphertext is not an age file")
	}

	// 5. The recipient is registered and active.
	rcpt, err := s.lookup(r, to)
	if err != nil {
		return err
	}
	switch {
	case rcpt == nil, rcpt.State == Closed:
		return noSuchMailbox
	case rcpt.State == Revoked:
		return revoked()
	}

	// 6. Dedupe, before anything asks whether the box takes new mail: a
	// retry gets the original receipt, whatever has changed since it was
	// stored, a renewal of the box's prekey included. What those checks
	// keep from the box is new mail, and a retry is none.
	msgID := sha256.Sum256(req.Ciphertext)
	if orig, err := s.store.Dedupe(ctx, to, msgID); err == nil {
		return s.duplicate(w, orig, from)
	} else if !errors.Is(err, ErrNotFound) {
		return err
	}

	// 7. The box takes new mail on this prekey, and from this sender.
	if rcpt.Prekey.Expired(now) {
		return fail(protocol.CodePrekeyExpired, "the box's owner must publish a new prekey (irongall prekey renew); retry later", "this box's prekey has expired")
	}
	// A prekey under a certificate the box's identity has revoked is one
	// nobody may encrypt to. The cure is an expired prekey's: the owner
	// publishes a new one, under a new certificate.
	if listed, err := rcpt.listed(rcpt.CertSerial); err != nil {
		return err
	} else if listed {
		return fail(protocol.CodePrekeyExpired, "the box's owner must publish a new prekey (irongall prekey renew); retry later", "this box's prekey is signed under a certificate its identity revoked")
	}
	// A box takes mail from a sender whose identity its client can verify:
	// one on an Ed25519 key always, and otherwise what it declared with its
	// prekey. Refused here, the sender has an error and no receipt for mail
	// the recipient would have refused on reading it.
	if t := identityType(sender.Identity); !protocol.AcceptsSender(rcpt.SenderKeyTypes, t) {
		return fail(protocol.CodeSenderKeyType, "a box whose identity is an ssh-ed25519 key, as irongall init makes one, can write to any box",
			"this box's client does not verify identities of your box's key type, %s", keyTypeValue(t))
	}
	// A prekey is named by both serials: its own, and its certificate's.
	if *req.PrekeySerial != rcpt.Prekey.Serial || *req.CertificateSerial != rcpt.CertSerial {
		return fail(protocol.CodeStalePrekey, "a newer prekey exists: fetch GET /v1/<address>/identity and re-encrypt the same envelope (irongall does this)", "the box's current prekey is serial %d, under certificate %d", prekeySerialValue(rcpt.Prekey.Serial), certificateSerialValue(rcpt.CertSerial))
	}
	if p := checkStanzas(stanzas, rcpt); p != nil {
		return p
	}

	// 8. First the box's ACL (PROTOCOL.md §6.2): deny, then allow. It is
	// read before any quota is taken, so a refused send spends none of them.
	// One code and one wording whether the sender was denied or is not on an
	// allow list, so a sender cannot tell which.
	if !rcpt.ACL.Admits(from) {
		return fail(protocol.CodeSenderNotAllowed, "nothing the sender can change: its client moves the message to outbox/failed/", "this box's ACL does not let your box send to it")
	}
	// Then quotas, counted only for sends that carried their sender's pass,
	// each taken before the write and given back unless the send is stored:
	// sends in flight at once cannot all pass on one count.
	stored := false
	if ok, wait := s.sends.take(from, now, lim.SendsPerDay); !ok {
		return spent(protocol.CodeSendsSpent, wait, "this box has sent its %d messages for the day", limitValue(lim.SendsPerDay))
	}
	defer func() {
		if !stored {
			s.sends.give(from, now, lim.SendsPerDay)
		}
	}()
	release, p, err := s.reserveCaps(ctx, to, from)
	if err != nil {
		return err
	}
	if p != nil {
		return p
	}
	defer release()
	// The box's own budget for new mail, from every sender together: what
	// keeps one box from taking mail at any rate however many boxes send.
	rlim, err := s.limitsFor(ctx, rcpt)
	if err != nil {
		return err
	}
	if rlim.ReceiveBurst > 0 {
		recv, ok, wait := s.receives.reserve(ctx, to.String(), s.now)
		if !ok {
			p := fail(protocol.CodeMailboxBusy, "the box takes only so much new mail a minute: post it again after Retry-After (irongall outbox flush does)", "the box has taken as much new mail as it takes for now")
			p.retryAfter = wait
			return p
		}
		defer func() {
			if stored {
				recv.keep()
			} else {
				recv.release(s.now())
			}
		}()
	}

	// 9. Write, and the counts above stand.
	h := &Header{
		ID:         msgID,
		From:       from,
		Size:       len(req.Ciphertext),
		ReceivedAt: now.UTC().Truncate(time.Millisecond),
		ExpiresAt:  now.UTC().Truncate(time.Millisecond).Add(protocol.TTL),
	}
	orig, err := s.store.PutMessage(ctx, to, h, req.Ciphertext)
	if err != nil {
		return err
	}
	if orig != nil {
		return s.duplicate(w, orig, from) // a concurrent send won the dedupe record
	}
	stored = true
	writeJSON(w, http.StatusCreated, receipt(h))
	return nil
}

// inFlight is, for each box, the sends this process has let past the pair
// and box caps and not yet stored, kept beside the store's counts and read
// with them under one lock, so sends in flight at once cannot all pass on
// the same counts (IronGall-dev/irongall-server#4). It is this process's
// alone, as every count is (LIMITS.md).
type inFlight struct {
	mu   sync.Mutex
	box  map[protocol.Address]int
	pair map[[2]protocol.Address]int
}

// reserveCaps checks the pair and box caps for one more message from from
// to box to, counting the sends in flight, and counts this one in. release
// takes it out once the send is over: by then a stored message is in the
// store's counts, so a send checked between the two sees both and is
// refused one early, never let past. A refusal is p.
func (s *Server) reserveCaps(ctx context.Context, to, from protocol.Address) (release func(), p *problem, err error) {
	if s.limits.PairCap == 0 && s.limits.BoxCap == 0 {
		return func() {}, nil, nil
	}
	// Load the box first, so what is read under the lock is memory.
	if _, _, err := s.store.Count(ctx, to); err != nil {
		return nil, nil, err
	}
	f := &s.inFlight[to[0]]
	pair := [2]protocol.Address{to, from}
	f.mu.Lock()
	defer f.mu.Unlock()
	if s.limits.PairCap > 0 {
		n, oldest, err := s.store.PairCount(ctx, to, from)
		if err != nil {
			return nil, nil, err
		}
		if n += f.pair[pair]; n >= s.limits.PairCap {
			p := fail(protocol.CodePairFull, "the box holds the most unacked mail it takes from you: retry after it reads some", "%d unacked messages from this sender, the oldest expiring %s", unackedValue(n), oldestValue(oldest))
			p.retryAfter = time.Duration(s.limits.PollAfter) * time.Second
			return nil, p, nil
		}
	}
	if s.limits.BoxCap > 0 {
		n, _, err := s.store.Count(ctx, to)
		if err != nil {
			return nil, nil, err
		}
		if n += f.box[to]; n >= s.limits.BoxCap {
			p := fail(protocol.CodeMailboxFull, "the box is full: retry later", "the box holds %d messages", messagesValue(n))
			p.retryAfter = time.Duration(s.limits.PollAfter) * time.Second
			return nil, p, nil
		}
	}
	if f.box == nil {
		f.box, f.pair = map[protocol.Address]int{}, map[[2]protocol.Address]int{}
	}
	f.box[to]++
	f.pair[pair]++
	return func() {
		f.mu.Lock()
		defer f.mu.Unlock()
		if f.box[to]--; f.box[to] <= 0 {
			delete(f.box, to)
		}
		if f.pair[pair]--; f.pair[pair] <= 0 {
			delete(f.pair, pair)
		}
	}, nil, nil
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
			return fail(protocol.CodeWrongRecipientType, "encrypt to the box's prekey", "the file has a stanza of a type no prekey has")
		}
	}
	if len(native) != 1 {
		return fail(protocol.CodeWrongRecipientType, "encrypt to one recipient only", "the file has more than one native stanza")
	}
	if native[0] == b.Prekey.Type() {
		return nil
	}
	if b.Prekey.Type() == protocol.PostQuantum {
		return fail(protocol.CodeWrongRecipientType, "this box needs age >= 1.3 or age-plugin-pq", "this box is post-quantum and the file is X25519 only")
	}
	return fail(protocol.CodeWrongRecipientType, "this box is --no-pq (X25519 only): re-fetch its prekey", "this box is --no-pq (X25519 only) and the file is post-quantum")
}

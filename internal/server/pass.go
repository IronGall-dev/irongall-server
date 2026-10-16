package server

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/IronGall-dev/irongall-client/protocol"
	"golang.org/x/crypto/ssh"
)

// A box proves itself with a pass it signs for itself (PROTOCOL.md §6.1b):
// the server issues nothing and stores nothing for it. A pass is checked in
// three steps, cheapest first: the certificate it carries against the hash of
// the box's current one, which costs no signature check; the working key's
// signature on the pass; and then the identity's signature on the
// certificate, with every rule of a certificate, as when it was put on
// record. So a pass that is not the box's costs at most one signature check
// to refuse, and one that is costs two. A pass that passed is remembered
// until it runs out, and every later call that carries it is a lookup in
// memory.

// seenPass is a pass this process checked: the hash of its Authorization
// value, the certificate it is signed under, and until when it is taken: the
// moment it runs out or its certificate ends, whichever comes first.
type seenPass struct {
	sum   [32]byte
	cert  [32]byte
	until time.Time
}

// passes remembers, for each box, the pass it showed last. An entry goes
// when its pass has run out, which is at most protocol.MaxPassLifetime after
// it was checked, so the map holds only boxes that called within that time.
type passes struct {
	mu    sync.Mutex
	seen  map[protocol.Address]seenPass
	sweep time.Time // when prune next runs
}

func newPasses() *passes { return &passes{seen: map[protocol.Address]seenPass{}} }

// has reports whether the Authorization value hashing to sum is the pass box
// a showed last, checked under the certificate cert and not run out at now.
func (ps *passes) has(a protocol.Address, sum, cert [32]byte, now time.Time) bool {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	p, ok := ps.seen[a]
	return ok && p.sum == sum && p.cert == cert && now.Before(p.until)
}

// keep remembers a pass of box a that was checked at now.
func (ps *passes) keep(a protocol.Address, p seenPass, now time.Time) {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	if !now.Before(ps.sweep) {
		for k, v := range ps.seen {
			if !now.Before(v.until) {
				delete(ps.seen, k)
			}
		}
		ps.sweep = now.Add(protocol.MaxPassLifetime)
	}
	ps.seen[a] = p
}

// standingOf returns what checking box a's pass needs: from memory when this
// process holds the box, so that a poll never leaves it, and otherwise from
// the box's record (lookup). ok is false for an address with no box.
func (s *Server) standingOf(r *http.Request, a protocol.Address) (st Standing, ok bool, err error) {
	if st, ok := s.store.Held(a); ok {
		return st, true, nil
	}
	b, err := s.lookup(r, a)
	if err != nil || b == nil {
		return Standing{}, false, err
	}
	st, err = b.standing()
	return st, err == nil, err
}

// serverName is the name the caller called this server by, the request's
// Host in lowercase, if it is one of the server's own. A pass names the
// server it was made for, and the name is not sent with it: checked against
// a name that is not ours, a pass made for another server would pass here.
func (s *Server) serverName(r *http.Request) (string, bool) {
	name := strings.ToLower(r.Host)
	return name, len(s.names) == 0 || slices.Contains(s.names, name)
}

func unauthorized(hint, format string, args ...any) *problem {
	return fail(protocol.CodeUnauthorized, hint, format, args...)
}

// listedCertificate refuses a pass of a box whose current certificate its
// identity has revoked (PROTOCOL.md §6.3a). No pass is looked at: one under
// that certificate is not taken, and the box has no other until it publishes
// a prekey under a new one, which needs no pass under the old.
func listedCertificate() *problem {
	return unauthorized("publish a new prekey, which comes with a new certificate: irongall prekey renew", "the box's current certificate is one its identity revoked")
}

// The hints of a 401: what a client does about it.
const (
	hintPass    = "send the box's pass in Authorization, signed by its working key (irongall and ig_owner do this)" //nolint:gosec // a hint's words, not a credential
	hintNewPass = "sign a new pass and retry once (irongall and ig_owner do this)"                                  //nolint:gosec // a hint's words, not a credential
)

// checkPass checks that the call carries the pass of box a: made for this
// server, not run out, and signed under the certificate whose hash is cert
// by a working key of the identity whose key, in SSH wire form, is key
// (PROTOCOL.md §6.1b). p is the call's pass if the caller parsed it already,
// and otherwise nil.
//
// A pass this process does not remember costs signature checks, and anyone
// can bring one: so its caller's address reserves a count under
// Limits.MissesPerMinute first, kept if the pass fails and given back if it
// passes (s.miss). One the process remembers is a lookup in memory.
func (s *Server) checkPass(r *http.Request, a protocol.Address, key string, cert [32]byte, p *protocol.Pass) error {
	return s.passCheck(r, a, key, cert, p, true)
}

// checkPassBounded is checkPass for a call that a count taken before it
// already bounds, a registration's (Limits.RegistrationsPerHour): its pass
// is checked without a count of its own.
func (s *Server) checkPassBounded(r *http.Request, a protocol.Address, key string, cert [32]byte) error {
	return s.passCheck(r, a, key, cert, nil, false)
}

func (s *Server) passCheck(r *http.Request, a protocol.Address, key string, cert [32]byte, p *protocol.Pass, count bool) (err error) {
	auth := r.Header.Get("Authorization")
	if len(auth) > protocol.MaxPassAuthorization {
		if !count {
			return unauthorized(hintPass, "no pass, or not a pass")
		}
		return s.notAPass(r) // longer than any pass can be: refused before it is hashed or parsed
	}
	now := s.now()
	sum := sha256.Sum256([]byte(auth))
	if s.passes.has(a, sum, cert, now) {
		return nil
	}
	if count {
		var m *reservation
		if m, err = s.miss(r); err != nil {
			return err
		}
		defer func() {
			if err != nil {
				m.keep()
			} else {
				m.release(s.now())
			}
		}()
	}
	if p == nil {
		var err error
		if p, err = protocol.ParsePass(auth); err != nil {
			return unauthorized(hintPass, "no pass, or not a pass")
		}
	}
	if p.Address != a {
		return unauthorized(hintPass, "the pass is another box's")
	}
	name, ours := s.serverName(r)
	if !ours {
		return unauthorized("call the server by the name in its URL", "this server is not %q, so no pass made for that name is for it", name)
	}
	// Run out, or running out too far ahead: either way the box signs another.
	// A new pass cures neither if the caller's clock is off, so each says
	// what this clock reads and which way the caller's is likely wrong.
	if !now.Before(p.NotAfter) {
		return fail(protocol.CodePassExpired, fmt.Sprintf("%s; refused again, this machine's clock reads %d minutes or more behind the server's: check it", hintNewPass, protocol.PassLifetime/time.Minute),
			"the pass has run out; %s", s.clock())
	}
	if p.NotAfter.After(now.Add(protocol.MaxPassLifetime)) {
		return fail(protocol.CodePassExpired, fmt.Sprintf("%s; refused again, this machine's clock reads more than %d minutes ahead of the server's: check it", hintNewPass, (protocol.MaxPassLifetime-protocol.PassLifetime)/time.Minute),
			"the pass runs out more than %d minutes from now; %s", protocol.MaxPassLifetime/time.Minute, s.clock())
	}
	// The certificate's hash, then the working key's signature: what
	// refuses a pass that is not the box's, for one signature check at most.
	under, err := p.VerifyUnder(cert, name, now)
	switch {
	case errors.Is(err, protocol.ErrCertificate):
		return unauthorized("sign the pass with the working key of the box's newest prekey; if that key is lost, irongall prekey renew", "the pass is not under the box's current certificate")
	case errors.Is(err, protocol.ErrCertificateNotBegun):
		return unauthorized("a certificate starts an hour before it is made: check this machine's clock, then irongall prekey renew", "the certificate the pass is signed under has not begun; %s", s.clock())
	case errors.Is(err, protocol.ErrCertificateTime):
		return unauthorized("publish a new prekey, which comes with a new certificate: irongall prekey renew", "the certificate the pass is signed under has ended; %s", s.clock())
	case err != nil:
		return unauthorized(hintNewPass, "the pass is not this box's for this server")
	}
	// Then the certificate itself, against the box's identity, as when it was
	// put on record: the identity's signature and every rule of a
	// certificate. It is a second check of what was checked then, and it is
	// reached only by a pass the working key signed. If it fails, the record
	// is wrong, and a new prekey, which is checked in full, puts it right.
	checked, err := checkCertificate(key, under, a, now)
	if err != nil {
		if s.log != nil {
			s.log.Printf("box %s: the certificate on record does not verify against the identity on record: %v", redact("/"+a.String()), err)
		}
		return unauthorized("publish a new prekey, which comes with a new certificate: irongall prekey renew", "the box's certificate on record does not verify against its identity")
	}
	// A pass is never good for longer than the certificate it is under.
	until := p.NotAfter
	if end := checked.NotAfter(); end.Before(until) {
		until = end
	}
	s.passes.keep(a, seenPass{sum: sum, cert: cert, until: until}, now)
	return nil
}

// notAPass refuses a call whose Authorization holds no pass, and counts it
// against the caller's address as a check that failed.
func (s *Server) notAPass(r *http.Request) error {
	if err := s.failed(r); err != nil {
		return err
	}
	return unauthorized(hintPass, "no pass, or not a pass")
}

// failed counts a check that failed against the caller's address, for one
// refused before a reservation was taken (s.miss). Past the count it is
// refused as such instead.
func (s *Server) failed(r *http.Request) error {
	m, err := s.miss(r)
	if err != nil {
		return err
	}
	m.keep()
	return nil
}

// checkCertificate holds a certificate to the identity whose key, in SSH wire
// form, is key, and whose address is a: protocol.CheckCertificate, for an
// identity rebuilt from its key with every check its document had.
func checkCertificate(key string, cert ssh.PublicKey, a protocol.Address, now time.Time) (*protocol.Certificate, error) {
	pub, err := ssh.ParsePublicKey([]byte(key))
	if err != nil {
		return nil, err
	}
	id, err := protocol.IdentityOf(pub)
	if err != nil {
		return nil, err
	}
	if id.Address() != a {
		return nil, errors.New("the identity on record is not this address's")
	}
	return protocol.CheckCertificate(id, cert, now)
}

// owner authenticates a call a box makes about itself: it returns the
// address in the path, once the call has shown that box's pass. A box this
// process holds is checked from memory; any other costs a read of its
// record, which lookup limits for an address that names no box.
func (s *Server) owner(r *http.Request) (protocol.Address, error) {
	a, err := pathAddr(r)
	if err != nil {
		return a, err
	}
	st, ok, err := s.standingOf(r, a)
	switch {
	case err != nil:
		return a, err
	case !ok, st.State == Closed:
		return a, noSuchMailbox
	case st.State == Revoked:
		return a, revoked()
	case st.Listed:
		return a, listedCertificate()
	}
	return a, s.checkPass(r, a, st.Key, st.Cert, nil)
}

// sender authenticates a send: the sender is the box the call's pass names
// (PROTOCOL.md §4.5, step 1).
func (s *Server) sender(r *http.Request) (protocol.Address, error) {
	p, err := protocol.ParsePass(r.Header.Get("Authorization"))
	if err != nil {
		return protocol.Address{}, s.notAPass(r)
	}
	a := p.Address
	st, ok, err := s.standingOf(r, a)
	switch {
	case err != nil:
		return a, err
	case !ok, st.State == Closed:
		return a, fail(protocol.CodeUnknownSender, "register your own box first: irongall init", "the box the pass names is not registered, or is closed")
	case st.State == Revoked:
		return a, fail(protocol.CodeSenderRevoked, "your box is revoked: make a new one, irongall init", "the sending box is revoked")
	case st.Listed:
		return a, listedCertificate()
	}
	return a, s.checkPass(r, a, st.Key, st.Cert, p)
}

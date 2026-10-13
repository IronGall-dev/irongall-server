package server

import (
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/IronGall-dev/irongall-client/protocol"
)

// A box proves itself with a pass it signs for itself (PROTOCOL.md §6.1b):
// the server issues nothing and stores nothing for it. Checking one costs two
// signature checks, so a pass that passed is remembered until it runs out,
// and every later call that carries it is a lookup in memory.

// seenPass is a pass this process checked: the hash of its Authorization
// value, the certificate it is signed under, and when it runs out.
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

// The hints of a 401: what a client does about it.
const (
	hintPass    = "send the box's pass in Authorization, signed by its working key (irongall and ig_owner do this)" //nolint:gosec // a hint's words, not a credential
	hintNewPass = "sign a new pass and retry once (irongall and ig_owner do this)"                                  //nolint:gosec // a hint's words, not a credential
)

// checkPass checks that the call carries the pass of box a: made for this
// server, not run out, and signed under the certificate cert by a working
// key of the identity whose public key is key (PROTOCOL.md §6.1b). p is the
// call's pass if the caller parsed it already, and otherwise nil.
func (s *Server) checkPass(r *http.Request, a protocol.Address, key [ed25519.PublicKeySize]byte, cert [32]byte, p *protocol.Pass) error {
	auth := r.Header.Get("Authorization")
	now := s.now()
	sum := sha256.Sum256([]byte(auth))
	if s.passes.has(a, sum, cert, now) {
		return nil
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
	if !now.Before(p.NotAfter) {
		return fail(protocol.CodePassExpired, hintNewPass, "the pass has run out")
	}
	if p.NotAfter.After(now.Add(protocol.MaxPassLifetime)) {
		return fail(protocol.CodePassExpired, hintNewPass+"; if it is refused again, check this machine's clock",
			"the pass runs out more than %d minutes from now", protocol.MaxPassLifetime/time.Minute)
	}
	id, err := protocol.NewIdentity(key[:])
	if err != nil {
		return err
	}
	under, err := p.Verify(id, name, now)
	switch {
	case errors.Is(err, protocol.ErrCertificateTime):
		return unauthorized("publish a new prekey, which comes with a new certificate: irongall rekey", "the certificate the pass is signed under has ended, or has not begun")
	case err != nil:
		return unauthorized(hintNewPass, "the pass is not this box's for this server")
	case certHash(under) != cert:
		return unauthorized("sign the pass with the working key of the box's newest prekey; if that key is lost, irongall rekey", "the pass is not under the box's current certificate")
	}
	s.passes.keep(a, seenPass{sum: sum, cert: cert, until: p.NotAfter}, now)
	return nil
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
	}
	return a, s.checkPass(r, a, st.Key, st.Cert, nil)
}

// sender authenticates a send: the sender is the box the call's pass names
// (PROTOCOL.md §4.5, step 1).
func (s *Server) sender(r *http.Request) (protocol.Address, error) {
	p, err := protocol.ParsePass(r.Header.Get("Authorization"))
	if err != nil {
		return protocol.Address{}, unauthorized(hintPass, "no pass, or not a pass")
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
	}
	return a, s.checkPass(r, a, st.Key, st.Cert, p)
}

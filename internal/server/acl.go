package server

import (
	"errors"
	"net/http"

	"github.com/IronGall-dev/irongall-client/protocol"
)

// The bound on a PUT …/acl body, before it is parsed: each entry as JSON
// writes it, an address in quotes with a comma, and room for a client that
// indents its lists, plus the rest of the document. With no bound on the
// entries, the body is bounded so that the record stays one DynamoDB item,
// which holds at most 400 KB.
const (
	aclEntryBytes    = 96
	aclBodyAllowance = 1 << 10
	aclBodyUnbounded = 256 << 10
)

func (s *Server) aclBodyLimit() int64 {
	if s.limits.ACLEntries <= 0 {
		return aclBodyUnbounded
	}
	return int64(s.limits.ACLEntries)*aclEntryBytes + aclBodyAllowance
}

// hintACL names what writes an ACL: the client does, from its own lists.
const hintACL = "irongall peer allow and irongall peer block write this box's ACL from its own lists"

// putACL is PUT /v1/<address>/acl (with the pass): the box's sender ACL,
// replaced whole by one of a higher version (PROTOCOL.md §6.2). Then the
// box's unacked mail from every sender its deny list matches is deleted, as
// acks delete it.
func (s *Server) putACL(w http.ResponseWriter, r *http.Request) error {
	a, err := s.owner(r)
	if err != nil {
		return err
	}
	if err := s.spendOwner(r.Context(), a); err != nil {
		return err
	}
	var doc protocol.ACLDocument
	if err := decodeBody(w, r, s.aclBodyLimit(), &doc); err != nil {
		return err
	}
	acl, err := protocol.CheckACL(&doc, s.limits.ACLEntries)
	switch {
	case errors.Is(err, protocol.ErrACLTooLarge):
		return fail(protocol.CodeTooLarge, "list fewer addresses: "+hintACL, "an ACL here holds at most %d entries, its two lists together", s.limits.ACLEntries)
	case err != nil:
		return fail(protocol.CodeBadRequest, hintACL, "%v", err)
	}
	b, err := s.box(r.Context(), a)
	if err != nil {
		return err
	}
	if b == nil {
		return noSuchMailbox
	}
	if held := b.ACL.Document(); acl.Version <= *held.Version {
		return fail(protocol.CodeConflict, "GET the same path for the version held, and send above it", "this box's ACL is at version %d, and a new one must be above it", *held.Version)
	}
	b.ACL = acl
	if err := s.store.UpdateBox(r.Context(), b); err != nil {
		if errors.Is(err, ErrStale) {
			return fail(protocol.CodeConflict, "retry", "the box changed during the request")
		}
		return err
	}
	// After the record holds the ACL, so the sends it refuses are refused
	// from here on. Memory says first whether the box holds any mail.
	if acl.Deny.Len() > 0 {
		if n, _, err := s.store.Count(r.Context(), a); err != nil {
			return err
		} else if n > 0 {
			if err := s.store.DeleteFrom(r.Context(), a, acl.Deny.Has); err != nil {
				return err
			}
		}
	}
	writeJSON(w, http.StatusOK, acl.Document())
	return nil
}

// getACL is GET /v1/<address>/acl (with the pass): the box's ACL as it was
// put, or, for a box that has put none, version 0 allowing everyone.
func (s *Server) getACL(w http.ResponseWriter, r *http.Request) error {
	a, err := s.owner(r)
	if err != nil {
		return err
	}
	if err := s.spendOwner(r.Context(), a); err != nil {
		return err
	}
	b, err := s.box(r.Context(), a)
	if err != nil {
		return err
	}
	if b == nil {
		return noSuchMailbox
	}
	writeJSON(w, http.StatusOK, b.ACL.Document())
	return nil
}

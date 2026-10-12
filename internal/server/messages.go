package server

import (
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/IronGall-dev/irongall-client/protocol"
)

// pageSize is the list page: up to 50 messages (the delivery contract).
const pageSize = 50

// list is GET /v1/<address>/messages (PROTOCOL.md §5.1): metadata only,
// oldest first, pages of 50, with an ETag. The poll rate applies to every
// poll, empty ones included. A page after the first is a continuation, not a
// poll, with an allowance of its own (Limits.continuations); a cursor with
// nothing after it continues nothing, so it is a poll. Only a list with
// something to return reads storage.
func (s *Server) list(w http.ResponseWriter, r *http.Request) error {
	box, err := s.owner(r)
	if err != nil {
		return err
	}
	q := r.URL.Query()
	cursor := q.Get("cursor")
	if len(q) > 1 || (len(q) == 1 && !q.Has("cursor")) {
		return fail(protocol.CodeBadRequest, "", "the only query parameter is cursor")
	}
	var after *Cursor
	more := 0 // live messages past the cursor
	if cursor != "" {
		if after, err = parseCursor(cursor); err != nil {
			return err
		}
		if more, err = s.store.After(r.Context(), box, after); err != nil {
			return err
		}
	}
	if more == 0 {
		if ok, wait := s.polls.take(box.String(), s.now()); !ok {
			return rateLimited(wait, "poll at most once a minute (poll_after)")
		}
	} else if ok, wait := s.pages.take(box.String(), s.now()); !ok {
		return rateLimited(wait, "too many list pages at once")
	}
	n, version, err := s.store.Count(r.Context(), box)
	if err != nil {
		return err
	}
	etag := fmt.Sprintf(`"%016x"`, version)
	w.Header().Set("ETag", etag)
	if cursor == "" && etagMatch(r.Header.Get("If-None-Match"), etag) {
		w.WriteHeader(http.StatusNotModified)
		return nil
	}
	resp := protocol.MessageList{Count: n, Messages: []protocol.MessageInfo{}, PollAfter: s.limits.PollAfter}
	if n == 0 || (after != nil && more == 0) {
		writeJSON(w, http.StatusOK, resp)
		return nil
	}
	page, err := s.store.List(r.Context(), box, after, pageSize+1)
	if err != nil {
		return err
	}
	if len(page) > pageSize {
		page = page[:pageSize]
		next := formatCursor(page[pageSize-1])
		resp.NextCursor = &next
	}
	for _, h := range page {
		resp.Messages = append(resp.Messages, protocol.MessageInfo{
			ID:         hexID(h.ID),
			From:       h.From.String(),
			Size:       h.Size,
			ReceivedAt: formatTime(h.ReceivedAt),
			ExpiresAt:  formatTime(h.ExpiresAt),
		})
	}
	writeJSON(w, http.StatusOK, resp)
	return nil
}

// etagMatch is If-None-Match's comparison (RFC 9110 §13.1.2).
func etagMatch(header, etag string) bool {
	for _, t := range strings.Split(header, ",") {
		t = strings.TrimPrefix(strings.TrimSpace(t), "W/")
		if t == etag || t == "*" {
			return true
		}
	}
	return false
}

// A cursor is the last key listed, opaque to clients: base64url of the
// receipt time in milliseconds (u64, big endian) and the id.
func formatCursor(h Header) string {
	b := binary.BigEndian.AppendUint64(nil, uint64(h.ReceivedAt.UnixMilli())) //nolint:gosec // receipt times are after 1970
	return base64.RawURLEncoding.EncodeToString(append(b, h.ID[:]...))
}

func parseCursor(s string) (*Cursor, error) {
	b, err := base64.RawURLEncoding.Strict().DecodeString(s)
	if err != nil || len(b) != 8+32 {
		return nil, fail(protocol.CodeBadRequest, "pass next_cursor exactly as received", "not a cursor")
	}
	c := &Cursor{ReceivedAt: time.UnixMilli(int64(binary.BigEndian.Uint64(b))).UTC()} //nolint:gosec // decoded from our own cursor
	copy(c.ID[:], b[8:])
	return c, nil
}

// gone is the answer for a message the box does not hold.
func gone() *problem {
	return fail(protocol.CodeNoSuchMessage, "treat it as gone", "no message has this id: acked or expired")
}

// held answers gone, from memory, for an id the box does not hold: a fetch
// or an ack reads or writes storage only for a message that is there.
func (s *Server) held(r *http.Request, box protocol.Address, id [32]byte) error {
	ok, err := s.store.Holds(r.Context(), box, id)
	if err != nil {
		return err
	}
	if !ok {
		return gone()
	}
	return nil
}

// fetch is GET /v1/<address>/messages/<id>: the body, read through this
// endpoint, never a redirect.
func (s *Server) fetch(w http.ResponseWriter, r *http.Request) error {
	box, err := s.owner(r)
	if err != nil {
		return err
	}
	id, err := pathID(r)
	if err != nil {
		return err
	}
	held, again, err := s.store.Fetched(r.Context(), box, id)
	if err != nil {
		return err
	}
	if !held {
		return gone()
	}
	// A message is fetched once and kept by its reader. Fetching it again is
	// for catching up after a failure, so it has an allowance of its own, and
	// only a repeat ever touches it: PollBurst at once, one more each PollRefill.
	if again {
		if ok, wait := s.repeats.take(box.String(), s.now()); !ok {
			return fetchedAlready(wait)
		}
	}
	h, body, err := s.store.Message(r.Context(), box, id)
	if errors.Is(err, ErrNotFound) {
		return gone()
	}
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, protocol.Message{
		ID:         hexID(h.ID),
		From:       h.From.String(),
		ReceivedAt: formatTime(h.ReceivedAt),
		ExpiresAt:  formatTime(h.ExpiresAt),
		Ciphertext: body,
		Signature:  h.Signature,
	})
	return nil
}

// ack is DELETE /v1/<address>/messages/<id>. Reading does not delete; this
// does. The dedupe record stays until the TTL.
func (s *Server) ack(w http.ResponseWriter, r *http.Request) error {
	box, err := s.owner(r)
	if err != nil {
		return err
	}
	id, err := pathID(r)
	if err != nil {
		return err
	}
	if err := s.held(r, box, id); err != nil {
		return err
	}
	err = s.store.DeleteMessage(r.Context(), box, id)
	if errors.Is(err, ErrNotFound) {
		return gone()
	}
	if err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

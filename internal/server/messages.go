package server

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/IronGall-dev/irongall-client/protocol"
)

// pageSize is the list page: up to 50 messages (the delivery contract).
const pageSize = 50

// list is GET /v1/<address>/messages (PROTOCOL.md §5.1): metadata only,
// oldest first, pages of 50. Every answer is a page with the count, and
// carries the poll interval in Retry-After; a first page carries its ETag
// too, and a poll that sends it back is 304 while the page is unchanged
// (writeList). The poll rate applies to every poll, empty ones and 304s
// included, and is taken before the condition is read: a box that polls too
// often is told 429, never 304. A page after the first is a continuation,
// not a poll, with an allowance of its own (Limits.continuations); a cursor
// with nothing after it continues nothing, so it is a poll. Only a list with
// something to return reads storage.
func (s *Server) list(w http.ResponseWriter, r *http.Request) error {
	box, err := s.owner(r, cursorParam)
	if err != nil {
		return err
	}
	cursor, hasCursor := r.URL.Query()[cursorParam]
	var after *Cursor
	more := 0          // live messages past the cursor
	continues := false // the cursor is the one this process handed the box last
	if hasCursor {
		if after, err = parseCursor(cursor[0]); err != nil {
			return err
		}
		if more, err = s.store.After(r.Context(), box, after); err != nil {
			return err
		}
		continues = s.drains.take(box, cursor[0])
	}
	// A page after the first is a continuation only when it presents the
	// cursor of the page served last: a made-up, replayed or retried cursor
	// is answered all the same, and charged as a poll
	// (IronGall-dev/irongall-server#5).
	if more == 0 || !continues {
		if ok, wait := s.polls.take(box.String(), s.now()); !ok {
			return rateLimited(protocol.QuotaPolls, wait, "poll at most once a minute (Retry-After)")
		}
	} else if ok, wait := s.pages.take(box.String(), s.now()); !ok {
		return rateLimited(protocol.QuotaPages, wait, "too many list pages at once")
	}
	n, err := s.store.Count(r.Context(), box)
	if err != nil {
		return err
	}
	resp := protocol.MessageList{Count: int64(n), Messages: []protocol.MessageInfo{}}
	if n == 0 || (after != nil && more == 0) {
		s.writeList(w, r, resp, !hasCursor)
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
		s.drains.put(box, next)
	}
	for _, h := range page {
		resp.Messages = append(resp.Messages, protocol.MessageInfo{
			ID:         hexID(h.ID),
			From:       h.From.String(),
			Size:       int64(h.Size),
			ReceivedAt: formatTime(h.ReceivedAt),
			ExpiresAt:  formatTime(h.ExpiresAt),
		})
	}
	s.writeList(w, r, resp, !hasCursor)
	return nil
}

// writeList writes a list answer with the poll interval in Retry-After, as
// RFC 9773 §4.3 uses the field. A first page carries an ETag: the first 16
// bytes of the SHA-256 of its body, in hex. It is a strong validator that
// every process computes alike with no key, and it changes with any message
// that enters or leaves the page or the count. A page that holds mail cannot
// be made to share an empty box's tag, the one a client keeps: that is a
// second preimage of 128 bits. An If-None-Match that names it, compared weakly (RFC 9110
// §13.1.2), is answered 304 with no body: its ETag, its Retry-After and the
// headers every answer carries (RFC 9110 §15.4.5).
func (s *Server) writeList(w http.ResponseWriter, r *http.Request, l protocol.MessageList, first bool) {
	body, err := jsonBytes(l)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	h := w.Header()
	h.Set("Retry-After", strconv.Itoa(s.limits.PollAfter))
	if first {
		sum := sha256.Sum256(body)
		tag := `"` + hex.EncodeToString(sum[:16]) + `"`
		h.Set("ETag", tag)
		if etagMatch(r.Header.Get("If-None-Match"), tag) {
			w.WriteHeader(http.StatusNotModified)
			return
		}
	}
	h.Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

// etagMatch is If-None-Match's weak comparison (RFC 9110 §13.1.2): a tag a
// proxy on the way marked weak still matches, and * matches any page.
func etagMatch(header, etag string) bool {
	for _, t := range strings.Split(header, ",") {
		t = strings.TrimPrefix(strings.TrimSpace(t), "W/")
		if t == etag || t == "*" {
			return true
		}
	}
	return false
}

// drains remembers, for each box with a drain open, the one next_cursor this
// process last handed it. Serving that cursor's page replaces it with the
// next, and the last page of a drain clears it. It is this process's alone,
// as every count is: a page that lands on another process is charged as a
// poll there.
type drains struct {
	mu   sync.Mutex
	next map[protocol.Address]string
}

// take reports whether cursor is the one box a was handed last, and spends it.
func (d *drains) take(a protocol.Address, cursor string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	ok := d.next[a] == cursor
	if ok {
		delete(d.next, a)
	}
	return ok
}

// put remembers the cursor just handed to box a.
func (d *drains) put(a protocol.Address, cursor string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.next == nil {
		d.next = map[protocol.Address]string{}
	}
	d.next[a] = cursor
}

// cursorParam is the list's one query parameter: the next_cursor of the
// page before.
const cursorParam = "cursor"

// A cursor is the last key listed, opaque to clients: base64url of the
// receipt time in milliseconds (u64, big endian) and the id, unpadded, so
// one or more of [A-Za-z0-9_-] as a cursor is (protocol.CheckCursor).
func formatCursor(h Header) string {
	b := binary.BigEndian.AppendUint64(nil, uint64(h.ReceivedAt.UnixMilli())) //nolint:gosec // receipt times are after 1970
	return base64.RawURLEncoding.EncodeToString(append(b, h.ID[:]...))
}

func parseCursor(s string) (*Cursor, error) {
	b, err := base64.RawURLEncoding.Strict().DecodeString(s)
	if err != nil || len(b) != 8+32 {
		return nil, fail(protocol.CodeBadRequest, "pass next_cursor exactly as received", "the query parameter %s is not a cursor this server handed out", memberValue(cursorParam))
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
		return s.notHeld(r, box)
	}
	return nil
}

// notHeld answers a fetch or an ack of an id box a does not hold. A held
// message's first fetch spends the box's budget of mail taken out
// (Limits.DrainBurst), and its ack is paid for by its receive; anything else
// is a call, spent from the box's budget (Limits.CallBurst).
func (s *Server) notHeld(r *http.Request, a protocol.Address) error {
	if err := s.spendOwner(r.Context(), a); err != nil {
		return err
	}
	return gone()
}

// fetch is GET /v1/<address>/messages/<id>: the ciphertext's bytes and
// nothing else, read through this endpoint, never a redirect. Who sent it,
// on this server's word, and when, are in the list.
func (s *Server) fetch(w http.ResponseWriter, r *http.Request) error {
	box, err := s.owner(r)
	if err != nil {
		return err
	}
	id, err := pathID(r)
	if err != nil {
		return s.notHeld(r, box)
	}
	// A first fetch of a held message is new mail drained, and spends the
	// box's budget of it (Limits.DrainBurst): how much mail a box takes out,
	// whoever sent it, which only the box's own calls spend. Whether a fetch
	// is a first one is known only once memory counts it, so a token is
	// reserved before and given back if it was not.
	lim, err := s.limitsOf(r.Context(), box)
	if err != nil {
		return err
	}
	var drain *reservation
	if lim.DrainBurst > 0 {
		var ok bool
		var wait time.Duration
		if drain, ok, wait = s.drained.reserve(r.Context(), box.String(), s.now); !ok {
			return spent(protocol.CodeFetchPaced, wait, "this box takes out at most so much new mail a minute: the rest waits on the server")
		}
	}
	held, again, err := s.store.Fetched(r.Context(), box, id)
	if err != nil || !held || again {
		drain.release(s.now())
	} else {
		drain.keep()
	}
	if err != nil {
		return err
	}
	if !held {
		return s.notHeld(r, box)
	}
	// A message is fetched once and kept by its reader. Fetching it again is
	// for catching up after a failure, so it has an allowance of its own, and
	// only a repeat ever touches it: PollBurst at once, one more each PollRefill.
	if again {
		if ok, wait := s.repeats.take(box.String(), s.now()); !ok {
			return fetchedAlready(wait)
		}
	}
	_, body, err := s.store.Message(r.Context(), box, id)
	if errors.Is(err, ErrNotFound) {
		return gone()
	}
	if err != nil {
		return err
	}
	h := w.Header()
	h.Set("Content-Type", protocol.CiphertextContentType)
	h.Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body) //nolint:gosec // an age file, as application/octet-stream, to the box that holds it: no page renders it
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
		return s.notHeld(r, box)
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

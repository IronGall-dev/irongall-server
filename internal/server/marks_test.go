package server

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/IronGall-dev/irongall-client/protocol"
)

// A first page carries an ETag, the first 16 bytes of the SHA-256 of its
// body, and a poll that sends it back is 304 while the page is unchanged
// (PROTOCOL.md §5.1). The tag is the page's own: every process computes it
// alike, with no key, and an empty box's is the same on every server. A tag
// of the page before, the old "<count>-<version>" form among them, is not
// the page's. Weak comparison: W/ is read past, and * names any page. A page
// after the first carries none and is never 304. Every answer carries the
// poll interval in Retry-After, a 304's too.
func TestAFirstPageIsNotModifiedWhileUnchanged(t *testing.T) {
	l := relaxed()
	l.PairCap, l.BoxCap = 0, 0
	e := newEnv(t, l)
	from, to := e.raw().register(protocol.MaxPrekeyLifetime), e.raw().register(protocol.MaxPrekeyLifetime)
	poll := func(query, ifNoneMatch string) (*http.Response, []byte) {
		t.Helper()
		req, _ := http.NewRequest(http.MethodGet, e.srv.URL+to.path("/messages")+query, nil)
		req.Header.Set("Authorization", to.pass(1))
		if ifNoneMatch != "" {
			req.Header.Set("If-None-Match", ifNoneMatch)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		if got := resp.Header.Get("Retry-After"); got != strconv.Itoa(l.PollAfter) {
			t.Errorf("If-None-Match %q: %d with Retry-After %q, want %d", ifNoneMatch, resp.StatusCode, got, l.PollAfter)
		}
		return resp, body
	}
	const emptyPage = `{"count":0,"messages":[],"next_cursor":null}` + "\n"
	sum := sha256.Sum256([]byte(emptyPage))
	emptyTag := `"` + hex.EncodeToString(sum[:16]) + `"`
	resp, body := poll("", "")
	if resp.StatusCode != http.StatusOK || string(body) != emptyPage || resp.Header.Get("ETag") != emptyTag {
		t.Fatalf("an empty box: %d %q, ETag %q, want 200 %q with the page's hash, %s", resp.StatusCode, body, resp.Header.Get("ETag"), emptyPage, emptyTag)
	}
	for _, tag := range []string{emptyTag, "W/" + emptyTag, `"other", ` + emptyTag, "*"} {
		if resp, body := poll("", tag); resp.StatusCode != http.StatusNotModified || len(body) != 0 || resp.Header.Get("ETag") != emptyTag {
			t.Errorf("an empty box, If-None-Match %q: %d %q, ETag %q, want 304 with no body", tag, resp.StatusCode, body, resp.Header.Get("ETag"))
		}
	}
	for _, tag := range []string{`"0-0000000000000000"`, `"` + strings.Repeat("0", 32) + `"`, emptyTag[1 : len(emptyTag)-1]} {
		if resp, _ := poll("", tag); resp.StatusCode != http.StatusOK {
			t.Errorf("an empty box, If-None-Match %q: %d, want 200", tag, resp.StatusCode)
		}
	}
	const n = 3
	for range n {
		var ct bytes.Buffer
		w, _ := age.Encrypt(&ct, to.keys[1].Recipient())
		_, _ = io.WriteString(w, `{"v":1}`)
		_ = w.Close()
		e.want(e.do(http.MethodPost, to.path("/messages"), sealedTo(1, 1, ct.Bytes()), from.pass(1)), http.StatusCreated, "")
	}
	resp, body = poll("", emptyTag)
	var list protocol.MessageList
	if resp.StatusCode != http.StatusOK || json.Unmarshal(body, &list) != nil || list.Count != n || len(list.Messages) != n {
		t.Fatalf("a box holding %d, sent the empty box's tag: %d %s, want 200 with the mail", n, resp.StatusCode, body)
	}
	held := resp.Header.Get("ETag")
	if sum := sha256.Sum256(body); held != `"`+hex.EncodeToString(sum[:16])+`"` || held == emptyTag {
		t.Fatalf("a box holding %d: ETag %q, want its page's hash", n, held)
	}
	if resp, _ := poll("", held); resp.StatusCode != http.StatusNotModified {
		t.Errorf("a box holding %d, sent its own page's tag: %d, want 304", n, resp.StatusCode)
	}
	// A cursor after every message: a poll, answered with an empty page that
	// is not the first, so neither tagged nor 304, whatever it sends.
	last := formatCursor(Header{ReceivedAt: e.clock.Now().Add(time.Hour)})
	for _, tag := range []string{"", "*", held} {
		if resp, _ := poll("?cursor="+last, tag); resp.StatusCode != http.StatusOK || resp.Header.Get("ETag") != "" {
			t.Errorf("a page after the first, If-None-Match %q: %d, ETag %q, want 200 and none", tag, resp.StatusCode, resp.Header.Get("ETag"))
		}
	}
}

// A 304 is a poll: it takes from the poll rate, and a box that polls faster is
// refused 429, never answered 304, whatever it sends (PROTOCOL.md §5.1).
func TestA304IsAPoll(t *testing.T) {
	l := relaxed()
	l.PollBurst, l.PollRefill = 2, time.Hour
	e := newEnv(t, l)
	to := e.raw().register(protocol.MaxPrekeyLifetime)
	poll := func(tag string) reply {
		t.Helper()
		req, _ := http.NewRequest(http.MethodGet, e.srv.URL+to.path("/messages"), nil)
		req.Header.Set("Authorization", to.pass(1))
		if tag != "" {
			req.Header.Set("If-None-Match", tag)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return reply{status: resp.StatusCode, header: resp.Header, body: b}
	}
	first := poll("")
	tag := first.header.Get("ETag")
	if first.status != http.StatusOK || tag == "" {
		t.Fatalf("the first poll: %d, ETag %q", first.status, tag)
	}
	if r := poll(tag); r.status != http.StatusNotModified {
		t.Fatalf("the second poll, inside the rate: %d, want 304", r.status)
	}
	if r := poll(tag); r.status != http.StatusTooManyRequests || r.code() != protocol.CodeRateLimited || r.header.Get("Retry-After") == "" {
		t.Fatalf("a poll past the rate, with the page's tag: %d %s, want 429 rate_limited with Retry-After", r.status, r.body)
	}
}

// An id that shares a held message's first 8 bytes is not that message: its
// fetch and its ack are 404 from memory, and touch no storage.
func TestAnIDThatSharesAPrefixIsNotHeld(t *testing.T) {
	l := relaxed()
	e := newEnv(t, l)
	a, b := e.box(protocol.Classic), e.box(protocol.Classic)
	send(t, a, b, "held")
	e2, cs := counted(t, e, l)
	pass := e2.pass(b)
	list := listOf(t, e2.do(http.MethodGet, "/v1/"+b.Address().String()+"/messages", nil, pass))
	if len(list.Messages) != 1 {
		t.Fatalf("listed %d", len(list.Messages))
	}
	real, _ := hex.DecodeString(list.Messages[0].ID)
	forged := append([]byte{}, real[:8]...)
	tail := make([]byte, 24)
	_, _ = rand.Read(tail)
	forged = append(forged, tail...)
	path := "/v1/" + b.Address().String() + "/messages/" + hex.EncodeToString(forged)
	before := cs.reads.Load()
	for range 5 {
		e2.want(e2.do(http.MethodDelete, path, nil, pass), http.StatusNotFound, protocol.CodeNoSuchMessage)
		e2.want(e2.do(http.MethodGet, path, nil, pass), http.StatusNotFound, protocol.CodeNoSuchMessage)
	}
	if n := cs.reads.Load(); n != before {
		t.Fatalf("%d storage calls for an id that only shares a held message's prefix", n-before)
	}
	if res := receive(t, b); len(res.Delivered) != 1 {
		t.Fatalf("the held message: delivered %d", len(res.Delivered))
	}
}

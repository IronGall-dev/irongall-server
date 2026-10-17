package server

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"filippo.io/age"
	"github.com/IronGall-dev/irongall-client/protocol"
)

// A list carries no ETag and reads no If-None-Match (PROTOCOL.md §5.1):
// every poll is a page with the box's count and poll_after, so no answer can
// stand for an empty box's, and none leaves out when to poll next. It
// replaces the test that a sender could not steer a box's version to an
// empty one's (IronGall-dev/irongall-server#10), which an ETag made of that
// version needed.
func TestAListIsNeverNotModified(t *testing.T) {
	l := relaxed()
	l.PairCap, l.BoxCap = 0, 0
	e := newEnv(t, l)
	from, to := e.raw().register(protocol.MaxPrekeyLifetime), e.raw().register(protocol.MaxPrekeyLifetime)
	poll := func(ifNoneMatch string) (*http.Response, protocol.MessageList) {
		t.Helper()
		req, _ := http.NewRequest(http.MethodGet, e.srv.URL+to.path("/messages"), nil)
		req.Header.Set("Authorization", to.pass(1))
		if ifNoneMatch != "" {
			req.Header.Set("If-None-Match", ifNoneMatch)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var list protocol.MessageList
		if err := json.NewDecoder(resp.Body).Decode(&list); err != nil {
			t.Fatalf("%d: %v", resp.StatusCode, err)
		}
		return resp, list
	}
	// "0-0000000000000000" is what an empty box's ETag was.
	tags := []string{"", "*", `"0-0000000000000000"`, `W/"0-0000000000000000"`}
	for _, tag := range tags {
		if resp, list := poll(tag); resp.StatusCode != http.StatusOK || resp.Header.Get("ETag") != "" || list.Count != 0 || list.PollAfter != int64(l.PollAfter) {
			t.Fatalf("an empty box, If-None-Match %q: %d, ETag %q, %+v", tag, resp.StatusCode, resp.Header.Get("ETag"), list)
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
	for _, tag := range tags {
		if resp, list := poll(tag); resp.StatusCode != http.StatusOK || resp.Header.Get("ETag") != "" || list.Count != n || len(list.Messages) != n || list.PollAfter != int64(l.PollAfter) {
			t.Fatalf("a box holding %d, If-None-Match %q: %d, ETag %q, %+v", n, tag, resp.StatusCode, resp.Header.Get("ETag"), list)
		}
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

package server

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"

	"filippo.io/age"
	"github.com/IronGall-dev/irongall-client/protocol"
)

// zeroSubset returns indexes of a non-empty subset of xs whose XOR is zero,
// by Gaussian elimination over GF(2)^64: what any sender can do with the
// first 8 bytes of ids it chose, given 65 of them.
func zeroSubset(xs []uint64) []int {
	type row struct {
		v    uint64
		from map[int]bool
	}
	var basis [64]*row // by the highest bit set
	for i, x := range xs {
		r := &row{x, map[int]bool{i: true}}
		for bit := 63; bit >= 0 && r.v != 0; bit-- {
			if r.v>>bit&1 == 0 {
				continue
			}
			b := basis[bit]
			if b == nil {
				basis[bit] = r
				break
			}
			r.v ^= b.v
			for k, in := range b.from {
				if in {
					r.from[k] = !r.from[k]
				}
			}
		}
		if r.v == 0 {
			var out []int
			for k, in := range r.from {
				if in {
					out = append(out, k)
				}
			}
			return out
		}
	}
	return nil
}

// A sender cannot make a box that holds mail look empty
// (IronGall-dev/irongall-server#10): ciphertexts whose ids' first 8 bytes
// XOR to zero, sent to an empty box, leave it a version and an ETag of its
// own, and the owner's client lists and delivers them.
func TestASenderCannotForgeAnEmptyBox(t *testing.T) {
	l := relaxed()
	l.PairCap, l.BoxCap = 0, 0
	e := newEnv(t, l)
	from, to := e.raw().register(protocol.MaxPrekeyLifetime), e.raw().register(protocol.MaxPrekeyLifetime)
	var bodies [][]byte
	var prefixes []uint64
	for range 70 {
		var ct bytes.Buffer
		w, _ := age.Encrypt(&ct, to.keys[1].Recipient())
		_, _ = io.WriteString(w, `{"v":1}`)
		_ = w.Close()
		id := sha256.Sum256(ct.Bytes())
		bodies, prefixes = append(bodies, ct.Bytes()), append(prefixes, prefix8(id[:]))
	}
	subset := zeroSubset(prefixes)
	var x uint64
	for _, i := range subset {
		x ^= prefixes[i]
	}
	if len(subset) == 0 || x != 0 {
		t.Fatalf("no subset of plain prefixes XORs to zero: %v", subset)
	}
	empty := e.do(http.MethodGet, to.path("/messages"), nil, to.pass(1))
	e.want(empty, http.StatusOK, "")
	one := uint64(1)
	for _, i := range subset {
		e.want(e.do(http.MethodPost, to.path(""), protocol.SendRequest{PrekeySerial: &one, CertificateSerial: &one, Ciphertext: bodies[i]}, from.pass(1)), http.StatusCreated, "")
	}
	full := e.do(http.MethodGet, to.path("/messages"), nil, to.pass(1))
	e.want(full, http.StatusOK, "")
	if full.header.Get("ETag") == empty.header.Get("ETag") {
		t.Fatalf("a box holding %d messages has the empty box's ETag %s", len(subset), full.header.Get("ETag"))
	}
	// Each half holds by itself: the count, and a version made of tags no
	// sender can steer to zero.
	var n int
	var version uint64
	if _, err := fmt.Sscanf(full.header.Get("ETag"), `"%d-%016x"`, &n, &version); err != nil || n != len(subset) || version == 0 {
		t.Fatalf("the ETag %s: count %d, version %016x (%v), want %d and not zero", full.header.Get("ETag"), n, version, err, len(subset))
	}
	req, _ := http.NewRequest(http.MethodGet, e.srv.URL+to.path("/messages"), nil)
	req.Header.Set("Authorization", to.pass(1))
	req.Header.Set("If-None-Match", empty.header.Get("ETag"))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var list protocol.MessageList
	_ = json.NewDecoder(resp.Body).Decode(&list)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || list.Count != len(subset) {
		t.Fatalf("a poll with the empty box's ETag: %d, count %d, want 200 and %d", resp.StatusCode, list.Count, len(subset))
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

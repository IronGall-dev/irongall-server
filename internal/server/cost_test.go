package server

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/IronGall-dev/irongall-client/protocol"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"golang.org/x/crypto/ssh"
)

// Measurements for costing: what one box costs a process's memory,
// and how large the items the store writes are. Evidence, not a test: it
// asserts nothing and is skipped unless IRONGALL_COST=1.
//
//	IRONGALL_COST=1 go test ./internal/server -run TestCost -v

func costOnly(t *testing.T) {
	t.Helper()
	if os.Getenv("IRONGALL_COST") == "" {
		t.Skip("set IRONGALL_COST=1 to measure")
	}
}

func heapNow() uint64 {
	runtime.GC()
	runtime.GC()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m.HeapAlloc
}

func costAddrs(n int) []protocol.Address {
	as := make([]protocol.Address, n)
	for i := range as {
		_, _ = rand.Read(as[i][:])
	}
	return as
}

// costBox is a real box record: an identity, and a prekey statement it
// signed, post-quantum or not, with n retired prekeys.
func costBox(t *testing.T, pq bool, retired int) *Box {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := ssh.NewSignerFromKey(priv)
	id, err := protocol.NewIdentity(pub)
	if err != nil {
		t.Fatal(err)
	}
	var key string
	if pq {
		k, err := age.GenerateHybridIdentity()
		if err != nil {
			t.Fatal(err)
		}
		key = k.Recipient().String()
	} else {
		k, _ := age.GenerateX25519Identity()
		key = k.Recipient().String()
	}
	now := time.Now().UTC().Truncate(time.Second)
	p := &protocol.Prekey{Address: id.Address(), Serial: uint64(retired) + 1, Key: key, NotAfter: now.Add(protocol.TTL)}
	sig, err := protocol.Sign(signer, p.Statement(), protocol.PrekeyNamespace(id.Address()))
	if err != nil {
		t.Fatal(err)
	}
	b := &Box{Addr: id.Address(), Identity: id.Document(), State: Active, Statement: p.Statement(), Signature: sig, Prekey: p, Epoch: uint32(retired) + 1, Rev: uint64(retired) + 2, Created: now}
	for i := range retired {
		b.Retired = append(b.Retired, Retired{Type: p.Type(), NotAfter: now.Add(time.Duration(i) * time.Hour), KeyHash: sha256.Sum256([]byte{byte(i)})})
	}
	return b
}

// TestCostMemoryPerBox measures the heap each structure holds per box.
func TestCostMemoryPerBox(t *testing.T) {
	costOnly(t)
	const n = 200_000
	addrs := costAddrs(n)
	ctx := context.Background()
	now := time.Now()

	// The index: a loaded box and its live messages' marks, grown by append
	// as the load and the stream grow them.
	for _, k := range []int{0, 1, 10, 100} {
		before := heapNow()
		x := newIndex()
		for _, a := range addrs {
			var marks []mark
			for i := range k {
				marks = append(marks, mark{id: uint64(i), from: 1, exp: 1 << 62})
			}
			_ = x.ensure(ctx, a, func() (boxRead, error) {
				return boxRead{exists: true, st: Standing{State: Active, Epoch: 1}, rev: 2, marks: marks}, nil
			})
		}
		t.Logf("index, %3d live messages: %6.0f B per loaded box", k, float64(heapNow()-before)/n)
		runtime.KeepAlive(x)
	}

	// The poll bucket: one map entry per box that has polled, until its
	// bucket is full again.
	before := heapNow()
	bs := newBuckets(10, 50*time.Second)
	for _, a := range addrs {
		bs.take(a.String(), now)
	}
	t.Logf("poll bucket: %6.0f B per box that has polled", float64(heapNow()-before)/n)
	runtime.KeepAlive(bs)

	// The daily send counter: one entry per sender per UTC day.
	before = heapNow()
	var d daily
	for _, a := range addrs {
		d.add(a, now, 20, true)
	}
	t.Logf("daily send count: %6.0f B per sender that sent today", float64(heapNow()-before)/n)
	runtime.KeepAlive(&d)

	// The token cache: one encrypted token per box, its newest epoch's, for
	// at most Config.TokenCache boxes.
	keys, _ := NewDevKeys()
	for _, pq := range []bool{true, false} {
		const m = 20_000
		b := costBox(t, pq, 0)
		s := New(Config{Store: NewMemStore(time.Now), Keys: keys, Limits: DefaultLimits(), TokenCache: m})
		before := heapNow()
		start := time.Now()
		var size int
		for _, a := range addrs[:m] {
			c := *b
			c.Addr = a
			ct, err := s.encryptedToken(&c)
			if err != nil {
				t.Fatal(err)
			}
			size = len(ct)
		}
		el := time.Since(start)
		t.Logf("token cache, pq=%v: %6.0f B per entry (ciphertext %d B, %.0f µs to encrypt)", pq, float64(heapNow()-before)/m, size, float64(el.Microseconds())/m)
		runtime.KeepAlive(s)
	}

	// The box record cache: bounded (-box-cache, default 10,000).
	for _, c := range []struct {
		pq      bool
		retired int
	}{{true, 0}, {true, 10}, {false, 0}} {
		const m = 10_000
		b := costBox(t, c.pq, c.retired)
		before := heapNow()
		cache := newBoxCache(m)
		for _, a := range addrs[:m] {
			// Its own bytes, as a record decoded from the table has.
			x := cloneBox(b)
			x.Addr = a
			x.Identity, x.Statement, x.Signature = bytes.Clone(b.Identity), bytes.Clone(b.Statement), bytes.Clone(b.Signature)
			p := *b.Prekey
			p.Key = strings.Clone(p.Key)
			x.Prekey = &p
			cache.put(x)
		}
		t.Logf("box record cache, pq=%v, %2d retired: %6.0f B per record", c.pq, c.retired, float64(heapNow()-before)/m)
		runtime.KeepAlive(cache)
	}
}

// itemSize is an item's size as DynamoDB bills it: attribute names plus
// values (AWS docs, "DynamoDB item sizes and formats").
func itemSize(it map[string]types.AttributeValue) int {
	n := 0
	for k, v := range it {
		n += len(k) + valueSize(v)
	}
	return n
}

func valueSize(v types.AttributeValue) int {
	switch v := v.(type) {
	case *types.AttributeValueMemberB:
		return len(v.Value)
	case *types.AttributeValueMemberS:
		return len(v.Value)
	case *types.AttributeValueMemberN:
		digits := len(strings.Trim(strings.ReplaceAll(v.Value, ".", ""), "0"))
		return (digits+1)/2 + 1
	case *types.AttributeValueMemberBOOL:
		return 1
	case *types.AttributeValueMemberL:
		n := 3
		for _, e := range v.Value {
			n += 1 + valueSize(e)
		}
		return n
	case *types.AttributeValueMemberM:
		n := 3
		for k, e := range v.Value {
			n += 1 + len(k) + valueSize(e)
		}
		return n
	}
	return 0
}

// TestCostItemSizes prints the size of every item the store writes, from the
// functions that build them, and the write units each costs (1 per KB,
// rounded up).
func TestCostItemSizes(t *testing.T) {
	costOnly(t)
	wcu := func(n int) int { return (n + 1023) / 1024 }
	for _, c := range []struct {
		pq      bool
		retired int
	}{{true, 0}, {true, 1}, {true, 10}, {false, 0}, {false, 10}} {
		b := costBox(t, c.pq, c.retired)
		n := itemSize(boxItem(b))
		t.Logf("box record, pq=%v, %2d retired: %5d B = %d write units (identity %d, statement %d, signature %d)",
			c.pq, c.retired, n, wcu(n), len(b.Identity), len(b.Statement), len(b.Signature))
	}

	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := ssh.NewSignerFromKey(priv)
	to := costAddrs(1)[0]
	body := make([]byte, 4096)
	sig, err := protocol.Sign(signer, body, protocol.MessageNamespace(to))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Millisecond)
	h := &Header{ID: sha256.Sum256(body), From: costAddrs(1)[0], Size: len(body), ReceivedAt: now, ExpiresAt: now.Add(protocol.TTL), Signature: sig}
	live := msgItem(to, h)
	n := itemSize(live)
	t.Logf("message item, unacked: %4d B = %d write unit (signature %d B)", n, wcu(n), len(sig))
	index := map[string]types.AttributeValue{"box": live["box"], "live": live["live"], "id": live["id"], "from": live["from"], "size": live["size"]}
	t.Logf("its entry in the live index: %4d B", itemSize(index))
	acked := map[string]types.AttributeValue{}
	for k, v := range live {
		if k != "live" && k != "sig" {
			acked[k] = v
		}
	}
	t.Logf("message item, acked (kept as the dedupe record): %4d B", itemSize(acked))
}

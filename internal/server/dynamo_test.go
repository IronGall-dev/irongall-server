package server

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/IronGall-dev/irongall-client/client"
	"github.com/IronGall-dev/irongall-client/protocol"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	stypes "github.com/aws/aws-sdk-go-v2/service/dynamodbstreams/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/smithy-go"
)

// The suite runs against the in-memory store, or, with
// IRONGALL_TEST_BOXES_TABLE, IRONGALL_TEST_MSGS_TABLE,
// IRONGALL_TEST_ACCOUNTS_TABLE and IRONGALL_TEST_BUCKET set, against DynamoDB
// + S3 Express: every test, plus the ones here that need AWS. Name tables and
// a directory bucket kept for tests, never the ones a running server uses.

func onAWS() bool { return os.Getenv("IRONGALL_TEST_MSGS_TABLE") != "" }

func newTestStore(t *testing.T, now func() time.Time) (Store, func() bool) {
	t.Helper()
	if !onAWS() {
		return NewMemStore(now), nil
	}
	s := startDynamo(t, now)
	return s, s.Ready
}

func startDynamo(t *testing.T, now func() time.Time) *DynamoStore {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion("us-east-1"))
	if err != nil {
		t.Fatal(err)
	}
	s := NewDynamoStore(DynamoConfig{
		AWS:            cfg,
		BoxesTable:     os.Getenv("IRONGALL_TEST_BOXES_TABLE"),
		MsgsTable:      os.Getenv("IRONGALL_TEST_MSGS_TABLE"),
		AccountsTable:  os.Getenv("IRONGALL_TEST_ACCOUNTS_TABLE"),
		Bucket:         os.Getenv("IRONGALL_TEST_BUCKET"),
		Now:            now,
		BoxCache:       100,
		StreamInterval: 200 * time.Millisecond,
		// The tests read back what they wrote within milliseconds.
		ConsistentReads: true,
		Fatal:           func(err error) { t.Errorf("stream: %v", err) },
	})
	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	return s
}

// dynamoEnv is an env on DynamoDB + S3 Express; the test is skipped without.
func dynamoEnv(t *testing.T) (*env, *DynamoStore) {
	t.Helper()
	if !onAWS() {
		t.Skip("needs IRONGALL_TEST_BOXES_TABLE, IRONGALL_TEST_MSGS_TABLE, IRONGALL_TEST_ACCOUNTS_TABLE and IRONGALL_TEST_BUCKET")
	}
	e := newEnv(t, relaxed())
	return e, e.store.(*DynamoStore)
}

// failOnce makes the store fail once at a point, as a crash there would.
func failOnce(s *DynamoStore, point string) {
	var mu sync.Mutex
	done := false
	s.fault = func(p string) error {
		mu.Lock()
		defer mu.Unlock()
		if p == point && !done {
			done = true
			return errors.New("injected: a crash " + p)
		}
		return nil
	}
}

func idOf(t *testing.T, r *protocol.Receipt) [32]byte {
	t.Helper()
	var id [32]byte
	copy(id[:], mustHex(t, r.ID))
	return id
}

// member reports whether an account's side holds a box.
func (s *DynamoStore) member(t *testing.T, account string, a protocol.Address) bool {
	t.Helper()
	out, err := s.db.GetItem(context.Background(), &dynamodb.GetItemInput{TableName: &s.accts, Key: memberKey(account, a), ConsistentRead: aws.Bool(true)})
	if err != nil {
		t.Fatal(err)
	}
	return out.Item != nil
}

// stored reads a message's item from the table as it is, or nil.
func (s *DynamoStore) stored(t *testing.T, box protocol.Address, id [32]byte) item {
	t.Helper()
	out, err := s.db.GetItem(context.Background(), &dynamodb.GetItemInput{TableName: &s.msgs, Key: msgKey(box, id), ConsistentRead: aws.Bool(true)})
	if err != nil {
		t.Fatal(err)
	}
	return out.Item
}

func (s *DynamoStore) bodyExists(t *testing.T, box protocol.Address, id [32]byte) bool {
	t.Helper()
	_, err := s.s3.HeadObject(context.Background(), &s3.HeadObjectInput{Bucket: &s.bucket, Key: aws.String(bodyKey(box, id))})
	if err != nil && !isNoSuchKey(err) {
		t.Fatal(err)
	}
	return err == nil
}

// listed reports whether the table lists the message: its item is in the
// live index.
func (s *DynamoStore) listed(t *testing.T, box protocol.Address, id [32]byte) bool {
	t.Helper()
	_, ok := s.stored(t, box, id)["live"]
	return ok
}

// Each crash point between the writes, then the retry.

func TestCrashAfterTheBody(t *testing.T) {
	e, s := dynamoEnv(t)
	a, b := e.box(protocol.Classic), e.box(protocol.Classic)
	failOnce(s, "put: after the body")
	if _, err := a.Send(context.Background(), b.Address(), "an orphan body first"); err == nil {
		t.Fatal("the crash was not reported")
	}
	if rs, err := a.Flush(context.Background()); err != nil || len(rs) != 1 {
		t.Fatalf("retry: %v", err)
	}
	if res := receive(t, b); len(res.Delivered) != 1 {
		t.Fatalf("delivered %d", len(res.Delivered))
	}
}

func TestRetryAfterAckIsNotRedelivered(t *testing.T) {
	e, s := dynamoEnv(t)
	a, b := e.box(protocol.Classic), e.box(protocol.Classic)
	sent := capture(e, http.MethodPost, "/v1/"+b.Address().String())
	send(t, a, b, "once")
	e.setMiddle(nil)
	receive(t, b)
	// A retry of the same bytes after the ack: the original receipt, from the
	// item the ack left as the dedupe record.
	if code, out := post(t, e.srv.URL+"/v1/"+b.Address().String(), *sent); code != http.StatusOK {
		t.Fatalf("retry after the ack: %d %s", code, out)
	}
	if n, _, _ := s.Count(context.Background(), b.Address()); n != 0 {
		t.Fatal("the retry brought back an acked message")
	}
	// In the table, too: memory's tomb for the ack would hide a message the
	// retry listed again, until the stream brought it. The record keeps no
	// signature.
	var req protocol.SendRequest
	_ = json.Unmarshal(*sent, &req)
	it := s.stored(t, b.Address(), sha256.Sum256(req.Ciphertext))
	if _, ok := it["live"]; ok || it == nil {
		t.Fatalf("after the ack and the retry: %v", it)
	}
	if _, ok := it["sig"]; ok {
		t.Fatal("the acked message's record kept its signature")
	}
	id := sha256.Sum256(req.Ciphertext)
	if s.bodyExists(t, b.Address(), id) {
		t.Fatal("the ack left the body")
	}
	if err := s.DeleteMessage(context.Background(), b.Address(), id); !errors.Is(err, ErrNotFound) {
		t.Fatalf("a second ack: %v", err)
	}
	if res := receive(t, b); len(res.Delivered) != 0 {
		t.Fatal("delivered twice")
	}
}

func TestCrashBetweenAnAcksDeletes(t *testing.T) {
	e, s := dynamoEnv(t)
	a, b := e.box(protocol.Classic), e.box(protocol.Classic)
	ctx := context.Background()
	send(t, a, b, "acked halfway")
	failOnce(s, "ack: after the body")
	res, err := b.Receive(ctx)
	if err == nil || res == nil || len(res.Delivered) != 1 {
		t.Fatalf("first drain: %v", err)
	}
	if n, _, _ := s.Count(ctx, b.Address()); n != 1 {
		t.Fatal("the message left the list with the body")
	}
	// The client acks again on its next drain, and it leaves the list.
	res = receive(t, b)
	if len(res.Delivered) != 0 || len(res.Duplicates) != 0 || len(res.Refused) != 0 {
		t.Fatalf("second drain: %+v", res)
	}
	if n, _, _ := s.Count(ctx, b.Address()); n != 0 {
		t.Fatal("not acked on the second drain")
	}
}

func TestHeaderWithoutBodyIsGone(t *testing.T) {
	e, s := dynamoEnv(t)
	a, b := e.box(protocol.Classic), e.box(protocol.Classic)
	ctx := context.Background()
	id := idOf(t, send(t, a, b, "its body expires early"))
	if _, _, err := s.Message(ctx, b.Address(), id); err != nil {
		t.Fatal(err)
	}
	if err := s.deleteBody(ctx, b.Address(), id); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Message(ctx, b.Address(), id); !errors.Is(err, ErrNotFound) {
		t.Fatalf("fetch: %v, want gone", err)
	}
	if s.listed(t, b.Address(), id) {
		t.Fatal("the bodiless message is still listed")
	}
	if n, _, _ := s.Count(ctx, b.Address()); n != 0 {
		t.Fatal("still counted")
	}
}

// An acked message is never served, even if its body comes back: a send
// whose dedupe read was stale writes the body before its conditional write
// finds the acked item, leaving a body the lifecycle rule reaps.
func TestAckedMessageWithABodyAgainIsGone(t *testing.T) {
	e, s := dynamoEnv(t)
	a, b := e.box(protocol.Classic), e.box(protocol.Classic)
	ctx := context.Background()
	id := idOf(t, send(t, a, b, "acked, then its body rewritten"))
	if res := receive(t, b); len(res.Delivered) != 1 {
		t.Fatalf("delivered %d", len(res.Delivered))
	}
	if _, err := s.s3.PutObject(ctx, &s3.PutObjectInput{Bucket: &s.bucket, Key: aws.String(bodyKey(b.Address(), id)), Body: strings.NewReader("ciphertext")}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Message(ctx, b.Address(), id); !errors.Is(err, ErrNotFound) {
		t.Fatalf("fetch of an acked message: %v", err)
	}
}

// Two processes on one pair of tables: what one writes reaches the other
// through the streams, and an id the other has not heard of yet is read by
// its key.
func TestTwoProcesses(t *testing.T) {
	e, _ := dynamoEnv(t)
	ctx := context.Background()
	other := startDynamo(t, e.clock.Now)
	srv2 := httptest.NewServer(New(Config{Store: other, Keys: e.keys, Limits: relaxed(), Now: e.clock.Now, Ready: other.Ready}).Handler())
	t.Cleanup(srv2.Close)
	e2 := &env{t: t, clock: e.clock, store: other, srv: srv2}

	a, b := e.box(protocol.Classic), e.box(protocol.Classic)
	tok := func() string {
		tk, err := os.ReadFile(filepath.Join(b.Dir(), "token"))
		if err != nil {
			t.Fatal(err)
		}
		return strings.TrimSpace(string(tk))
	}
	waitFor := func(what string, ok func() bool) time.Duration {
		t.Helper()
		start := time.Now()
		for time.Since(start) < 15*time.Second {
			if ok() {
				return time.Since(start)
			}
			time.Sleep(50 * time.Millisecond)
		}
		t.Fatalf("%s: not within 15 s", what)
		return 0
	}
	count := func(s Store) int {
		n, _, _ := s.Count(ctx, b.Address())
		return n
	}

	// An ack on the other process before it has heard of the message.
	id := idOf(t, send(t, a, b, "acked elsewhere at once"))
	if r := e2.do(http.MethodDelete, "/v1/"+b.Address().String()+"/messages/"+hexID(id), nil, tok()); r.status != http.StatusNoContent {
		t.Fatalf("ack on the other process: %d %s", r.status, r.body)
	}
	took := waitFor("the ack reaching the first process", func() bool { return count(e.store) == 0 })
	t.Logf("an ack on the second process reached the first in %s", took)

	// A send reaches the other process's count.
	send(t, a, b, "seen elsewhere")
	took = waitFor("the send reaching the other process", func() bool { return count(other) == 1 })
	t.Logf("a send on the first process reached the second in %s", took)
	if r := e2.do(http.MethodGet, "/v1/"+b.Address().String()+"/messages", nil, tok()); r.status != http.StatusOK || !strings.Contains(string(r.body), `"count":1`) {
		t.Fatalf("list on the other process: %d %s", r.status, r.body)
	}

	// A new prekey bumps the epoch: the other process refuses the old token
	// from memory once the stream brings it.
	old := tok()
	if _, err := b.Rekey(ctx, ""); err != nil {
		t.Fatal(err)
	}
	waitFor("the epoch reaching the other process", func() bool {
		st, err := other.Standing(ctx, b.Address())
		return err == nil && st.Epoch == 1
	})
	if r := e2.do(http.MethodGet, "/v1/"+b.Address().String()+"/messages", nil, old); r.code() != protocol.CodeTokenStale {
		t.Fatalf("old token on the other process: %d %s", r.status, r.body)
	}
}

// A restart starts with empty memory and is ready at once; each box is read
// on its first use, once, and answered from memory after that.
func TestRestartLoadsLazily(t *testing.T) {
	e, _ := dynamoEnv(t)
	ctx := context.Background()
	a, b, c, d, f := e.box(protocol.Classic), e.box(protocol.Classic), e.box(protocol.Classic), e.box(protocol.Classic), e.box(protocol.Classic)
	send(t, a, b, "one")
	send(t, a, b, "two")
	send(t, a, f, "three")
	if _, err := c.Rekey(ctx, ""); err != nil {
		t.Fatal(err)
	}
	send(t, a, d, "deleted by the close")
	if r := e.do(http.MethodDelete, "/v1/"+d.Address().String(), nil, tokenOf(t, d)); r.status != http.StatusNoContent {
		t.Fatalf("close: %d %s", r.status, r.body)
	}
	_, version, _ := e.store.Count(ctx, b.Address())

	fresh := startDynamo(t, e.clock.Now)
	if !fresh.Ready() || fresh.loads.Load() != 0 {
		t.Fatalf("ready %v after %d loads: want ready with none", fresh.Ready(), fresh.loads.Load())
	}
	// Each of these is its box's first use.
	if n, _, _ := fresh.PairCount(ctx, b.Address(), a.Address()); n != 2 {
		t.Fatalf("pair count %d", n)
	}
	if n, _, _ := fresh.Count(ctx, f.Address()); n != 1 {
		t.Fatalf("count %d", n)
	}
	if n, v, _ := fresh.Count(ctx, b.Address()); n != 2 || v != version {
		t.Fatalf("count %d, version %x; want 2, %x", n, v, version)
	}
	if n := fresh.loads.Load(); n != 2 {
		t.Fatalf("%d loads for two boxes", n)
	}
	if st, err := fresh.Standing(ctx, c.Address()); err != nil || st.Epoch != 1 {
		t.Fatalf("rekeyed box: %v %v", st, err)
	}
	if st, err := fresh.Standing(ctx, d.Address()); err != nil || st.State != Closed {
		t.Fatalf("closed box: %v %v", st, err)
	}
	if n, _, _ := fresh.Count(ctx, d.Address()); n != 0 {
		t.Fatal("the close left mail in the table")
	}
	var nobody protocol.Address
	if _, err := fresh.Standing(ctx, nobody); !errors.Is(err, ErrNotFound) {
		t.Fatalf("no box: %v", err)
	}
}

// Polls read a box once per process, on its first use: every later poll,
// empty or not, is answered from memory, kept current by the stream.
func TestPollsReadOncePerProcess(t *testing.T) {
	e, s := dynamoEnv(t)
	a, b := e.box(protocol.Classic), e.box(protocol.Classic)
	poll := func() reply {
		e.clock.Add(time.Minute) // past the poll limit
		return e.do(http.MethodGet, "/v1/"+b.Address().String()+"/messages", nil, tokenOf(t, b))
	}
	if r := poll(); r.status != http.StatusOK {
		t.Fatalf("%d %s", r.status, r.body)
	}
	before := s.loads.Load()
	for range 3 {
		if r := poll(); r.status != http.StatusOK || !strings.Contains(string(r.body), `"count":0`) {
			t.Fatalf("%d %s", r.status, r.body)
		}
	}
	send(t, a, b, "counted from memory")
	if r := poll(); !strings.Contains(string(r.body), `"count":1`) {
		t.Fatalf("after a send: %s", r.body)
	}
	if n := s.loads.Load() - before; n != 0 {
		t.Fatalf("%d loads after the first poll", n)
	}
}

// A throttled store answers 503 with Retry-After, never a wrong answer.
type throttled struct{ Store }

func (throttled) Count(context.Context, protocol.Address) (int, uint64, error) {
	return 0, 0, &smithy.GenericAPIError{Code: "ProvisionedThroughputExceededException", Message: "slow down"}
}

func TestThrottleIs503(t *testing.T) {
	e := newEnv(t, relaxed())
	b := e.box(protocol.Classic)
	tk, _ := os.ReadFile(filepath.Join(b.Dir(), "token"))
	srv := httptest.NewServer(New(Config{Store: throttled{e.store}, Keys: e.keys, Limits: relaxed(), Now: e.clock.Now}).Handler())
	defer srv.Close()
	e2 := &env{t: t, clock: e.clock, srv: srv}
	r := e2.do(http.MethodGet, "/v1/"+b.Address().String()+"/messages", nil, strings.TrimSpace(string(tk)))
	if r.status != http.StatusServiceUnavailable || r.code() != protocol.CodeUnavailable || r.header.Get("Retry-After") == "" {
		t.Fatalf("%d %s, Retry-After %q", r.status, r.body, r.header.Get("Retry-After"))
	}
	if !IsThrottle(&smithy.GenericAPIError{Code: "ThrottlingException"}) || IsThrottle(errors.New("other")) {
		t.Fatal("IsThrottle")
	}
}

// Until the store has loaded its memory, every call is a 503.
func TestNotReadyIs503(t *testing.T) {
	keys, _ := NewDevKeys()
	srv := httptest.NewServer(New(Config{Store: NewMemStore(time.Now), Keys: keys, Limits: relaxed(), Ready: func() bool { return false }}).Handler())
	defer srv.Close()
	e := &env{t: t, srv: srv}
	var a protocol.Address
	if r := e.do(http.MethodGet, "/v1/"+a.String()+"/messages", nil, "igt1_x"); r.status != http.StatusServiceUnavailable || r.header.Get("Retry-After") == "" {
		t.Fatalf("%d %s", r.status, r.body)
	}
}

func TestLoadKeys(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "keys")
	k32 := "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="
	if err := os.WriteFile(path, []byte("# server token keys\n2 "+k32+"\n1 "+k32+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	k, err := LoadKeys(path)
	if err != nil || k.Current != 2 || len(k.keys) != 2 {
		t.Fatalf("%v %+v", err, k)
	}
	var a protocol.Address
	if err := k.Check(a, 0, k.Mint(a, 0)); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadKeys(path); err == nil {
		t.Fatal("a group-readable key file was loaded")
	}
	for _, bad := range []string{"", "1\n", "1 c2hvcnQ=\n", "1 " + k32 + "\n1 " + k32 + "\n", "x " + k32 + "\n"} {
		_ = os.WriteFile(path, []byte(bad), 0o600)
		_ = os.Chmod(path, 0o600)
		if _, err := LoadKeys(path); err == nil {
			t.Fatalf("loaded %q", bad)
		}
	}
}

// countingStore counts the calls that read storage, and the ack, which
// writes it.
type countingStore struct {
	Store
	reads atomic.Int64
}

func (c *countingStore) Box(ctx context.Context, a protocol.Address) (*Box, error) {
	c.reads.Add(1)
	return c.Store.Box(ctx, a)
}

func (c *countingStore) List(ctx context.Context, box protocol.Address, after *Cursor, limit int) ([]Header, error) {
	c.reads.Add(1)
	return c.Store.List(ctx, box, after, limit)
}

func (c *countingStore) Dedupe(ctx context.Context, box protocol.Address, id [32]byte) (*Header, error) {
	c.reads.Add(1)
	return c.Store.Dedupe(ctx, box, id)
}

func (c *countingStore) Message(ctx context.Context, box protocol.Address, id [32]byte) (*Header, []byte, error) {
	c.reads.Add(1)
	return c.Store.Message(ctx, box, id)
}

func (c *countingStore) DeleteMessage(ctx context.Context, box protocol.Address, id [32]byte) error {
	c.reads.Add(1)
	return c.Store.DeleteMessage(ctx, box, id)
}

func tokenOf(t *testing.T, b *client.Box) string {
	t.Helper()
	tk, err := os.ReadFile(filepath.Join(b.Dir(), "token"))
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(tk))
}

// An empty poll never leaves the process (ARCHITECTURE.md § Memory): an active
// box at epoch 0, a rekeyed one, a stale token and a closed box are all
// answered from memory.
func TestPollStaysInMemory(t *testing.T) {
	e := newEnv(t, relaxed())
	ctx := context.Background()
	b, c := e.box(protocol.Classic), e.box(protocol.Classic)
	cs := &countingStore{Store: e.store}
	srv := httptest.NewServer(New(Config{Store: cs, Keys: e.keys, Limits: relaxed(), Now: e.clock.Now}).Handler())
	defer srv.Close()
	e2 := &env{t: t, srv: srv}
	poll := func(x *client.Box, tok string) reply {
		return e2.do(http.MethodGet, "/v1/"+x.Address().String()+"/messages", nil, tok)
	}

	if r := poll(b, tokenOf(t, b)); r.status != http.StatusOK {
		t.Fatalf("active box: %d %s", r.status, r.body)
	}
	old := tokenOf(t, c)
	if _, err := c.Rekey(ctx, ""); err != nil {
		t.Fatal(err)
	}
	if r := poll(c, tokenOf(t, c)); r.status != http.StatusOK {
		t.Fatalf("rekeyed box: %d %s", r.status, r.body)
	}
	if r := poll(c, old); r.code() != protocol.CodeTokenStale {
		t.Fatalf("stale token: %d %s", r.status, r.body)
	}
	if r := e.do(http.MethodDelete, "/v1/"+c.Address().String(), nil, tokenOf(t, c)); r.status != http.StatusNoContent {
		t.Fatalf("close: %d %s", r.status, r.body)
	}
	if r := poll(c, tokenOf(t, c)); r.code() != protocol.CodeNoSuchMailbox {
		t.Fatalf("closed box: %d %s", r.status, r.body)
	}
	before := cs.reads.Load()
	rec, err := e.store.Box(ctx, b.Address())
	if err != nil {
		t.Fatal(err)
	}
	rec.State = Revoked
	if err := e.store.UpdateBox(ctx, rec); err != nil {
		t.Fatal(err)
	}
	if cs.reads.Load() != before {
		t.Fatal("the test's own reads were counted")
	}
	if r := poll(b, tokenOf(t, b)); r.code() != protocol.CodeRevoked {
		t.Fatalf("revoked box: %d %s", r.status, r.body)
	}
	if n := cs.reads.Load(); n != 0 {
		t.Fatalf("%d storage reads for polls", n)
	}
}

// A header past its expiry is never listed, though the TTL has not deleted
// it yet.
func TestExpiredHeadersAreNotListed(t *testing.T) {
	e := newEnv(t, relaxed())
	a, b := e.box(protocol.Classic), e.box(protocol.Classic)
	send(t, a, b, "expires first")
	e.clock.Add(protocol.TTL / 2)
	live := send(t, a, b, "still live")
	e.clock.Add(protocol.TTL / 2)
	r := e.do(http.MethodGet, "/v1/"+b.Address().String()+"/messages", nil, tokenOf(t, b))
	var l protocol.MessageList
	_ = json.Unmarshal(r.body, &l)
	if r.status != http.StatusOK || l.Count != 1 || len(l.Messages) != 1 || l.Messages[0].ID != live.ID {
		t.Fatalf("%d %s", r.status, r.body)
	}
	e.clock.Add(protocol.TTL / 2)
	if r := e.do(http.MethodGet, "/v1/"+b.Address().String()+"/messages/"+live.ID, nil, tokenOf(t, b)); r.code() != protocol.CodeNoSuchMessage {
		t.Fatalf("fetch after expiry: %d %s", r.status, r.body)
	}
	if r := e.do(http.MethodDelete, "/v1/"+b.Address().String()+"/messages/"+live.ID, nil, tokenOf(t, b)); r.code() != protocol.CodeNoSuchMessage {
		t.Fatalf("ack after expiry: %d %s", r.status, r.body)
	}
}

// The dedupe record spans the TTL: the same bytes sent again inside it get
// the original receipt. Past it they cannot come back at all, since they
// name a prekey that lives at most the TTL: it has expired, or been renewed.
func TestResendAfterExpiryIsRefused(t *testing.T) {
	e := newEnv(t, relaxed())
	a, b := e.box(protocol.Classic), e.box(protocol.Classic)
	sent := capture(e, http.MethodPost, "/v1/"+b.Address().String())
	first := send(t, a, b, "once, then again")
	e.setMiddle(nil)
	e.clock.Add(protocol.TTL - time.Second)
	code, out := post(t, e.srv.URL+"/v1/"+b.Address().String(), *sent)
	var r protocol.Receipt
	_ = json.Unmarshal(out, &r)
	if code != http.StatusOK || r.ReceivedAt != first.ReceivedAt {
		t.Fatalf("inside the TTL: %d %s", code, out)
	}
	e.clock.Add(time.Second)
	if code, out := post(t, e.srv.URL+"/v1/"+b.Address().String(), *sent); code != http.StatusConflict || !strings.Contains(string(out), `"prekey_expired"`) {
		t.Fatalf("past the TTL: %d %s", code, out)
	}
}

// Only a box's record (sk 0x00) is memory's: another item under the box,
// whatever it holds, changes nothing on the stream.
func TestOnlyTheBoxRecordIsMemorys(t *testing.T) {
	s := NewDynamoStore(DynamoConfig{BoxCache: 10})
	var a protocol.Address
	a[0] = 7
	if err := s.idx.ensure(context.Background(), a, func() (boxRead, error) {
		return boxRead{exists: true, st: Standing{State: Closed}, rev: 1}, nil
	}); err != nil {
		t.Fatal(err)
	}
	b := func(v []byte) stypes.AttributeValue { return &stypes.AttributeValueMemberB{Value: v} }
	keys := func(sk []byte) map[string]stypes.AttributeValue {
		return map[string]stypes.AttributeValue{"addr": b(a[:]), "sk": b(sk)}
	}
	other := keys([]byte("a-later-item"))
	img := map[string]stypes.AttributeValue{
		"addr": other["addr"], "sk": other["sk"], "state": &stypes.AttributeValueMemberS{Value: string(Revoked)},
		"epoch": &stypes.AttributeValueMemberN{Value: "7"}, "rev": &stypes.AttributeValueMemberN{Value: "9"},
	}
	record := func(op stypes.OperationType, k, img map[string]stypes.AttributeValue) stypes.Record {
		return stypes.Record{EventName: op, Dynamodb: &stypes.StreamRecord{Keys: k, NewImage: img}}
	}
	standing := func() (Standing, bool) { return s.idx.standing(a) }
	s.applyBoxRecord(record(stypes.OperationTypeInsert, other, img))
	if st, _ := standing(); st.State != Closed {
		t.Fatalf("another item set the standing: %v", st)
	}
	s.applyBoxRecord(record(stypes.OperationTypeRemove, other, nil))
	if _, ok := standing(); !ok {
		t.Fatal("another item's removal dropped the box")
	}
	s.applyBoxRecord(record(stypes.OperationTypeRemove, keys([]byte{skBox}), nil))
	if _, ok := standing(); ok {
		t.Fatal("the record's removal was not applied")
	}
}

// A box's record is only written over the revision it was read at.
func TestUpdateBoxIsConditional(t *testing.T) {
	e := newEnv(t, relaxed())
	ctx := context.Background()
	b := e.box(protocol.Classic)
	first, _ := e.store.Box(ctx, b.Address())
	second, _ := e.store.Box(ctx, b.Address())
	first.Epoch++
	if err := e.store.UpdateBox(ctx, first); err != nil {
		t.Fatal(err)
	}
	second.State = Closed
	if err := e.store.UpdateBox(ctx, second); !errors.Is(err, ErrStale) {
		t.Fatalf("an update over a stale read: %v", err)
	}
	if got, _ := e.store.Box(ctx, b.Address()); got.State != Active || got.Epoch != first.Epoch {
		t.Fatalf("stored %v at epoch %d", got.State, got.Epoch)
	}
}

// Closing a box deletes its mail, bodies included: a sender's retry after
// the box is closed and reopened is answered, and nothing comes back.
func TestRetryAfterCloseIsNotRedelivered(t *testing.T) {
	e := newEnv(t, relaxed())
	ctx := context.Background()
	a, b := e.box(protocol.Classic), e.box(protocol.Classic)
	sent := capture(e, http.MethodPost, "/v1/"+b.Address().String())
	send(t, a, b, "deleted unread")
	e.setMiddle(nil)
	if r := e.do(http.MethodDelete, "/v1/"+b.Address().String(), nil, tokenOf(t, b)); r.status != http.StatusNoContent {
		t.Fatalf("close: %d %s", r.status, r.body)
	}
	if _, err := b.Rekey(ctx, ""); err != nil { // reopen
		t.Fatal(err)
	}
	receive(t, b) // activates it
	// A retry of the same bytes names the retired serial: it is stale, and
	// never reaches the dedupe record.
	var req protocol.SendRequest
	_ = json.Unmarshal(*sent, &req)
	if code, out := post(t, e.srv.URL+"/v1/"+b.Address().String(), *sent); code != http.StatusConflict || !strings.Contains(string(out), `"stale_prekey"`) {
		t.Fatalf("retry: %d %s", code, out)
	}
	if res := receive(t, b); len(res.Delivered) != 0 {
		t.Fatal("mail deleted by the close came back")
	}
	if s, ok := e.store.(*DynamoStore); ok {
		if id := sha256.Sum256(req.Ciphertext); s.listed(t, b.Address(), id) || s.bodyExists(t, b.Address(), id) {
			t.Fatal("mail the close deleted is still listed, or its body kept")
		}
	}
}

func TestBoxCache(t *testing.T) {
	var a1, a2, a3 protocol.Address
	a1[0], a2[0], a3[0] = 1, 2, 3
	c := newBoxCache(2)
	c.put(&Box{Addr: a1, Rev: 3})
	c.put(&Box{Addr: a1, Rev: 2})
	if b, _ := c.get(a1); b.Rev != 3 {
		t.Fatalf("rev %d: an older record replaced a newer one", b.Rev)
	}
	c.refresh(a1, 3, func() (*Box, error) { return &Box{Addr: a1, Rev: 3, Epoch: 9}, nil })
	if b, _ := c.get(a1); b.Epoch == 9 {
		t.Fatal("refreshed at the same rev")
	}
	c.refresh(a1, 4, func() (*Box, error) { return &Box{Addr: a1, Rev: 4}, nil })
	if b, _ := c.get(a1); b.Rev != 4 {
		t.Fatal("not refreshed to a newer rev")
	}
	c.refresh(a2, 1, func() (*Box, error) { return &Box{Addr: a2, Rev: 1}, nil })
	if _, ok := c.get(a2); ok {
		t.Fatal("refresh cached a record it did not hold")
	}
	c.put(&Box{Addr: a2, Rev: 1})
	c.get(a1)
	c.put(&Box{Addr: a3, Rev: 1}) // evicts a2, the least recently used
	if _, ok := c.get(a2); ok {
		t.Fatal("over its size")
	}
	if _, ok := c.get(a1); !ok {
		t.Fatal("evicted the recently used record")
	}
	c.evict(a1)
	if _, ok := c.get(a1); ok {
		t.Fatal("not evicted")
	}
}

// A call whose token is missing or not ours reads the record, never memory:
// the box's state answers first, as for a box this process has not used.
func TestCallsWithoutOurTokenReadTheRecord(t *testing.T) {
	e := newEnv(t, relaxed())
	ctx := context.Background()
	poll := func(a protocol.Address, tok string) reply {
		return e.do(http.MethodGet, "/v1/"+a.String()+"/messages", nil, tok)
	}
	set := func(x *client.Box, f func(*Box)) {
		rec, err := e.store.Box(ctx, x.Address())
		if err != nil {
			t.Fatal(err)
		}
		f(rec)
		if err := e.store.UpdateBox(ctx, rec); err != nil {
			t.Fatal(err)
		}
	}
	b, c, d := e.box(protocol.Classic), e.box(protocol.Classic), e.box(protocol.Classic)
	if r := poll(b.Address(), "igt1_not-a-token"); r.code() != protocol.CodeUnauthorized {
		t.Fatalf("bad token: %d %s", r.status, r.body)
	}
	if r := poll(b.Address(), tokenOf(t, c)); r.code() != protocol.CodeUnauthorized {
		t.Fatalf("another box's token: %d %s", r.status, r.body)
	}
	var nobody protocol.Address
	if r := poll(nobody, "igt1_x"); r.code() != protocol.CodeNoSuchMailbox {
		t.Fatalf("unknown box: %d %s", r.status, r.body)
	}
	// Our token, but no record (a box this server never registered here).
	if r := poll(nobody, e.keys.Mint(nobody, 0)); r.code() != protocol.CodeNoSuchMailbox {
		t.Fatalf("our token, no box: %d %s", r.status, r.body)
	}
	set(c, func(x *Box) { x.State = Closed })
	if r := poll(c.Address(), "igt1_x"); r.code() != protocol.CodeNoSuchMailbox {
		t.Fatalf("closed box: %d %s", r.status, r.body)
	}
	set(d, func(x *Box) { x.State = Revoked })
	if r := poll(d.Address(), ""); r.code() != protocol.CodeRevoked {
		t.Fatalf("revoked box, no token: %d %s", r.status, r.body)
	}
}

package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/IronGall-dev/irongall-client/client"
	"github.com/IronGall-dev/irongall-client/protocol"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

func TestAdoptKeys(t *testing.T) {
	k, _ := NewDevKeys()
	var id [16]byte
	id[0] = 7
	key := k.MintAdopt("echo", id)
	if acc, got, err := k.VerifyAdopt(key); err != nil || acc != "echo" || got != id {
		t.Fatalf("verify: %q %x %v", acc, got, err)
	}
	other, _ := NewDevKeys()
	raw, _ := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(key, adoptPrefix))
	flip := func(i int) string {
		b := append([]byte(nil), raw...)
		b[i] ^= 1
		return adoptPrefix + base64.RawURLEncoding.EncodeToString(b)
	}
	for name, bad := range map[string]string{
		"another server's": other.MintAdopt("echo", id),
		"a token":          k.Mint(protocol.Address{}, 1),
		"no prefix":        strings.TrimPrefix(key, adoptPrefix),
		"truncated":        key[:len(key)-4],
		"another key id":   flip(1),
		"another account":  flip(18),
		"a longer account": flip(17),
		"a bad mac":        flip(len(raw) - 1),
		"a bad account id": k.MintAdopt("Echo", id),
		"an unknown kid":   flip(0),
		"not base64":       adoptPrefix + "!!",
		"an empty one":     "",
		"an empty account": k.MintAdopt("", id),
		"a too-long one":   key + "AAAA",
		"too short":        adoptPrefix + "AAAA",
		"a length past the end": func() string {
			b := append([]byte(nil), raw...)
			b[17] = 255
			return adoptPrefix + base64.RawURLEncoding.EncodeToString(b)
		}(),
	} {
		if _, _, err := k.VerifyAdopt(bad); err == nil {
			t.Errorf("%s: verified", name)
		}
	}
}

// accountEnv is an env with an account, unmetered or not, and an adopt key
// into it with the given uses.
func accountEnv(t *testing.T, e *env, unmetered bool, uses int) (*Account, string) {
	t.Helper()
	ctx := context.Background()
	id, err := NewAccountID()
	if err != nil {
		t.Fatal(err)
	}
	a, err := NewAccount(id, unmetered)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.store.CreateAccount(ctx, a); err != nil {
		t.Fatal(err)
	}
	if err := e.store.CreateAccount(ctx, &Account{ID: id}); !errors.Is(err, ErrExists) {
		t.Fatalf("the account again: %v", err)
	}
	return a, e.adoptKey(t, id, uses, time.Hour)
}

func (e *env) adoptKey(t *testing.T, account string, uses int, ttl time.Duration) string {
	t.Helper()
	k := &AdoptKey{Account: account, Uses: uses, Expires: e.clock.Now().Add(ttl)}
	_, _ = rand.Read(k.ID[:])
	if err := e.store.PutAdoptKey(context.Background(), k); err != nil {
		t.Fatal(err)
	}
	if err := e.store.PutAdoptKey(context.Background(), k); !errors.Is(err, ErrExists) {
		t.Fatalf("the key again: %v", err)
	}
	return e.keys.MintAdopt(account, k.ID)
}

func (e *env) accountOf(b *client.Box) string {
	e.t.Helper()
	r, err := e.store.Box(context.Background(), b.Address())
	if err != nil {
		e.t.Fatal(err)
	}
	return r.Account
}

func adopt(t *testing.T, b *client.Box, key string) string {
	t.Helper()
	acc, err := b.Adopt(context.Background(), key)
	if err != nil {
		t.Fatalf("adopt: %v", err)
	}
	return acc
}

func TestAccounts(t *testing.T) {
	ctx := context.Background()
	l := relaxed()
	l.SendsPerDay, l.MaxSize, l.AccountMaxSize = 2, 1024, 4096

	t.Run("an unmetered account lifts the daily limit and the cap", func(t *testing.T) {
		e := newEnv(t, l)
		acc, key := accountEnv(t, e, true, 1)
		a, b, c := e.box(protocol.Classic), e.box(protocol.Classic), e.box(protocol.Classic)
		if got := adopt(t, a, key); got != acc.ID || e.accountOf(a) != acc.ID {
			t.Fatalf("adopted into %q, the record says %q", got, e.accountOf(a))
		}
		for i := range 3 {
			send(t, a, b, strings.Repeat("x", 100*i))
		}
		send(t, a, b, strings.Repeat("x", 2000)) // over 1024
		if _, err := a.Send(ctx, b.Address(), strings.Repeat("x", 5000)); client.Code(err) != protocol.CodeTooLarge || !strings.Contains(err.Error(), "4096") {
			t.Fatalf("over the largest cap: %v", err)
		}
		// A box in no account has the server's limits.
		send(t, c, b, "1")
		if _, err := c.Send(ctx, b.Address(), strings.Repeat("x", 2000)); client.Code(err) != protocol.CodeTooLarge || !strings.Contains(err.Error(), "1024") {
			t.Fatalf("over the cap: %v", err)
		}
		send(t, c, b, "2")
		if _, err := c.Send(ctx, b.Address(), "3"); client.Code(err) != protocol.CodeRateLimited {
			t.Fatalf("third send: %v", err)
		}
		// The key's one use is spent.
		if _, err := c.Adopt(ctx, key); client.Code(err) != protocol.CodeAdoptKeyRefused {
			t.Fatalf("a spent key: %v", err)
		}
		// Leaving gives a back the server's limits; sends in the account
		// counted for nothing.
		if err := a.Leave(ctx); err != nil || e.accountOf(a) != "" {
			t.Fatalf("leave: %v, account %q", err, e.accountOf(a))
		}
		if err := a.Leave(ctx); err != nil {
			t.Fatalf("leave again: %v", err)
		}
		if _, err := a.Send(ctx, b.Address(), strings.Repeat("x", 2000)); client.Code(err) != protocol.CodeTooLarge {
			t.Fatalf("after leaving, over the cap: %v", err)
		}
		send(t, a, b, "4")
		send(t, a, b, "5")
		if _, err := a.Send(ctx, b.Address(), "6"); client.Code(err) != protocol.CodeRateLimited {
			t.Fatalf("after leaving, a third send: %v", err)
		}
	})

	t.Run("a metered account has the free limits until credit exists", func(t *testing.T) {
		e := newEnv(t, l)
		_, key := accountEnv(t, e, false, 1)
		a, b := e.box(protocol.Classic), e.box(protocol.Classic)
		adopt(t, a, key)
		send(t, a, b, "1")
		send(t, a, b, "2")
		if _, err := a.Send(ctx, b.Address(), "3"); client.Code(err) != protocol.CodeRateLimited {
			t.Fatalf("third send: %v", err)
		}
	})

	t.Run("keys that are refused", func(t *testing.T) {
		e := newEnv(t, l)
		acc, key := accountEnv(t, e, true, 2)
		a, b := e.box(protocol.Classic), e.box(protocol.Classic)
		other, _ := NewDevKeys()
		var unstored [16]byte
		unstored[0] = 1
		expiring := e.adoptKey(t, acc.ID, 1, time.Minute)
		e.clock.Add(2 * time.Minute)
		for name, k := range map[string]string{
			"another server's": other.MintAdopt(acc.ID, unstored),
			"never stored":     e.keys.MintAdopt(acc.ID, unstored),
			"expired":          expiring,
			"not a key":        "iga1_x",
		} {
			if _, err := a.Adopt(ctx, k); client.Code(err) != protocol.CodeAdoptKeyRefused {
				t.Errorf("%s: %v", name, err)
			}
		}
		if e.accountOf(a) != "" {
			t.Fatal("a refused key adopted the box")
		}
		// Adopting into the account the box is already in spends no use.
		adopt(t, a, key)
		adopt(t, a, key)
		adopt(t, b, key)
		if _, err := e.box(protocol.Classic).Adopt(ctx, key); client.Code(err) != protocol.CodeAdoptKeyRefused {
			t.Fatalf("a third box on a two-use key: %v", err)
		}
	})

	t.Run("moving to another account", func(t *testing.T) {
		e := newEnv(t, l)
		first, key1 := accountEnv(t, e, false, 1)
		second, key2 := accountEnv(t, e, true, 1)
		a := e.box(protocol.Classic)
		adopt(t, a, key1)
		if got := adopt(t, a, key2); got != second.ID || e.accountOf(a) != second.ID {
			t.Fatalf("moved to %q", e.accountOf(a))
		}
		if s, ok := e.store.(*DynamoStore); ok {
			if s.member(t, first.ID, a.Address()) || !s.member(t, second.ID, a.Address()) {
				t.Fatal("the accounts' side does not match the box record")
			}
			if err := a.Leave(ctx); err != nil {
				t.Fatal(err)
			}
			if s.member(t, second.ID, a.Address()) {
				t.Fatal("the account still holds a box that left")
			}
		}
	})

	t.Run("calls that are refused", func(t *testing.T) {
		e := newEnv(t, l)
		r := newRaw(t)
		r.prekey(t, 1, e.clock.Now().Add(30*24*time.Hour), nil)
		reg := e.do(http.MethodPut, r.path(""), r.registration(1), "")
		tok := r.token(t, reg)
		e.want(e.do(http.MethodPut, r.path("/account"), protocol.AdoptRequest{Key: "x"}, ""), 401, protocol.CodeUnauthorized)
		e.want(e.do(http.MethodPut, r.path("/account"), []byte(`{"key":1}`), tok), 400, protocol.CodeBadRequest)
		e.want(e.do(http.MethodDelete, r.path("/account"), nil, ""), 401, protocol.CodeUnauthorized)
		e.want(e.do(http.MethodDelete, r.path("/account"), nil, tok), 204, "")
		// Over the largest cap, a send is refused before anything else is
		// read: here, that the sender is no box at all.
		e.want(e.do(http.MethodPost, r.path(""), protocol.SendRequest{From: strings.Repeat("0", 64), Ciphertext: make([]byte, 4097), Signature: []byte("s")}, ""), 413, protocol.CodeTooLarge)
	})
}

// Adopt and Leave write only over the record they were given.
func TestAdoptAndLeaveNameTheRecord(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t, relaxed())
	acc, key := accountEnv(t, e, true, 1)
	_, id, _ := e.keys.VerifyAdopt(key)
	a := e.box(protocol.Classic)
	old, err := e.store.Box(ctx, a.Address())
	if err != nil {
		t.Fatal(err)
	}
	cur := cloneBox(old)
	if err := e.store.UpdateBox(ctx, cur); err != nil {
		t.Fatal(err)
	}
	if err := e.store.Adopt(ctx, cloneBox(old), acc.ID, id); !errors.Is(err, ErrStale) {
		t.Fatalf("adopt over an old record: %v", err)
	}
	if err := e.store.Adopt(ctx, cur, acc.ID, id); err != nil || cur.Account != acc.ID {
		t.Fatalf("adopt: %v", err)
	}
	stale := cloneBox(cur)
	stale.Rev--
	if err := e.store.Leave(ctx, stale); !errors.Is(err, ErrStale) {
		t.Fatalf("leave over an old record: %v", err)
	}
	if err := e.store.Leave(ctx, cur); err != nil || cur.Account != "" {
		t.Fatalf("leave: %v", err)
	}
}

// staleStore loses every race to adopt or leave.
type staleStore struct{ Store }

func (staleStore) Adopt(context.Context, *Box, string, [16]byte) error { return ErrStale }
func (staleStore) Leave(context.Context, *Box) error                   { return ErrStale }

func TestAdoptRaceIsAConflict(t *testing.T) {
	l := relaxed()
	e := newEnv(t, l)
	acc, key := accountEnv(t, e, true, 2)
	a := e.box(protocol.Classic)
	adopt(t, a, e.adoptKey(t, acc.ID, 1, time.Hour))
	stale := New(Config{Store: staleStore{e.store}, Keys: e.keys, Limits: l, Now: e.clock.Now}).Handler()
	e.setMiddle(func(w http.ResponseWriter, r *http.Request, _ http.Handler) { stale.ServeHTTP(w, r) })
	b := e.box(protocol.Classic)
	if _, err := b.Adopt(context.Background(), key); client.Code(err) != protocol.CodeConflict {
		t.Fatalf("adopt: %v", err)
	}
	if err := a.Leave(context.Background()); client.Code(err) != protocol.CodeConflict {
		t.Fatalf("leave: %v", err)
	}
}

// A change to an account reaches memory by the accounts stream: an operator
// makes a metered account unmetered by hand, then deletes it, and its box
// has the free limits again.
func TestAccountChangesReachMemory(t *testing.T) {
	if !onAWS() {
		t.Skip("needs the AWS tables")
	}
	ctx := context.Background()
	l := relaxed()
	l.SendsPerDay = 1
	e := newEnv(t, l)
	s := e.store.(*DynamoStore)
	acc, key := accountEnv(t, e, false, 1)
	a, b := e.box(protocol.Classic), e.box(protocol.Classic)
	adopt(t, a, key)
	send(t, a, b, "1")
	if _, err := a.Send(ctx, b.Address(), "2"); client.Code(err) != protocol.CodeRateLimited {
		t.Fatalf("second send: %v", err)
	}
	if _, err := s.db.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName: &s.accts, Key: accountKey(acc.ID, skAccount),
		UpdateExpression:          aws.String("SET #u = :t, #r = :r"),
		ExpressionAttributeNames:  map[string]string{"#u": "unmetered", "#r": "rev"},
		ExpressionAttributeValues: map[string]types.AttributeValue{":t": &types.AttributeValueMemberBOOL{Value: true}, ":r": num(2)},
	}); err != nil {
		t.Fatal(err)
	}
	until(t, func(i int) bool {
		_, err := a.Send(ctx, b.Address(), fmt.Sprintf("unmetered %d", i))
		return err == nil
	})
	if _, err := s.db.DeleteItem(ctx, &dynamodb.DeleteItemInput{TableName: &s.accts, Key: accountKey(acc.ID, skAccount)}); err != nil {
		t.Fatal(err)
	}
	until(t, func(i int) bool {
		_, err := a.Send(ctx, b.Address(), fmt.Sprintf("gone %d", i))
		return client.Code(err) == protocol.CodeRateLimited
	})
}

// until retries ok every 100 ms, for up to 10 s: the stream's delay.
func until(t *testing.T, ok func(i int) bool) {
	t.Helper()
	for i := range 100 {
		if ok(i) {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("the stream never brought the change")
}

// A send past the free cap's size waits for the one allowance for large
// reads; a smaller one never does, and one over the largest cap is refused
// at once.
func TestLargeReadsTakeTurns(t *testing.T) {
	l := relaxed()
	l.MaxSize, l.AccountMaxSize = 16<<10, 64<<10 // bodies read at once up to ~25 KB, at most ~91 KB
	keys, _ := NewDevKeys()
	srv := New(Config{Store: NewMemStore(time.Now), Keys: keys, Limits: l})
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	post := func(size int, wait time.Duration) (int, error) {
		j, _ := json.Marshal(protocol.SendRequest{From: strings.Repeat("0", 64), Ciphertext: make([]byte, size), Signature: []byte("s")})
		ctx, cancel := context.WithTimeout(context.Background(), wait)
		defer cancel()
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, ts.URL+"/v1/"+strings.Repeat("1", 64), bytes.NewReader(j))
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return 0, err
		}
		resp.Body.Close()
		return resp.StatusCode, nil
	}
	srv.largeRead <- struct{}{} // another large send is being read
	if _, err := post(30000, 300*time.Millisecond); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("a large send did not wait its turn: %v", err)
	}
	if code, err := post(500, 5*time.Second); err != nil || code != http.StatusBadRequest { // read, then not_age
		t.Fatalf("a small send waited: %d %v", code, err)
	}
	if code, err := post(100000, 5*time.Second); err != nil || code != http.StatusRequestEntityTooLarge {
		t.Fatalf("over the largest cap: %d %v", code, err)
	}
	<-srv.largeRead
	if code, err := post(30000, 5*time.Second); err != nil || code != http.StatusBadRequest {
		t.Fatalf("a large send with the allowance free: %d %v", code, err)
	}
	if len(srv.largeRead) != 0 {
		t.Fatal("the allowance was not given back")
	}
}

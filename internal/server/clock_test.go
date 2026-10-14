package server

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/IronGall-dev/irongall-client/client"
	"github.com/IronGall-dev/irongall-client/protocol"
)

// Every check is exact at the clock of whoever makes it, and whoever makes a
// time-limited thing leaves an hour of room (PROTOCOL.md §0). These tests
// give a box a clock of its own, set apart from the server's: every other
// test here shares one clock between the two, and so cannot see a check that
// only a second of difference fails.

// skewed returns the options of a box whose clock is *off from the server's.
func (e *env) skewed(off *time.Duration) client.Options {
	o := e.opts()
	o.Now = func() time.Time { return e.clock.Now().Add(*off) }
	return o
}

// A box whose clock is less than protocol.PassLifetime behind the server's,
// or up to protocol.MaxPassLifetime less protocol.PassLifetime ahead, works
// in full: it registers, mail under a certificate made that moment reaches
// it and is delivered, its own mail is delivered, and it renews.
func TestABoxWhoseClockIsOffByLessThanThePassAllows(t *testing.T) {
	ctx := context.Background()
	for _, off := range []time.Duration{-9 * time.Minute, -2 * time.Minute, -time.Second, time.Second, 2 * time.Second, 30 * time.Second, 3 * time.Minute, 49 * time.Minute} {
		e := newEnv(t, relaxed())
		b, err := client.Init(ctx, t.TempDir(), e.skewed(&off), protocol.Classic)
		if err != nil {
			t.Errorf("a clock %v off: init: %v", off, err)
			continue
		}
		fresh := e.box(protocol.Classic) // made this moment, on the server's clock: no certificate is newer
		if _, err := fresh.Send(ctx, b.Address(), "under a certificate made this moment"); err != nil {
			t.Errorf("a clock %v off: mail to it: %v", off, err)
		}
		if res, err := b.Receive(ctx); err != nil || len(res.Delivered) != 1 || len(res.Refused) != 0 {
			t.Errorf("a clock %v off: it reads: %+v, %v", off, res, err)
		}
		if _, err := b.Send(ctx, fresh.Address(), "from the box whose clock is off"); err != nil {
			t.Errorf("a clock %v off: it sends: %v", off, err)
		}
		if res, err := fresh.Receive(ctx); err != nil || len(res.Delivered) != 1 || len(res.Refused) != 0 {
			t.Errorf("a clock %v off: its mail is read: %+v, %v", off, res, err)
		}
		if _, err := b.Rekey(ctx, protocol.Classic); err != nil {
			t.Errorf("a clock %v off: it renews: %v", off, err)
		}
	}
}

// The two boxes at the far edges of what the server takes, 49 minutes fast
// and 9 slow, exchange mail under certificates made that moment.
func TestTheTwoClocksFurthestApart(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t, relaxed())
	fast, slow := 49*time.Minute, -9*time.Minute
	f, err := client.Init(ctx, t.TempDir(), e.skewed(&fast), protocol.Classic)
	if err != nil {
		t.Fatal(err)
	}
	s, err := client.Init(ctx, t.TempDir(), e.skewed(&slow), protocol.Classic)
	if err != nil {
		t.Fatal(err)
	}
	send(t, f, s, "from the fast box to the slow one")
	send(t, s, f, "from the slow box to the fast one")
	for _, b := range []*client.Box{f, s} {
		if res, err := b.Receive(ctx); err != nil || len(res.Delivered) != 1 || len(res.Refused) != 0 {
			t.Errorf("%+v, %v", res, err)
		}
	}
}

// Further off, the box is refused, and the server's words state what its
// clock reads and which way the caller's is likely off. For a pass refused
// for its time the client adds the date on the answer beside its own clock.
// A box that cannot register leaves nothing in the way of registering once
// its clock is right.
func TestABoxWhoseClockIsTooFarOffIsRefusedAndTold(t *testing.T) {
	ctx := context.Background()
	for _, c := range []struct {
		off  time.Duration
		code protocol.Code
		says []string
	}{
		{-11 * time.Minute, protocol.CodePassExpired, []string{"the pass has run out; the server's clock reads", "10 minutes or more behind the server's", "11m0s behind that"}},
		{51 * time.Minute, protocol.CodePassExpired, []string{"more than 60 minutes from now; the server's clock reads", "more than 50 minutes ahead of the server's", "51m0s ahead of that"}},
		{61 * time.Minute, protocol.CodeBadKey, []string{"has not begun; the server's clock reads", "more than an hour ahead of the server's", "irongall init for a new box"}},
	} {
		e := newEnv(t, relaxed())
		off, dir := c.off, t.TempDir()
		_, err := client.Init(ctx, dir, e.skewed(&off), protocol.Classic)
		if client.Code(err) != c.code {
			t.Errorf("a clock %v off: init: %v, want the code %s", c.off, err, c.code)
			continue
		}
		for _, s := range c.says {
			if !strings.Contains(err.Error(), s) {
				t.Errorf("a clock %v off: the refusal does not say %q: %v", c.off, s, err)
			}
		}
		if strings.Contains(strings.ToLower(err.Error()), "set this machine's clock") || strings.Contains(err.Error(), ": set it") {
			t.Errorf("a clock %v off: the refusal tells its reader to set the clock by the server's: %v", c.off, err)
		}
		off = 0
		if _, err := client.Init(ctx, dir, e.skewed(&off), protocol.Classic); err != nil {
			t.Errorf("a clock %v off, then set right: init: %v", c.off, err)
		}
	}
}

// A box holds a pass the server still takes, and its clock then goes back.
// Mail waits for it under a certificate that has not begun by the clock as
// it now reads: its sender's clock is 49 minutes fast, which the server
// takes, so that certificate starts 11 minutes back. A box that fetched that
// mail would refuse it and ack it. It does not fetch: it does not use a kept
// pass that has more left than it was signed for, and the server refuses the
// one it signs instead, which has run out by the server's clock. The mail is
// delivered when the clock is right.
func TestABoxWhoseClockGoesBackFetchesNothing(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t, relaxed())
	var off time.Duration
	b, err := client.Init(ctx, t.TempDir(), e.skewed(&off), protocol.Classic)
	if err != nil {
		t.Fatal(err)
	}
	if res := receive(t, b); len(res.Delivered) != 0 { // the pass is in the box now, and the server remembers it
		t.Fatal(res)
	}
	fast := 49 * time.Minute
	sender, err := client.Init(ctx, t.TempDir(), e.skewed(&fast), protocol.Classic)
	if err != nil {
		t.Fatal(err)
	}
	send(t, sender, b, "under a certificate that starts 11 minutes back")

	off = -12 * time.Minute
	res, err := b.Receive(ctx)
	if client.Code(err) != protocol.CodePassExpired || !strings.Contains(err.Error(), "12m0s behind that") || (res != nil && len(res.Delivered)+len(res.Refused) != 0) {
		t.Fatalf("its clock set back 12 minutes: %+v, %v", res, err)
	}
	// Control: at that clock the mail would be refused, so the stop above is
	// what kept it. The certificate it is signed under has not begun.
	first, _ := e.numbers(sender.Address())
	sig, rerr := os.ReadFile(filepath.Join(sender.Dir(), "prekeys", strconv.FormatUint(first, 10)+".txt.sig")) //nolint:gosec // a test's own file
	if rerr != nil {
		t.Fatal(rerr)
	}
	if began, err := protocol.CertificateBegan(sig); err != nil || !began.After(e.clock.Now().Add(off)) {
		t.Fatalf("the sender's certificate began %v, which is not after the reader's clock: the test does not reach the case", began)
	}
	off = 0
	if res := receive(t, b); len(res.Delivered) != 1 || len(res.Refused) != 0 {
		t.Fatalf("on time again: %+v", res)
	}
}

// The server takes a prekey statement that ends up to an hour past the 33
// days a client asks for, and refuses one a second longer, stating its
// clock. And it dates every answer by that clock.
func TestThePrekeyCeilingAndTheDateOnAnAnswer(t *testing.T) {
	e := newEnv(t, relaxed())
	now := e.clock.Now()
	for _, c := range []struct {
		ends   time.Duration
		status int
		code   protocol.Code
	}{
		{protocol.PrekeyLifetime, http.StatusCreated, ""},
		{protocol.PrekeyLifetime + 2*time.Second, http.StatusCreated, ""},
		{protocol.MaxPrekeyLifetime, http.StatusCreated, ""},
		{protocol.MaxPrekeyLifetime + time.Second, http.StatusBadRequest, protocol.CodeBadKey},
	} {
		r := e.raw()
		r.prekey(1, now.Add(c.ends), nil)
		rep := e.do("PUT", r.path(""), r.registration(1), r.pass(1))
		e.want(rep, c.status, c.code)
		if c.code != "" && !strings.Contains(string(rep.body), "the server's clock reads "+now.UTC().Format(protocol.TimeLayout)) {
			t.Errorf("a prekey ending %v from now: the refusal does not state the server's clock: %s", c.ends, rep.body)
		}
		if got, want := rep.header.Get("Date"), now.UTC().Format(http.TimeFormat); got != want {
			t.Errorf("a prekey ending %v from now: the answer is dated %q, and the server's clock reads %q", c.ends, got, want)
		}
	}
	// The clock the answers are dated by is the one the checks read, wherever it is set.
	e.clock.Add(100 * 24 * time.Hour)
	if got, want := e.do("GET", e.raw().path("/identity"), nil, "").header.Get("Date"), e.clock.Now().UTC().Format(http.TimeFormat); got != want {
		t.Errorf("an answer is dated %q, and the server's clock reads %q", got, want)
	}
}

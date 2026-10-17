package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"github.com/IronGall-dev/irongall-client/api/apitest"
	"github.com/IronGall-dev/irongall-client/protocol"
)

// The operator clears what the limits keyed by an address hold of one
// caller (AdminHandler): an address that spent its calls with no pass makes
// them again at once, the answer names the limits that held anything, and
// nothing else is touched. The interface is never on the API's routes.
func TestTheOperatorClearsAnAddress(t *testing.T) {
	l := relaxed()
	e := newEnv(t, l)
	b := e.box(protocol.Classic)
	l.PublicBurst, l.PublicRefill = 2, time.Hour
	s := New(Config{Store: e.store, Keys: e.keys, Limits: l, Now: e.clock.Now})
	srv := httptest.NewServer(apitest.Handler(t, s.Handler()))
	t.Cleanup(srv.Close)
	api := &env{t: t, clock: e.clock, srv: srv}
	read := "/v1/" + b.Address().String()
	clear := func(ip string) (int, string, []string) {
		t.Helper()
		w := httptest.NewRecorder()
		s.AdminHandler().ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/limits/clear?ip="+ip, nil))
		var got struct {
			Address string   `json:"address"`
			Cleared []string `json:"cleared"`
		}
		if w.Code == http.StatusOK {
			if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil || got.Cleared == nil {
				t.Fatalf("the answer: %v: %s", err, w.Body)
			}
		}
		return w.Code, got.Address, got.Cleared
	}

	for range l.PublicBurst {
		api.want(api.do(http.MethodGet, read, nil, ""), http.StatusOK, "")
	}
	api.want(api.do(http.MethodGet, read, nil, ""), http.StatusTooManyRequests, protocol.CodeRateLimited)
	if code, key, cleared := clear("127.0.0.1"); code != http.StatusOK || key != "127.0.0.1" || !slices.Equal(cleared, []string{"public"}) {
		t.Fatalf("clear: %d %q %v, want the address's calls with no pass", code, key, cleared)
	}
	for range l.PublicBurst {
		api.want(api.do(http.MethodGet, read, nil, ""), http.StatusOK, "")
	}
	api.want(api.do(http.MethodGet, read, nil, ""), http.StatusTooManyRequests, protocol.CodeRateLimited)

	// Another address's counts are its own: clearing it clears nothing here.
	if code, _, cleared := clear("192.0.2.1"); code != http.StatusOK || len(cleared) != 0 {
		t.Fatalf("clear of an address that holds nothing: %d %v", code, cleared)
	}
	api.want(api.do(http.MethodGet, read, nil, ""), http.StatusTooManyRequests, protocol.CodeRateLimited)
	// An IPv6 address is cleared as the limits count it, by its /64.
	if code, key, _ := clear("2001:db8:1:2:3:4:5:6"); code != http.StatusOK || key != "2001:db8:1:2::/64" {
		t.Fatalf("an IPv6 address: %d %q", code, key)
	}
	for _, bad := range []string{"", "nonsense", "127.0.0.1/8", "irongall.dev"} {
		if code, _, _ := clear(bad); code != http.StatusBadRequest {
			t.Errorf("clear %q: %d, want 400", bad, code)
		}
	}
	for _, r := range s.routes() {
		if r.pattern == "POST /limits/clear" {
			t.Fatal("the operator's interface is on the API's routes")
		}
	}
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/limits/clear?ip=127.0.0.1", nil))
	if w.Code != http.StatusNotFound {
		t.Fatalf("the API's handler answers the operator's command: %d", w.Code)
	}
}

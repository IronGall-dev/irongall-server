package server

import (
	"net/http"
	"slices"
	"testing"

	"github.com/IronGall-dev/irongall-client/api/apitest"
	"github.com/IronGall-dev/irongall-client/protocol"
)

// The server's routes are the API description's, no more and no fewer: a
// route added on one side and not the other fails here, and every answer
// on a route is held to the description by apitest in every other test.
func TestTheRoutesAreTheDescriptions(t *testing.T) {
	want, err := apitest.Routes()
	if err != nil {
		t.Fatal(err)
	}
	got := []string{linkRoute}
	for _, r := range (&Server{}).routes() {
		got = append(got, r.pattern)
	}
	slices.Sort(got)
	if !slices.Equal(got, want) {
		t.Errorf("the server's routes are\n  %v\nthe description's\n  %v", got, want)
	}
}

// The read of a box is GET /v1/<address>, and the two reads it replaced are
// no routes of this server: GET …/identity gets the router's plain 404, and
// GET …/revocations, whose PUT stays, its plain 405. A revocation server
// keeps that GET; a mailbox server is not one.
func TestTheReadsTheBoxReplacedAreGone(t *testing.T) {
	e := newEnv(t, relaxed())
	b := e.box(protocol.Classic)
	for path, want := range map[string]int{
		"/identity":    http.StatusNotFound,
		"/revocations": http.StatusMethodNotAllowed,
	} {
		resp, err := http.Get(e.srv.URL + "/v1/" + b.Address().String() + path)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != want || resp.Header.Get("Content-Type") == protocol.ProblemContentType {
			t.Errorf("GET …%s: %d %s, want the router's plain %d", path, resp.StatusCode, resp.Header.Get("Content-Type"), want)
		}
		if want == http.StatusMethodNotAllowed && resp.Header.Get("Allow") != http.MethodPut {
			t.Errorf("GET …%s: Allow %q, want the PUT that stays", path, resp.Header.Get("Allow"))
		}
	}
	e.want(e.do(http.MethodGet, "/v1/"+b.Address().String(), nil, ""), http.StatusOK, "")
}

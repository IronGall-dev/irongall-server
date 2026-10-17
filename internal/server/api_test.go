package server

import (
	"slices"
	"testing"

	"github.com/IronGall-dev/irongall-client/api/apitest"
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

package server

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/IronGall-dev/irongall-client/api/apitest"
	"github.com/IronGall-dev/irongall-client/client"
)

// Outside /v1/ the server has the link page and nothing else: a site's own
// pages (a front page, llms.txt, docs) are served by whatever stands in
// front of it.
func TestNoPagesButTheLinkPage(t *testing.T) {
	keys, _ := NewDevKeys()
	srv := httptest.NewServer(apitest.Handler(t, New(Config{Store: NewMemStore(time.Now), Keys: keys, Limits: relaxed(), Ready: func() bool { return false }}).Handler()))
	defer srv.Close()
	for _, p := range []string{"/", "/llms.txt", "/docs/", "/docs", "/index.html", "/to.html", "/nope"} {
		resp, err := http.Get(srv.URL + p)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("GET %s: %d", p, resp.StatusCode)
		}
	}
	resp, err := http.Get(srv.URL + "/v1/" + strings.Repeat("0", 64) + "/identity")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("the API while not ready: %d", resp.StatusCode)
	}
}

// A box's link opens a page for any 64 lowercase hex characters, the form
// clients take, while the API is still 503: fixed text and the address, kept
// out of Referer headers and search engines. Anything else is 404.
func TestLinkPage(t *testing.T) {
	keys, _ := NewDevKeys()
	srv := httptest.NewServer(apitest.Handler(t, New(Config{Store: NewMemStore(time.Now), Keys: keys, Limits: relaxed(), Ready: func() bool { return false }}).Handler()))
	defer srv.Close()
	get := func(method, path string) (*http.Response, string) {
		t.Helper()
		req, _ := http.NewRequest(method, srv.URL+path, nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp, string(b)
	}
	a := strings.Repeat("0a", 32)
	resp, body := get(http.MethodGet, "/to/"+a)
	h := resp.Header
	if resp.StatusCode != http.StatusOK || h.Get("Content-Type") != "text/html; charset=utf-8" || h.Get("Cache-Control") != pageMaxAge ||
		h.Get("X-Content-Type-Options") != "nosniff" ||
		h.Get("Referrer-Policy") != "no-referrer" || h.Get("X-Robots-Tag") != "noindex" || !strings.HasPrefix(h.Get("Content-Security-Policy"), "default-src 'none';") {
		t.Fatalf("GET /to/<address>: %d %v", resp.StatusCode, h)
	}
	for _, want := range []string{"<code>" + a + "</code>", "echo hello | irongall send https://irongall.dev/to/" + a + "</code>", `<meta name="robots" content="noindex">`} {
		if !strings.Contains(body, want) {
			t.Errorf("the page lacks %q", want)
		}
	}
	if strings.Contains(body, "{{") {
		t.Error("the page has template text left in it")
	}
	if resp, body := get(http.MethodHead, "/to/"+a); resp.StatusCode != http.StatusOK || body != "" {
		t.Errorf("HEAD: %d %q", resp.StatusCode, body)
	}
	if resp, _ := get(http.MethodPost, "/to/"+a); resp.StatusCode == http.StatusOK {
		t.Error("POST: 200")
	}
	for _, p := range []string{"/to/" + strings.ToUpper(a), "/to/" + a[:63], "/to/" + a + "0", "/to/" + a + "/", "/to/", "/to/%3Cscript%3E" + a[13:]} {
		if resp, body := get(http.MethodGet, p); resp.StatusCode != http.StatusNotFound || strings.Contains(body, "irongall send") {
			t.Errorf("GET %s: %d", p, resp.StatusCode)
		}
	}
}

// The page's command is the client README's: the echo box's link renders to
// a line of the README, at the address the client code carries.
func TestLinkPageCommandIsInTheClientREADME(t *testing.T) {
	keys, _ := NewDevKeys()
	srv := httptest.NewServer(apitest.Handler(t, New(Config{Store: NewMemStore(time.Now), Keys: keys, Limits: relaxed()}).Handler()))
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/to/" + client.EchoAddress)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	readme, err := os.ReadFile("../../../irongall-client/README.md")
	if err != nil {
		t.Fatal(err)
	}
	line := "echo hello | irongall send https://irongall.dev/to/" + client.EchoAddress
	if !strings.Contains(string(b), "<code>"+line+"</code>") || !strings.Contains(string(readme), "\n"+line+"\n") {
		t.Errorf("the page and the README do not both give %q", line)
	}
}

package server

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/IronGall-dev/irongall-client/protocol"
)

// siteFiles is a site as a renderer writes one: the front page, a page at a
// path of its own, an index of another type in a directory, and three icons.
var siteFiles = map[string]string{
	"index.html":           "<!doctype html><title>front</title>",
	"llms.txt":             "what an agent reads first\n",
	"docs/index.md":        "# docs\n",
	"favicon.ico":          "\x00\x00\x01\x00ico",
	"favicon.svg":          "<svg xmlns=\"http://www.w3.org/2000/svg\"/>",
	"apple-touch-icon.png": "\x89PNG\r\n\x1a\npng",
}

func writeSite(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// siteServer is a server with the site above, and ready as given: the API
// answers 503 until it is.
func siteServer(t *testing.T, l Limits, ready bool) *httptest.Server {
	t.Helper()
	site, err := LoadSite(writeSite(t, siteFiles))
	if err != nil {
		t.Fatal(err)
	}
	s := New(Config{Store: NewMemStore(time.Now), Limits: l, Site: site, Ready: func() bool { return ready }})
	srv := httptest.NewServer(s.Handler())
	t.Cleanup(srv.Close)
	return srv
}

func get(t *testing.T, srv *httptest.Server, method, path string, hdr ...string) (*http.Response, string) {
	t.Helper()
	req, _ := http.NewRequest(method, srv.URL+path, nil)
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	resp, err := (&http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, string(b)
}

// Each page answers at its own path and nowhere else, with the type of its
// extension, a cache of five minutes, nosniff, its hash as a strong ETag and
// a Last-Modified; an index answers at its directory's path, which the path
// without the slash redirects to. The API and the link page are never the
// site's.
func TestTheSiteServesEachPageAtItsPath(t *testing.T) {
	srv := siteServer(t, relaxed(), true)
	for path, want := range map[string]struct{ file, ctype string }{
		"/":                     {"index.html", "text/html; charset=utf-8"},
		"/llms.txt":             {"llms.txt", "text/plain; charset=utf-8"},
		"/docs/":                {"docs/index.md", "text/plain; charset=utf-8"},
		"/favicon.ico":          {"favicon.ico", "image/x-icon"},
		"/favicon.svg":          {"favicon.svg", "image/svg+xml"},
		"/apple-touch-icon.png": {"apple-touch-icon.png", "image/png"},
	} {
		resp, body := get(t, srv, http.MethodGet, path)
		sum := sha256.Sum256([]byte(siteFiles[want.file]))
		h := resp.Header
		if resp.StatusCode != http.StatusOK || body != siteFiles[want.file] || h.Get("Content-Type") != want.ctype ||
			h.Get("Cache-Control") != pageMaxAge || h.Get("X-Content-Type-Options") != "nosniff" ||
			h.Get("ETag") != `"`+hex.EncodeToString(sum[:16])+`"` || h.Get("Last-Modified") == "" {
			t.Errorf("%s: %d %q, headers %v", path, resp.StatusCode, body, h)
		}
	}
	if resp, _ := get(t, srv, http.MethodGet, "/docs"); resp.StatusCode != http.StatusMovedPermanently || resp.Header.Get("Location") != "/docs/" {
		t.Errorf("/docs: %d to %q, want 301 to /docs/", resp.StatusCode, resp.Header.Get("Location"))
	}
	for _, path := range []string{"/index.html", "/docs/index.md", "/nope", "/docs/nope", "/llms.txt/", "/to/"} {
		if resp, _ := get(t, srv, http.MethodGet, path); resp.StatusCode != http.StatusNotFound {
			t.Errorf("%s: %d, want 404", path, resp.StatusCode)
		}
	}
	if resp, body := get(t, srv, http.MethodGet, "/v1/"+strings.Repeat("0", 64)); resp.StatusCode != http.StatusNotFound || !strings.Contains(body, string(protocol.CodeNoSuchMailbox)) {
		t.Errorf("the API's read of a box: %d %s, want its own 404", resp.StatusCode, body)
	}
	if resp, body := get(t, srv, http.MethodGet, protocol.LinkPath+strings.Repeat("a", 64)); resp.StatusCode != http.StatusOK || !strings.Contains(body, strings.Repeat("a", 64)) {
		t.Errorf("the link page: %d", resp.StatusCode)
	}
}

// A page is answered as a static file is: 304 to its ETag or a date not
// before its own, a HEAD with no body, and a range.
func TestASitePageAnswersConditionally(t *testing.T) {
	srv := siteServer(t, relaxed(), true)
	first, _ := get(t, srv, http.MethodGet, "/llms.txt")
	if resp, body := get(t, srv, http.MethodGet, "/llms.txt", "If-None-Match", first.Header.Get("ETag")); resp.StatusCode != http.StatusNotModified || body != "" {
		t.Errorf("If-None-Match its ETag: %d %q, want 304", resp.StatusCode, body)
	}
	if resp, _ := get(t, srv, http.MethodGet, "/llms.txt", "If-Modified-Since", first.Header.Get("Last-Modified")); resp.StatusCode != http.StatusNotModified {
		t.Errorf("If-Modified-Since its date: %d, want 304", resp.StatusCode)
	}
	if resp, body := get(t, srv, http.MethodHead, "/llms.txt"); resp.StatusCode != http.StatusOK || body != "" || resp.Header.Get("Content-Length") != "26" {
		t.Errorf("HEAD: %d %q, length %q", resp.StatusCode, body, resp.Header.Get("Content-Length"))
	}
	if resp, body := get(t, srv, http.MethodGet, "/llms.txt", "Range", "bytes=0-3"); resp.StatusCode != http.StatusPartialContent || body != "what" {
		t.Errorf("a range: %d %q", resp.StatusCode, body)
	}
	if resp, _ := get(t, srv, http.MethodPost, "/llms.txt"); resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("POST: %d, want 405", resp.StatusCode)
	}
}

// A page of the site is a call with no pass: it spends the caller's address's
// allowance, a 404 among them, as the link page does. And it is answered
// while the API is not ready.
func TestASitePageIsACallWithNoPass(t *testing.T) {
	l := relaxed()
	l.PublicBurst, l.PublicRefill = 2, time.Hour
	srv := siteServer(t, l, false)
	if resp, _ := get(t, srv, http.MethodGet, "/v1/"+strings.Repeat("0", 64)); resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("the API before it is ready: %d, want 503", resp.StatusCode)
	}
	for i, path := range []string{"/", "/nope"} {
		if resp, _ := get(t, srv, http.MethodGet, path); resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusServiceUnavailable {
			t.Fatalf("page %d, before the API is ready: %d", i+1, resp.StatusCode)
		}
	}
	if resp, _ := get(t, srv, http.MethodGet, "/llms.txt"); resp.StatusCode != http.StatusTooManyRequests || resp.Header.Get("Retry-After") == "" {
		t.Errorf("a third page past an allowance of two: %d, want 429 with Retry-After", resp.StatusCode)
	}
}

// With no site, every path outside /v1/ and the link page is 404.
func TestNoSiteIsNotFound(t *testing.T) {
	srv := httptest.NewServer(New(Config{Store: NewMemStore(time.Now), Limits: relaxed()}).Handler())
	t.Cleanup(srv.Close)
	for _, path := range []string{"/", "/llms.txt"} {
		if resp, _ := get(t, srv, http.MethodGet, path); resp.StatusCode != http.StatusNotFound {
			t.Errorf("%s with no site: %d, want 404", path, resp.StatusCode)
		}
	}
}

// A site is what its renderer wrote: a file of a type it holds none of, a
// second index in one directory, or a link is refused at start.
func TestASiteOfAnythingElseIsRefused(t *testing.T) {
	for name, files := range map[string]map[string]string{
		"a type it holds none of": {"index.html": "x", "notes.pdf": "x"},
		"a file with no type":     {"index.html": "x", "README": "x"},
		"two indexes":             {"docs/index.md": "x", "docs/index.html": "x"},
	} {
		if _, err := LoadSite(writeSite(t, files)); err == nil {
			t.Errorf("%s: loaded", name)
		}
	}
	dir := writeSite(t, map[string]string{"index.html": "x"})
	if err := os.Symlink("/etc/hostname", filepath.Join(dir, "llms.txt")); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadSite(dir); err == nil {
		t.Error("a link: loaded")
	}
}

package server

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/IronGall-dev/irongall-client/api/apitest"
	"github.com/IronGall-dev/irongall-client/protocol"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
)

// errorWithURL is the test store, but a read of box's record fails with the
// text of an S3 transport error: the request's URL, which names the box and
// a message id.
type errorWithURL struct {
	Store
	box protocol.Address
	id  string
}

func (s errorWithURL) Known(a protocol.Address) (*Box, bool) {
	if a == s.box {
		return nil, false
	}
	return s.Store.Known(a)
}

func (s errorWithURL) Box(ctx context.Context, a protocol.Address) (*Box, error) {
	if a == s.box {
		return nil, fmt.Errorf(`operation error S3: PutObject, request send failed, Put "http://127.0.0.1:1/bucket/%s/%s?x-id=PutObject": dial tcp 127.0.0.1:1: connect: connection refused`, a, s.id)
	}
	return s.Store.Box(ctx, a)
}

// deadS3 is the test store, but a send is stored by a DynamoStore whose S3
// is a closed port: its PutMessage fails as a real S3 client does when it
// cannot connect.
type deadS3 struct {
	Store
	d *DynamoStore
}

func (s deadS3) PutMessage(ctx context.Context, box protocol.Address, h *Header, body []byte) (*Header, error) {
	return s.d.PutMessage(ctx, box, h, body)
}

// No line the server logs carries an address or a message id
// (IronGall-dev/irongall-server#9, PROTOCOL-SERVER.md §13): not a store's
// error, whose text holds a request's URL, not a real S3 client's, and not
// a path that holds one inside a longer segment or in capitals. Each line
// names the box by the name redact gives it, so the four lines about one box
// still match.
func TestNoLogLineCarriesAnAddress(t *testing.T) {
	var logged bytes.Buffer
	var a protocol.Address
	a[0], a[31] = 0xab, 0xcd
	id := strings.Repeat("ef", 32)
	s := New(Config{Store: errorWithURL{NewMemStore(time.Now), a, id}, Limits: relaxed(), Now: time.Now, Log: log.New(&logged, "", 0)})
	h := apitest.Handler(t, s.Handler())
	for _, p := range []string{"/v1/" + a.String(), "/v1/" + a.String() + "x", "/v1/x" + strings.ToUpper(a.String())} {
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, p, nil))
	}
	name := string(redact([]byte(a.String())))
	if lines := strings.Count(logged.String(), name); strings.Contains(logged.String(), a.String()) || strings.Contains(strings.ToLower(logged.String()), id) || lines != 4 {
		t.Errorf("the log names the box %d times, and holds it or the id in the clear:\n%s", lines, logged.String())
	}

	// A real S3 client's error, its URL as it writes it.
	var sdk bytes.Buffer
	d := NewDynamoStore(DynamoConfig{AWS: aws.Config{Region: "us-east-1", Credentials: credentials.NewStaticCredentialsProvider("k", "s", ""),
		BaseEndpoint: aws.String("http://127.0.0.1:1"), RetryMaxAttempts: 1}, BoxesTable: "b", MsgsTable: "m", AccountsTable: "a", Bucket: "bucket", Log: log.New(&sdk, "", 0)})
	logged.Reset()
	e := newEnv(t, relaxed(), func(c *Config) { c.Store, c.Log = deadS3{c.Store, d}, log.New(&logged, "", 0) })
	from, to := e.box(protocol.Classic), e.box(protocol.Classic)
	if _, err := from.Send(context.Background(), to.Address(), "never stored"); err == nil {
		t.Fatal("a send stored through a closed port")
	}
	var line string
	for l := range strings.Lines(logged.String()) {
		if strings.HasPrefix(l, "internal error: ") {
			line = l
		}
	}
	if !strings.Contains(line, "PutObject") || strings.Contains(line, to.Address().String()) || !strings.Contains(line, string(redact([]byte(to.Address().String())))) {
		t.Errorf("a real S3 client's error, logged: %q, in:\n%s", line, logged.String())
	}
}

// The access log writes one line a request, and nothing a caller sent can
// end it, pass for the server's own words or make it longer than what the
// server serves (IronGall-dev/irongall-server#11): a path is quoted, and a
// method or a path longer than the longest path this server serves is
// written as its length alone. The longest the routes and the site serve is
// written whole, and so is a method no route names.
// The server is not wrapped in apitest: a site's pages are a deployment's,
// which api/openapi.yaml does not describe (site_test.go's are not either).
func TestTheAccessLogWritesWhatACallerSentAsOneLine(t *testing.T) {
	site := t.TempDir()
	page := strings.Repeat("p", 200) + ".html"
	if err := os.WriteFile(filepath.Join(site, page), []byte("<p>a page</p>"), 0o600); err != nil {
		t.Fatal(err)
	}
	st, err := LoadSite(site)
	if err != nil {
		t.Fatal(err)
	}
	var logged bytes.Buffer
	s := New(Config{Store: NewMemStore(time.Now), Limits: relaxed(), Now: time.Now, Log: log.New(&logged, "", log.LstdFlags), Site: st})
	srv := httptest.NewServer(s.Handler())
	t.Cleanup(srv.Close)
	request := func(method, path string) string {
		t.Helper()
		c, err := net.Dial("tcp", strings.TrimPrefix(srv.URL, "http://"))
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = c.Close() }()
		logged.Reset()
		if _, err := fmt.Fprintf(c, "%s %s HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n", method, path); err != nil {
			t.Fatal(err)
		}
		if _, err := http.ReadResponse(bufio.NewReader(c), nil); err != nil {
			t.Fatal(err)
		}
		_ = c.SetReadDeadline(time.Now().Add(time.Second))
		_, _ = bufio.NewReader(c).ReadString(0) // until the server has closed: the line is written
		if n := strings.Count(logged.String(), "\n"); n != 1 {
			t.Fatalf("%s %.80s: %d lines logged:\n%s", method, path, n, logged.String())
		}
		return strings.SplitN(logged.String(), " ", 3)[2] // past the time
	}

	forged := "/v1/x%0A2026/10/13%2012:00:00%20store%20throttled:%20boom%0D%00%1B[2J%E2%80%AE"
	if got, want := request("GET", forged), "GET "+strconv.Quote("/v1/x\n2026/10/13 12:00:00 store throttled: boom\r\x00\x1b[2J‮")+" 404 "; !strings.HasPrefix(got, want) {
		t.Errorf("a path that would forge a line: %q, want it from %q", got, want)
	}
	var a protocol.Address
	a[0] = 1
	box := string(redact([]byte(a.String())))
	longest := "/v1/" + a.String() + "/messages/" + strings.Repeat("ab", 32)
	if got, want := request("GET", longest), "GET "+strconv.Quote("/v1/"+box+"/messages/"+string(redact([]byte(strings.Repeat("ab", 32)))))+" "; !strings.HasPrefix(got, want) {
		t.Errorf("the longest route's path: %q, want it from %q", got, want)
	}
	if got, want := request("GET", "/"+page), "GET "+strconv.Quote("/"+page)+" 200 "; !strings.HasPrefix(got, want) {
		t.Errorf("the site's longest page: %q, want it from %q", got, want)
	}
	over := "/" + strings.Repeat("q", len(page)+1)
	if got, want := request("GET", over), fmt.Sprintf("GET (a path of %d bytes) ", len(over)); !strings.HasPrefix(got, want) {
		t.Errorf("a path longer than any served: %q, want it from %q", got, want)
	}
	if got, want := request("GET", "/v1/"+strings.Repeat(a.String(), 1<<12)), fmt.Sprintf("GET (a path of %d bytes) ", 4+64<<12); !strings.HasPrefix(got, want) {
		t.Errorf("a long path of addresses: %q, want it from %q", got, want)
	}
	method := strings.Repeat("A", 1<<16)
	if got, want := request(method, "/v1/x"), fmt.Sprintf("(a method of %d bytes) %q ", len(method), "/v1/x"); !strings.HasPrefix(got, want) {
		t.Errorf("a method longer than any path served: %.100q, want it from %q", got, want)
	}
	if got, want := request("PROPFIND", "/v1/x"), `PROPFIND "/v1/x" 405 `; !strings.HasPrefix(got, want) {
		t.Errorf("a method no route names: %q, want it from %q", got, want)
	}
}

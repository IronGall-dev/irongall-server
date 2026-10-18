package main

import (
	"bytes"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/IronGall-dev/irongall-server/internal/server"
)

// The operator's socket: made 0600, a stale one replaced, anything else at
// its path refused, and limits clear answered through it.
func TestTheAdminSocket(t *testing.T) {
	dir, err := os.MkdirTemp("", "ig") // a short path: a Unix socket's is at most 108 bytes
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	path := filepath.Join(dir, "admin.sock")
	s := server.New(server.Config{Store: server.NewMemStore(time.Now), Limits: server.DefaultLimits(), Now: time.Now})

	first, err := listenAdmin(path)
	if err != nil {
		t.Fatal(err)
	}
	_ = first.Close() // a socket file left by a process that is gone
	if err := os.WriteFile(path+".x", nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := listenAdmin(path + ".x"); err == nil {
		t.Fatal("listened over a file that is not a socket")
	}
	l, err := listenAdmin(path)
	if err != nil {
		t.Fatalf("a stale socket was not replaced: %v", err)
	}
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("the socket's mode: %v %v", fi.Mode(), err)
	}
	go func() { _ = http.Serve(l, s.AdminHandler()) }()
	t.Cleanup(func() { _ = l.Close() })

	var out bytes.Buffer
	if err := adminCall(path, "/limits/clear?ip=192.0.2.7", &out); err != nil || strings.TrimSpace(out.String()) != `{"address":"192.0.2.7","cleared":[]}` {
		t.Fatalf("limits clear: %v %q", err, out.String())
	}
	if err := adminCall(path, "/limits/clear?ip=nonsense", &out); err == nil || !strings.Contains(err.Error(), "400") {
		t.Fatalf("limits clear of no address: %v", err)
	}
	if err := limits("clear", []string{"-socket", path}); err == nil {
		t.Fatal("limits clear with no -ip")
	}
	if err := limits("raise", []string{"-socket", path}); err == nil {
		t.Fatal("a limits command that is not one")
	}
}

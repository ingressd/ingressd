// SPDX-License-Identifier: Apache-2.0

package storagerelay

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/ingressd/ingressd/pkg/nodeproto"
)

// client is a minimal stand-in for the edge module's transport.
type client struct {
	t    *testing.T
	http *http.Client
}

func serveUnix(t *testing.T, s *Server) *client {
	t.Helper()
	dir, err := os.MkdirTemp("", "hsr")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "storage.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: s, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return &client{t: t, http: &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", sock)
		}}}}
}

func (c *client) do(req nodeproto.StorageRequest) (int, nodeproto.StorageResponse) {
	c.t.Helper()
	b, _ := json.Marshal(req)
	resp, err := c.http.Post("http://ingressd"+Path, "application/json", bytes.NewReader(b))
	if err != nil {
		c.t.Fatal(err)
	}
	defer resp.Body.Close()
	var res nodeproto.StorageResponse
	if resp.StatusCode == http.StatusOK {
		if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
			c.t.Fatal(err)
		}
	}
	return resp.StatusCode, res
}

func waitReady(t *testing.T, s *Server) {
	t.Helper()
	for i := 0; i < 200; i++ {
		if s.Ready() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("relay never became ready")
}

func TestRelayUnavailableWithoutBackend(t *testing.T) {
	s := &Server{}
	c := serveUnix(t, s)
	if code, _ := c.do(nodeproto.StorageRequest{Op: nodeproto.StorageLoad, Key: "a"}); code != http.StatusServiceUnavailable {
		t.Fatalf("status %d, want 503", code)
	}
	// A backend that cannot reach the panel → 503 too.
	s.SetBackend(context.Background(), BackendFunc(func(context.Context, nodeproto.StorageRequest) (nodeproto.StorageResponse, error) {
		return nodeproto.StorageResponse{}, errors.New("not connected to the panel")
	}), "nod_1")
	waitReady(t, s)
	if code, _ := c.do(nodeproto.StorageRequest{Op: nodeproto.StorageLoad, Key: "a"}); code != http.StatusServiceUnavailable {
		t.Fatalf("status %d, want 503", code)
	}
	s.SetBackend(context.Background(), nil, "")
	if code, _ := c.do(nodeproto.StorageRequest{Op: nodeproto.StorageLoad, Key: "a"}); code != http.StatusServiceUnavailable {
		t.Fatalf("status %d after detach, want 503", code)
	}
}

func TestRelayForwards(t *testing.T) {
	mem := NewMemory()
	s := &Server{}
	s.SetBackend(context.Background(), mem.Backend("nod_1"), "nod_1")
	waitReady(t, s)
	c := serveUnix(t, s)
	if code, res := c.do(nodeproto.StorageRequest{Op: nodeproto.StorageStore, Key: "certificates/x/y.crt", Value: []byte("v")}); code != 200 || res.Error != "" {
		t.Fatalf("store: %d %+v", code, res)
	}
	if _, res := c.do(nodeproto.StorageRequest{Op: nodeproto.StorageLoad, Key: "certificates/x/y.crt"}); string(res.Value) != "v" {
		t.Fatalf("load: %+v", res)
	}
	if _, res := c.do(nodeproto.StorageRequest{Op: nodeproto.StorageLoad, Key: "certificates/x/z.crt"}); !res.NotExist {
		t.Fatalf("missing: %+v", res)
	}
	if _, res := c.do(nodeproto.StorageRequest{Op: nodeproto.StorageStore, Key: "../escape", Value: []byte("v")}); res.Error == "" {
		t.Fatal("unclean key accepted")
	}
}

// Two nodes' relays sharing one panel: one stores a certificate and holds
// the issuance lock, the other sees both.
func TestTwoNodesShareLockAndCert(t *testing.T) {
	mem := NewMemory()
	a, b := &Server{}, &Server{}
	a.SetBackend(context.Background(), mem.Backend("nod_a"), "nod_a")
	b.SetBackend(context.Background(), mem.Backend("nod_b"), "nod_b")
	waitReady(t, a)
	waitReady(t, b)
	ca, cb := serveUnix(t, a), serveUnix(t, b)

	lock := nodeproto.StorageRequest{Op: nodeproto.StorageLock, Name: "issue_cert_shared.example", Owner: "tok"}
	if _, res := ca.do(lock); !res.Acquired {
		t.Fatal("a could not lock")
	}
	// Same owner token from another node is a different owner.
	if _, res := cb.do(lock); res.Acquired {
		t.Fatal("b took a's lock")
	}
	// b cannot release a's lock either.
	cb.do(nodeproto.StorageRequest{Op: nodeproto.StorageUnlock, Name: lock.Name, Owner: "tok"})
	if _, res := cb.do(nodeproto.StorageRequest{Op: nodeproto.StorageLock, Name: lock.Name, Owner: "tok2"}); res.Acquired {
		t.Fatal("b's unlock released a's lock")
	}
	ca.do(nodeproto.StorageRequest{Op: nodeproto.StorageStore, Key: "certificates/acme/shared.example/shared.example.crt", Value: []byte("CERT")})
	ca.do(nodeproto.StorageRequest{Op: nodeproto.StorageUnlock, Name: lock.Name, Owner: "tok"})
	if _, res := cb.do(nodeproto.StorageRequest{Op: nodeproto.StorageLock, Name: lock.Name, Owner: "tok2"}); !res.Acquired {
		t.Fatal("b could not lock after a unlocked")
	}
	if _, res := cb.do(nodeproto.StorageRequest{Op: nodeproto.StorageLoad, Key: "certificates/acme/shared.example/shared.example.crt"}); string(res.Value) != "CERT" {
		t.Fatalf("b load: %+v", res)
	}
}

func TestLockExpiry(t *testing.T) {
	now := time.Now()
	mem := NewMemory()
	mem.Now = func() time.Time { return now }
	if !mem.Handle("a", nodeproto.StorageRequest{Op: nodeproto.StorageLock, Name: "l", Owner: "1"}).Acquired {
		t.Fatal("lock")
	}
	now = now.Add(nodeproto.StorageLockTTL - time.Second)
	if mem.Handle("b", nodeproto.StorageRequest{Op: nodeproto.StorageLock, Name: "l", Owner: "2"}).Acquired {
		t.Fatal("lock taken before expiry")
	}
	// Renewal by the holder extends the lease.
	if !mem.Handle("a", nodeproto.StorageRequest{Op: nodeproto.StorageLock, Name: "l", Owner: "1"}).Acquired {
		t.Fatal("renew")
	}
	now = now.Add(nodeproto.StorageLockTTL - time.Second)
	if mem.Handle("b", nodeproto.StorageRequest{Op: nodeproto.StorageLock, Name: "l", Owner: "2"}).Acquired {
		t.Fatal("renewed lock taken")
	}
	now = now.Add(2 * time.Second)
	if !mem.Handle("b", nodeproto.StorageRequest{Op: nodeproto.StorageLock, Name: "l", Owner: "2"}).Acquired {
		t.Fatal("expired lock not taken over")
	}
}

func writeFile(t *testing.T, dir, key, v string) {
	t.Helper()
	p := filepath.Join(dir, filepath.FromSlash(key))
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(v), 0o600); err != nil {
		t.Fatal(err)
	}
}

// The cache dir is writable by the edge: symlinks (to files or directories
// outside it) are never followed by the root-run upload.
func TestUploadIgnoresSymlinks(t *testing.T) {
	dir, outside := t.TempDir(), t.TempDir()
	writeFile(t, dir, "certificates/acme-v02/a.example/a.example.crt", "A-local")
	writeFile(t, outside, "shadow", "root:secret")
	if err := os.Symlink(filepath.Join(outside, "shadow"), filepath.Join(dir, "certificates/acme-v02/a.example/a.example.key")); err != nil {
		t.Skip("symlinks unavailable:", err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "certificates/etc")); err != nil {
		t.Fatal(err)
	}
	mem := NewMemory()
	n, err := (&Server{CacheDir: dir}).Upload(context.Background(), BackendFunc(func(_ context.Context, req nodeproto.StorageRequest) (nodeproto.StorageResponse, error) {
		return mem.Handle("nod_1", req), nil
	}))
	if err != nil || n != 1 {
		t.Fatalf("Upload = %d, %v", n, err)
	}
	if got := mem.Keys(); !slices.Equal(got, []string{"certificates/acme-v02/a.example/a.example.crt"}) {
		t.Fatalf("panel keys = %v", got)
	}
}

func TestFirstUseUpload(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "certificates/acme-v02/a.example/a.example.crt", "A-local")
	writeFile(t, dir, "certificates/acme-v02/b.example/b.example.crt", "B-local")
	writeFile(t, dir, "acme/acme-v02/users/x/x.json", "account")
	writeFile(t, dir, "pki/authorities/local/root.crt", "ROOT")
	writeFile(t, dir, "locks/issue_cert_a.example.lock", "{}")
	writeFile(t, dir, "certificates/.tmp-123", "partial")
	mem := NewMemory()
	// Another node already shared b.example: its copy wins.
	mem.Handle("nod_other", nodeproto.StorageRequest{Op: nodeproto.StorageStore, Key: "certificates/acme-v02/b.example/b.example.crt", Value: []byte("B-shared")})

	marker := filepath.Join(t.TempDir(), "uploaded")
	gate := make(chan struct{})
	backend := BackendFunc(func(ctx context.Context, req nodeproto.StorageRequest) (nodeproto.StorageResponse, error) {
		<-gate
		return mem.Handle("nod_1", req), nil
	})
	s := &Server{CacheDir: dir, LocalPrefixes: []string{"pki"}, MarkerPath: marker}
	c := serveUnix(t, s)
	s.SetBackend(context.Background(), backend, "nod_1")
	// Until the upload is done, requests get 503 (the edge reads its cache).
	if code, _ := c.do(nodeproto.StorageRequest{Op: nodeproto.StorageLoad, Key: "certificates/acme-v02/a.example/a.example.crt"}); code != http.StatusServiceUnavailable {
		t.Fatalf("status %d during upload, want 503", code)
	}
	close(gate)
	waitReady(t, s)
	want := []string{"acme/acme-v02/users/x/x.json", "certificates/acme-v02/a.example/a.example.crt", "certificates/acme-v02/b.example/b.example.crt"}
	if got := mem.Keys(); !slices.Equal(got, want) {
		t.Fatalf("panel keys = %v, want %v", got, want)
	}
	if v := mem.Handle("x", nodeproto.StorageRequest{Op: nodeproto.StorageLoad, Key: "certificates/acme-v02/b.example/b.example.crt"}).Value; string(v) != "B-shared" {
		t.Fatalf("upload overwrote the shared copy: %q", v)
	}
	if b, _ := os.ReadFile(marker); string(b) != "nod_1\n" {
		t.Fatalf("marker = %q", b)
	}

	// Same identity again: no second upload, ready at once.
	calls := 0
	s2 := &Server{CacheDir: dir, MarkerPath: marker}
	s2.SetBackend(context.Background(), BackendFunc(func(context.Context, nodeproto.StorageRequest) (nodeproto.StorageResponse, error) {
		calls++
		return nodeproto.StorageResponse{}, nil
	}), "nod_1")
	if !s2.Ready() || calls != 0 {
		t.Fatalf("ready=%v calls=%d, want immediate readiness without upload", s2.Ready(), calls)
	}
}

func TestUploadRetriesUntilPanelReachable(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "certificates/c/c.crt", "C")
	mem := NewMemory()
	fail := true
	s := &Server{CacheDir: dir, RetryInterval: 10 * time.Millisecond}
	s.SetBackend(context.Background(), BackendFunc(func(ctx context.Context, req nodeproto.StorageRequest) (nodeproto.StorageResponse, error) {
		if fail {
			fail = false
			return nodeproto.StorageResponse{}, errors.New("offline")
		}
		return mem.Handle("n", req), nil
	}), "n")
	waitReady(t, s)
	if got := mem.Keys(); len(got) != 1 {
		t.Fatalf("keys = %v", got)
	}
}

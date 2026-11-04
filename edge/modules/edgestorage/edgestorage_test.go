// SPDX-License-Identifier: Apache-2.0

package edgestorage

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/certmagic"
)

// fakeRelay stands in for `ingressd serve` + panel: certmagic file storage
// semantics (by construction) and panel-style lock leases.
type fakeRelay struct {
	t     *testing.T
	sock  string
	store *certmagic.FileStorage
	down  atomic.Bool
	ttl   time.Duration

	mu       sync.Mutex
	locks    map[string]fakeLock
	ops      []string
	skew     time.Duration // added to the wall clock for lease expiry (advance)
	lockReqs int           // lock requests served (acquire and renew)
}

type fakeLock struct {
	owner   string
	expires time.Time
}

func newFakeRelay(t *testing.T) *fakeRelay {
	t.Helper()
	dir, err := os.MkdirTemp("", "hes")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	r := &fakeRelay{t: t, sock: filepath.Join(dir, "s.sock"), store: &certmagic.FileStorage{Path: filepath.Join(dir, "panel")},
		ttl: 2 * time.Minute, locks: map[string]fakeLock{}}
	ln, err := net.Listen("unix", r.sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: r, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return r
}

func (r *fakeRelay) opsSeen() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.ops)
}

// advance moves the relay's lease clock forward by d and returns the number
// of lock requests served so far: a request counted after that number saw
// the advanced clock.
func (r *fakeRelay) advance(d time.Duration) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.skew += d
	return r.lockReqs
}

func (r *fakeRelay) lockRequests() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.lockReqs
}

func (r *fakeRelay) ServeHTTP(w http.ResponseWriter, hr *http.Request) {
	if r.down.Load() {
		http.Error(w, "shared storage unavailable", http.StatusServiceUnavailable)
		return
	}
	var req request
	if err := json.NewDecoder(hr.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	r.mu.Lock()
	r.ops = append(r.ops, req.Op+" "+req.Key+req.Name)
	r.mu.Unlock()
	ctx := hr.Context()
	var res response
	notExist := func(err error) {
		if errors.Is(err, fs.ErrNotExist) {
			res.NotExist = true
		} else if err != nil {
			res.Error = err.Error()
		}
	}
	switch req.Op {
	case "store":
		notExist(r.store.Store(ctx, req.Key, req.Value))
	case "load":
		v, err := r.store.Load(ctx, req.Key)
		res.Value = v
		notExist(err)
	case "delete":
		notExist(r.store.Delete(ctx, req.Key))
	case "exists":
		res.Exists = r.store.Exists(ctx, req.Key)
	case "list":
		keys, err := r.store.List(ctx, req.Key, req.Recursive)
		res.Keys = keys
		notExist(err)
	case "stat":
		ki, err := r.store.Stat(ctx, req.Key)
		notExist(err)
		if err == nil {
			res.Info = &struct {
				Key        string    `json:"key"`
				Modified   time.Time `json:"modified"`
				Size       int64     `json:"size"`
				IsTerminal bool      `json:"is_terminal"`
			}{ki.Key, ki.Modified, ki.Size, ki.IsTerminal}
		}
	case "lock":
		r.mu.Lock()
		l, ok := r.locks[req.Name]
		now := time.Now().Add(r.skew)
		r.lockReqs++
		if !ok || l.owner == req.Owner || now.After(l.expires) {
			r.locks[req.Name] = fakeLock{owner: req.Owner, expires: now.Add(r.ttl)}
			res.Acquired = true
		}
		r.mu.Unlock()
	case "unlock":
		r.mu.Lock()
		if l, ok := r.locks[req.Name]; ok && l.owner == req.Owner {
			delete(r.locks, req.Name)
		}
		r.mu.Unlock()
	default:
		res.Error = "unknown op"
	}
	_ = json.NewEncoder(w).Encode(res)
}

func newClient(t *testing.T, r *fakeRelay) (*Client, string) {
	t.Helper()
	cache := t.TempDir()
	return New(Storage{Socket: r.sock, CacheDir: cache}, nil), cache
}

func TestStoreLoadListStatDelete(t *testing.T) {
	ctx := context.Background()
	r := newFakeRelay(t)
	c, cache := newClient(t, r)
	for _, k := range []string{"certificates/acme/a.example/a.example.crt", "certificates/acme/a.example/a.example.key", "certificates/acme/b.example/b.example.crt"} {
		if err := c.Store(ctx, k, []byte("v:"+k)); err != nil {
			t.Fatal(err)
		}
	}
	v, err := c.Load(ctx, "certificates/acme/a.example/a.example.crt")
	if err != nil || string(v) != "v:certificates/acme/a.example/a.example.crt" {
		t.Fatalf("Load = %q, %v", v, err)
	}
	if _, err := os.Stat(filepath.Join(cache, "certificates", "acme", "a.example", "a.example.crt")); err != nil {
		t.Fatalf("not written through to the cache: %v", err)
	}
	if _, err := c.Load(ctx, "certificates/none"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("missing key: %v, want fs.ErrNotExist", err)
	}
	keys, err := c.List(ctx, "certificates/acme", false)
	if err != nil || !slices.Equal(keys, []string{"certificates/acme/a.example", "certificates/acme/b.example"}) {
		t.Fatalf("List = %v, %v", keys, err)
	}
	keys, err = c.List(ctx, "certificates", true)
	if err != nil || len(keys) != 6 { // acme, 2 dirs, 3 files
		t.Fatalf("recursive List = %v, %v", keys, err)
	}
	ki, err := c.Stat(ctx, "certificates/acme/b.example/b.example.crt")
	if err != nil || !ki.IsTerminal || ki.Size != int64(len("v:certificates/acme/b.example/b.example.crt")) {
		t.Fatalf("Stat = %+v, %v", ki, err)
	}
	if !c.Exists(ctx, "certificates/acme/b.example") || c.Exists(ctx, "certificates/zzz") {
		t.Fatal("Exists")
	}
	if err := c.Delete(ctx, "certificates/acme/a.example"); err != nil {
		t.Fatal(err)
	}
	if c.Exists(ctx, "certificates/acme/a.example/a.example.key") {
		t.Fatal("Delete did not remove the subtree")
	}
	if _, err := os.Stat(filepath.Join(cache, "certificates", "acme", "a.example")); !os.IsNotExist(err) {
		t.Fatal("Delete did not remove the cached subtree")
	}
}

func TestCacheFallbackWhenPanelDown(t *testing.T) {
	ctx := context.Background()
	r := newFakeRelay(t)
	c, _ := newClient(t, r)
	key := "certificates/acme/x.example/x.example.crt"
	if err := c.Store(ctx, key, []byte("cert")); err != nil {
		t.Fatal(err)
	}
	r.down.Store(true)
	c.writeWait = 0 // writes fail at once (TestWritesWaitForRelay: they wait)
	if v, err := c.Load(ctx, key); err != nil || string(v) != "cert" {
		t.Fatalf("Load from cache = %q, %v", v, err)
	}
	if !c.Exists(ctx, key) {
		t.Fatal("Exists from cache")
	}
	if keys, err := c.List(ctx, "certificates/acme", false); err != nil || len(keys) != 1 {
		t.Fatalf("List from cache = %v, %v", keys, err)
	}
	if _, err := c.Stat(ctx, key); err != nil {
		t.Fatalf("Stat from cache: %v", err)
	}
	if err := c.Store(ctx, key, []byte("new")); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Store while down = %v, want ErrUnavailable", err)
	}
	if err := c.Delete(ctx, key); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Delete while down = %v", err)
	}
	if err := c.Lock(ctx, "issue_cert_x.example"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Lock while down = %v", err)
	}

	// Socket gone entirely (serve stopped): same behaviour.
	c2 := New(Storage{Socket: filepath.Join(t.TempDir(), "nope.sock"), CacheDir: c.cache.Path}, nil)
	if v, err := c2.Load(ctx, key); err != nil || string(v) != "cert" {
		t.Fatalf("Load without socket = %q, %v", v, err)
	}
	// Without a cache, reads fail.
	c3 := New(Storage{Socket: r.sock}, nil)
	if _, err := c3.Load(ctx, key); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Load without cache = %v", err)
	}
}

// The edge starts before serve and serve before its panel connection:
// writes and locks (certmagic's storage check before an issuance) wait for
// the relay instead of failing the issuance for good.
func TestWritesWaitForRelay(t *testing.T) {
	ctx := context.Background()
	r := newFakeRelay(t)
	c, _ := newClient(t, r)
	c.writeWait, c.writeRetry = 5*time.Second, 10*time.Millisecond
	r.down.Store(true)
	time.AfterFunc(150*time.Millisecond, func() { r.down.Store(false) })
	start := time.Now()
	if err := c.Store(ctx, "certificates/acme/w.example/w.example.crt", []byte("cert")); err != nil {
		t.Fatalf("Store across the outage: %v", err)
	}
	if d := time.Since(start); d < 100*time.Millisecond {
		t.Fatalf("Store returned after %v, before the relay came back", d)
	}
	r.down.Store(true)
	time.AfterFunc(100*time.Millisecond, func() { r.down.Store(false) })
	if err := c.Lock(ctx, "issue_cert_w.example"); err != nil {
		t.Fatalf("Lock across the outage: %v", err)
	}

	// The wait is bounded.
	r.down.Store(true)
	c.writeWait = 50 * time.Millisecond
	if err := c.Delete(ctx, "certificates/acme/w.example"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Delete after the wait = %v, want ErrUnavailable", err)
	}
	// And ends with the context.
	c.writeWait = time.Minute
	cctx, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
	defer cancel()
	if err := c.Store(cctx, "certificates/x", nil); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Store with an ended context = %v", err)
	}
}

func TestLoadRefreshesCache(t *testing.T) {
	ctx := context.Background()
	r := newFakeRelay(t)
	a, _ := newClient(t, r)
	b, bcache := newClient(t, r)
	key := "certificates/acme/y.example/y.example.crt"
	if err := a.Store(ctx, key, []byte("from-a")); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Load(ctx, key); err != nil {
		t.Fatal(err)
	}
	if v, _ := os.ReadFile(filepath.Join(bcache, filepath.FromSlash(key))); string(v) != "from-a" {
		t.Fatalf("b's cache = %q", v)
	}
}

func TestLocalPrefixesStayLocal(t *testing.T) {
	ctx := context.Background()
	r := newFakeRelay(t)
	c, cache := newClient(t, r)
	key := "pki/authorities/local/root.crt"
	if err := c.Store(ctx, key, []byte("root")); err != nil {
		t.Fatal(err)
	}
	if v, err := c.Load(ctx, key); err != nil || string(v) != "root" {
		t.Fatalf("Load = %q, %v", v, err)
	}
	if keys, err := c.List(ctx, "pki/authorities", true); err != nil || len(keys) != 2 {
		t.Fatalf("List = %v, %v", keys, err)
	}
	if _, err := os.Stat(filepath.Join(cache, "pki", "authorities", "local", "root.crt")); err != nil {
		t.Fatal(err)
	}
	if ops := r.opsSeen(); len(ops) != 0 {
		t.Fatalf("relay saw %v for a local key", ops)
	}
}

// Two nodes (clients with their own caches) share a stored certificate and
// a lock, as certmagic distributed solving needs.
func TestTwoClientsShareCertAndLock(t *testing.T) {
	ctx := context.Background()
	r := newFakeRelay(t)
	a, _ := newClient(t, r)
	b, _ := newClient(t, r)
	a.lockPoll, b.lockPoll = 20*time.Millisecond, 20*time.Millisecond

	if err := a.Lock(ctx, "issue_cert_shared.example"); err != nil {
		t.Fatal(err)
	}
	if ok, err := b.TryLock(ctx, "issue_cert_shared.example"); err != nil || ok {
		t.Fatalf("b.TryLock while a holds it = %v, %v", ok, err)
	}
	got := make(chan error, 1)
	go func() { got <- b.Lock(ctx, "issue_cert_shared.example") }()
	select {
	case err := <-got:
		t.Fatalf("b.Lock returned while a holds the lock: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	if err := a.Store(ctx, "certificates/acme/shared.example/shared.example.crt", []byte("CERT")); err != nil {
		t.Fatal(err)
	}
	if err := a.Unlock(ctx, "issue_cert_shared.example"); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-got:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("b.Lock did not return after a unlocked")
	}
	if v, err := b.Load(ctx, "certificates/acme/shared.example/shared.example.crt"); err != nil || string(v) != "CERT" {
		t.Fatalf("b.Load = %q, %v", v, err)
	}
	if err := b.Unlock(ctx, "issue_cert_shared.example"); err != nil {
		t.Fatal(err)
	}
	if err := b.Unlock(ctx, "issue_cert_shared.example"); err == nil {
		t.Fatal("double Unlock succeeded")
	}
}

func TestLockLeaseRenewed(t *testing.T) {
	ctx := context.Background()
	r := newFakeRelay(t)
	r.ttl = time.Minute // on the relay's lease clock, which the test advances
	a, _ := newClient(t, r)
	b, _ := newClient(t, r)
	a.lockRenew, b.lockRenew = 30*time.Millisecond, 30*time.Millisecond
	if err := a.Lock(ctx, "storage_clean"); err != nil {
		t.Fatal(err)
	}
	// Move the lease clock 4 x 40 s (well past the TTL) and wait after each
	// step for a renewal that saw the new time: only renewal keeps the lease.
	for range 4 {
		n := r.advance(40 * time.Second)
		deadline := time.Now().Add(10 * time.Second)
		for r.lockRequests() <= n {
			if time.Now().After(deadline) {
				t.Fatal("lease was not renewed")
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
	if ok, _ := b.TryLock(ctx, "storage_clean"); ok {
		t.Fatal("lease was not renewed")
	}
	if err := a.Unlock(ctx, "storage_clean"); err != nil {
		t.Fatal(err)
	}
	if ok, _ := b.TryLock(ctx, "storage_clean"); !ok {
		t.Fatal("b could not lock after unlock")
	}
	_ = b.Unlock(ctx, "storage_clean")
}

func TestCaddyModule(t *testing.T) {
	mi, err := caddy.GetModule("caddy.storage.ingressd")
	if err != nil {
		t.Fatal(err)
	}
	m := mi.New().(*Storage)
	if err := json.Unmarshal([]byte(`{"socket":"/run/ingressd/storage.sock","cache_dir":"/var/lib/ingressd/caddy","local_prefixes":["pki"]}`), m); err != nil {
		t.Fatal(err)
	}
	if err := m.Validate(); err != nil {
		t.Fatal(err)
	}
	st, err := m.CertMagicStorage()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := st.(certmagic.TryLocker); !ok {
		t.Fatal("not a TryLocker")
	}
	if err := (&Storage{}).Validate(); err == nil {
		t.Fatal("empty socket accepted")
	}
}

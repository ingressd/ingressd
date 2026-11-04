// SPDX-License-Identifier: Apache-2.0

// Package edgestorage is the Caddy storage module caddy.storage.ingressd:
// certmagic storage shared by every node of an org, kept in the ingressd
// panel (docs/rev1/CERT-STORAGE.md).
//
// The module talks to `ingressd serve` over a unix socket (Socket); serve
// relays each operation to the panel over the node's WebSocket. One node
// obtains a certificate, every node loads it, and any node can answer the
// ACME HTTP-01/TLS-ALPN challenge (certmagic distributed solving), because
// challenge data and locks live in the same shared storage.
//
// Failure behaviour:
//   - Every successful Store and Load is written through to CacheDir (a
//     certmagic file storage). When serve or the panel is unreachable, reads
//     (Load, Exists, List, Stat) are answered from that cache, so a node
//     keeps serving the certificates it has while the panel is down.
//   - Writes (Store, Delete) and locks fail loudly when the panel is
//     unreachable: certmagic then retries later, and no node issues a
//     certificate the others cannot see.
//   - Keys under LocalPrefixes (default "pki": Caddy's internal CA) never
//     leave the node; they live in CacheDir only.
//
// Locks are leases in the panel (2 minutes); the module renews the locks it
// holds every 30 s and polls once a second while waiting for one.
package edgestorage

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"path"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/certmagic"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(Storage{})
	caddy.RegisterModule(legacyStorage{})
}

// Storage configures the module.
type Storage struct {
	// Socket is serve's storage relay socket, e.g. /run/ingressd/storage.sock.
	Socket string `json:"socket,omitempty"`
	// CacheDir is the local write-through cache (a certmagic file storage
	// root), used for reads when the panel is unreachable. ingressd points
	// it at the former file_system root so existing certificates stay
	// readable. Empty disables the cache.
	CacheDir string `json:"cache_dir,omitempty"`
	// LocalPrefixes are top-level key prefixes kept in CacheDir only.
	// Default ["pki"].
	LocalPrefixes []string `json:"local_prefixes,omitempty"`
}

// CaddyModule returns the Caddy module information.
func (Storage) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "caddy.storage.ingressd",
		New: func() caddy.Module { return new(Storage) },
	}
}

// legacyStorage keeps a config autosaved before the rename loadable with
// --resume until the control plane renders the new module name.
type legacyStorage struct{ Storage }

func (legacyStorage) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "caddy.storage.homeedge", // legacy homeedge name, remove after 2027-01
		New: func() caddy.Module { return new(legacyStorage) },
	}
}

// Validate checks the configuration.
func (s *Storage) Validate() error {
	if s.Socket == "" {
		return errors.New("ingressd storage: socket is required")
	}
	return nil
}

// CertMagicStorage returns the certmagic storage.
func (s Storage) CertMagicStorage() (certmagic.Storage, error) {
	if s.Socket == "" {
		return nil, errors.New("ingressd storage: socket is required")
	}
	return New(s, caddy.Log().Named("storage.ingressd")), nil
}

// Interface guards.
var (
	_ caddy.StorageConverter = (*Storage)(nil)
	_ caddy.Validator        = (*Storage)(nil)
	_ certmagic.Storage      = (*Client)(nil)
	_ certmagic.TryLocker    = (*Client)(nil)
)

// Wire protocol, identical to github.com/ingressd/ingressd/pkg/nodeproto
// StorageRequest/StorageResponse (this module cannot import the control
// plane module).
type request struct {
	Op        string `json:"op"`
	Key       string `json:"key,omitempty"`
	Value     []byte `json:"value,omitempty"`
	Recursive bool   `json:"recursive,omitempty"`
	Name      string `json:"name,omitempty"`
	Owner     string `json:"owner,omitempty"`
}

type response struct {
	NotExist bool     `json:"not_exist,omitempty"`
	Error    string   `json:"error,omitempty"`
	Value    []byte   `json:"value,omitempty"`
	Exists   bool     `json:"exists,omitempty"`
	Keys     []string `json:"keys,omitempty"`
	Info     *struct {
		Key        string    `json:"key"`
		Modified   time.Time `json:"modified"`
		Size       int64     `json:"size"`
		IsTerminal bool      `json:"is_terminal"`
	} `json:"info,omitempty"`
	Acquired bool `json:"acquired,omitempty"`
}

const relayPath = "/v1/storage"

// Timing defaults. Tests shorten the per-Client copies (lockPoll,
// lockRenew fields), never these: renewal goroutines of earlier locks keep
// reading their own client's values.
const (
	defaultLockPoll  = time.Second
	defaultLockRenew = 30 * time.Second // panel lease is 2 minutes
	requestLimit     = 30 * time.Second
	// Writes and locks wait this long for the relay (polling every
	// defaultWriteRetry) before failing: see doWait.
	defaultWriteWait  = 2 * time.Minute
	defaultWriteRetry = 2 * time.Second
)

// ErrUnavailable wraps failures to reach the panel (serve down, panel
// offline, first-use upload still running).
var ErrUnavailable = errors.New("ingressd shared storage unavailable")

// Client implements certmagic.Storage over the relay socket.
type Client struct {
	socket string
	local  []string
	cache  *certmagic.FileStorage
	http   *http.Client
	log    *zap.Logger

	// lockPoll is how often Lock retries a held lock; lockRenew how often a
	// held lock's lease is renewed. Set by New; tests shorten them before
	// the first Lock.
	lockPoll, lockRenew time.Duration
	// writeWait and writeRetry bound doWait (tests shorten them).
	writeWait, writeRetry time.Duration

	warnMu   sync.Mutex
	lastWarn time.Time
}

// New builds a client (exported for tests and tools).
func New(s Storage, log *zap.Logger) *Client {
	if log == nil {
		log = zap.NewNop()
	}
	c := &Client{socket: s.Socket, local: s.LocalPrefixes, log: log, lockPoll: defaultLockPoll, lockRenew: defaultLockRenew,
		writeWait: defaultWriteWait, writeRetry: defaultWriteRetry}
	if c.local == nil {
		c.local = []string{"pki"}
	}
	if s.CacheDir != "" {
		c.cache = &certmagic.FileStorage{Path: s.CacheDir}
	}
	sock := s.Socket
	c.http = &http.Client{
		Timeout: requestLimit,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", sock)
			},
			MaxIdleConns: 8, IdleConnTimeout: 60 * time.Second,
		},
	}
	return c
}

func (c *Client) String() string { return "ingressd:" + c.socket }

// isLocal reports whether key stays on this node.
func (c *Client) isLocal(key string) bool {
	top, _, _ := strings.Cut(strings.Trim(path.Clean("/"+key), "/"), "/")
	return slices.Contains(c.local, top)
}

// do sends one request. Errors wrapping ErrUnavailable mean the panel was
// not reached; a panel answer with NotExist returns fs.ErrNotExist.
func (c *Client) do(ctx context.Context, req request) (response, error) {
	var res response
	body, err := json.Marshal(req)
	if err != nil {
		return res, err
	}
	hreq, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://ingressd"+relayPath, bytes.NewReader(body))
	if err != nil {
		return res, err
	}
	hreq.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(hreq)
	if err != nil {
		return res, fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		err := fmt.Errorf("storage relay: %s: %s", resp.Status, strings.TrimSpace(string(msg)))
		if resp.StatusCode == http.StatusServiceUnavailable || resp.StatusCode >= 500 {
			err = fmt.Errorf("%w: %w", ErrUnavailable, err)
		}
		return res, err
	}
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return res, fmt.Errorf("%w: bad relay response: %w", ErrUnavailable, err)
	}
	if res.NotExist {
		return res, fs.ErrNotExist
	}
	if res.Error != "" {
		return res, fmt.Errorf("ingressd storage (%s %s): %s", req.Op, req.Key+req.Name, res.Error)
	}
	return res, nil
}

// doWait is do for writes and locks, which have no cache fallback: while
// the relay is unavailable it retries until writeWait has passed. At
// start-up the edge comes up before serve, and serve before its panel
// connection; certmagic checks storage with a write before every issuance
// and drops the job (no retry) when that fails, so a certificate due at
// start-up would otherwise never be issued until the next config load.
func (c *Client) doWait(ctx context.Context, req request) (response, error) {
	deadline := time.Now().Add(c.writeWait)
	for {
		res, err := c.do(ctx, req)
		if err == nil || !errors.Is(err, ErrUnavailable) || !time.Now().Before(deadline) {
			return res, err
		}
		c.warn("panel unreachable; waiting to write shared storage", req.Op, req.Key+req.Name, err)
		select {
		case <-ctx.Done():
			return res, err
		case <-time.After(c.writeRetry):
		}
	}
}

// warn logs at most once a minute.
func (c *Client) warn(msg, op, key string, err error) {
	c.warnMu.Lock()
	defer c.warnMu.Unlock()
	if time.Since(c.lastWarn) > time.Minute {
		c.lastWarn = time.Now()
		c.log.Warn(msg, zap.String("op", op), zap.String("key", key), zap.Error(err))
	}
}

// fallback logs (rate-limited) that a read is served from the cache.
func (c *Client) fallback(op, key string, err error) bool {
	if c.cache == nil || !errors.Is(err, ErrUnavailable) {
		return false
	}
	c.warn("panel unreachable; reading certificates from the local cache", op, key, err)
	return true
}

func (c *Client) cacheStore(ctx context.Context, key string, value []byte) {
	if c.cache == nil {
		return
	}
	if old, err := c.cache.Load(ctx, key); err == nil && bytes.Equal(old, value) {
		return
	}
	if err := c.cache.Store(ctx, key, value); err != nil {
		c.log.Warn("updating the local certificate cache", zap.String("key", key), zap.Error(err))
	}
}

func (c *Client) localOnly() error {
	if c.cache == nil {
		return errors.New("ingressd storage: local key needs cache_dir")
	}
	return nil
}

// Store saves value at key in the panel, then in the cache.
func (c *Client) Store(ctx context.Context, key string, value []byte) error {
	if c.isLocal(key) {
		if err := c.localOnly(); err != nil {
			return err
		}
		return c.cache.Store(ctx, key, value)
	}
	if _, err := c.doWait(ctx, request{Op: "store", Key: key, Value: value}); err != nil {
		return err
	}
	c.cacheStore(ctx, key, value)
	return nil
}

// Load returns the value at key, from the panel or, when the panel is
// unreachable, the cache.
func (c *Client) Load(ctx context.Context, key string) ([]byte, error) {
	if c.isLocal(key) {
		if err := c.localOnly(); err != nil {
			return nil, err
		}
		return c.cache.Load(ctx, key)
	}
	res, err := c.do(ctx, request{Op: "load", Key: key})
	if err != nil {
		if c.fallback("load", key, err) {
			return c.cache.Load(ctx, key)
		}
		return nil, err
	}
	c.cacheStore(ctx, key, res.Value)
	return res.Value, nil
}

// Delete removes key (and everything below it) from the panel and the cache.
func (c *Client) Delete(ctx context.Context, key string) error {
	if c.isLocal(key) {
		if err := c.localOnly(); err != nil {
			return err
		}
		return c.cache.Delete(ctx, key)
	}
	if _, err := c.doWait(ctx, request{Op: "delete", Key: key}); err != nil {
		return err
	}
	if c.cache != nil {
		if err := c.cache.Delete(ctx, key); err != nil {
			c.log.Warn("deleting from the local certificate cache", zap.String("key", key), zap.Error(err))
		}
	}
	return nil
}

// Exists reports whether key exists.
func (c *Client) Exists(ctx context.Context, key string) bool {
	if c.isLocal(key) {
		return c.cache != nil && c.cache.Exists(ctx, key)
	}
	res, err := c.do(ctx, request{Op: "exists", Key: key})
	if err != nil {
		if c.fallback("exists", key, err) {
			return c.cache.Exists(ctx, key)
		}
		return false
	}
	return res.Exists
}

// List lists keys below prefix (certmagic file storage semantics).
func (c *Client) List(ctx context.Context, prefix string, recursive bool) ([]string, error) {
	if c.isLocal(prefix) {
		if err := c.localOnly(); err != nil {
			return nil, err
		}
		return c.cache.List(ctx, prefix, recursive)
	}
	res, err := c.do(ctx, request{Op: "list", Key: prefix, Recursive: recursive})
	if err != nil {
		if c.fallback("list", prefix, err) {
			return c.cache.List(ctx, prefix, recursive)
		}
		return nil, err
	}
	return res.Keys, nil
}

// Stat describes key.
func (c *Client) Stat(ctx context.Context, key string) (certmagic.KeyInfo, error) {
	if c.isLocal(key) {
		if err := c.localOnly(); err != nil {
			return certmagic.KeyInfo{}, err
		}
		return c.cache.Stat(ctx, key)
	}
	res, err := c.do(ctx, request{Op: "stat", Key: key})
	if err != nil {
		if c.fallback("stat", key, err) {
			return c.cache.Stat(ctx, key)
		}
		return certmagic.KeyInfo{}, err
	}
	if res.Info == nil {
		return certmagic.KeyInfo{}, errors.New("ingressd storage: stat without info")
	}
	return certmagic.KeyInfo{Key: res.Info.Key, Modified: res.Info.Modified, Size: res.Info.Size, IsTerminal: res.Info.IsTerminal}, nil
}

// --- locks ---

// held tracks the locks this process holds, by socket and name, so Unlock
// finds the owner token even across config reloads (new Client values).
var (
	heldMu sync.Mutex
	held   = map[string]*heldLock{}
)

type heldLock struct {
	owner string
	stop  chan struct{}
}

func newOwner() string {
	var b [12]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// tryOnce asks the panel for the lock once.
func (c *Client) tryOnce(ctx context.Context, name, owner string) (bool, error) {
	res, err := c.doWait(ctx, request{Op: "lock", Name: name, Owner: owner})
	if err != nil {
		return false, err
	}
	if res.Acquired {
		c.hold(name, owner)
	}
	return res.Acquired, nil
}

// Lock blocks until the lock is obtained, ctx ends, or the panel stays
// unreachable for writeWait (locks never fall back to the cache).
func (c *Client) Lock(ctx context.Context, name string) error {
	owner := newOwner()
	for {
		ok, err := c.tryOnce(ctx, name, owner)
		if err != nil {
			return fmt.Errorf("lock %s: %w", name, err)
		}
		if ok {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(c.lockPoll):
		}
	}
}

// TryLock tries once.
func (c *Client) TryLock(ctx context.Context, name string) (bool, error) {
	return c.tryOnce(ctx, name, newOwner())
}

// Unlock releases a lock this process holds.
func (c *Client) Unlock(ctx context.Context, name string) error {
	heldMu.Lock()
	h := held[c.socket+"\x00"+name]
	delete(held, c.socket+"\x00"+name)
	heldMu.Unlock()
	if h == nil {
		return fmt.Errorf("ingressd storage: lock %s is not held", name)
	}
	close(h.stop)
	_, err := c.do(ctx, request{Op: "unlock", Name: name, Owner: h.owner})
	return err
}

// hold records a lock and renews its lease until Unlock.
func (c *Client) hold(name, owner string) {
	h := &heldLock{owner: owner, stop: make(chan struct{})}
	heldMu.Lock()
	if old := held[c.socket+"\x00"+name]; old != nil {
		close(old.stop) // its lease expired and was taken over
	}
	held[c.socket+"\x00"+name] = h
	heldMu.Unlock()
	renew := c.lockRenew
	go func() {
		t := time.NewTicker(renew)
		defer t.Stop()
		for {
			select {
			case <-h.stop:
				return
			case <-t.C:
				ctx, cancel := context.WithTimeout(context.Background(), requestLimit)
				res, err := c.do(ctx, request{Op: "lock", Name: name, Owner: owner})
				cancel()
				if err != nil {
					c.log.Warn("renewing storage lock failed", zap.String("lock", name), zap.Error(err))
				} else if !res.Acquired {
					c.log.Error("storage lock lost to another node", zap.String("lock", name))
					return
				}
			}
		}
	}()
}

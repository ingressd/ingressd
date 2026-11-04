// SPDX-License-Identifier: Apache-2.0

// Package storagerelay is the node side of shared certificate storage
// (docs/rev1/CERT-STORAGE.md). `ingressd serve` runs a Server on a unix
// socket next to the control socket; the edge's caddy.storage.ingressd
// module sends it one JSON request per certmagic storage operation, and the
// Server forwards it to the panel (in managed mode, through the node agent's
// WebSocket).
//
// HTTP API (unix socket, edge → serve):
//
//	POST /v1/storage   body nodeproto.StorageRequest
//	→ 200 nodeproto.StorageResponse       the panel answered (may carry NotExist/Error)
//	→ 503 text                            no panel (offline, standalone, first-use upload running)
//	→ 400 text                            malformed request
//
// The module treats 503 and transport errors as "panel unreachable": reads
// fall back to its local cache, writes and locks fail.
package storagerelay

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/ingressd/ingressd/internal/safefs"
	"github.com/ingressd/ingressd/pkg/nodeproto"
)

// Path is the relay's single endpoint.
const Path = "/v1/storage"

// Backend forwards storage requests to the panel. An error means the panel
// could not be asked (not connected, timeout); a panel-side failure is a
// response with Error set.
type Backend interface {
	Storage(ctx context.Context, req nodeproto.StorageRequest) (nodeproto.StorageResponse, error)
}

// BackendFunc adapts a function to Backend.
type BackendFunc func(ctx context.Context, req nodeproto.StorageRequest) (nodeproto.StorageResponse, error)

func (f BackendFunc) Storage(ctx context.Context, req nodeproto.StorageRequest) (nodeproto.StorageResponse, error) {
	return f(ctx, req)
}

// ErrUnavailable is returned (as 503) while no backend is set or the
// first-use upload has not finished.
var ErrUnavailable = errors.New("shared storage unavailable")

// Server is the relay. The zero value with CacheDir set is usable; it
// answers 503 until SetBackend.
type Server struct {
	// CacheDir is Caddy's storage directory (also the edge module's
	// cache_dir). Its certificates are uploaded once per node identity when
	// a backend is first set, so a node switching from file_system storage
	// keeps its certificates and shares them with the org.
	CacheDir string
	// LocalPrefixes are top-level key prefixes the edge keeps node-local
	// (never uploaded), e.g. "pki" (Caddy's internal CA is per node).
	LocalPrefixes []string
	// MarkerPath records the identity (node id) whose upload finished.
	MarkerPath string
	// Timeout bounds one forwarded request (default 20 s).
	Timeout time.Duration
	// RetryInterval between upload attempts (default 10 s).
	RetryInterval time.Duration
	Log           *slog.Logger

	mu      sync.Mutex
	backend Backend
	ready   bool
	gen     int
	cancel  context.CancelFunc
}

func (s *Server) log() *slog.Logger {
	if s.Log == nil {
		return slog.New(slog.DiscardHandler)
	}
	return s.Log
}

// SetBackend switches the relay to b (nil: standalone, answer 503). scope
// identifies the node (its id): the first-use upload runs again when it
// changes (re-enrolled in another org). Requests are answered with 503
// until the upload finished.
func (s *Server) SetBackend(ctx context.Context, b Backend, scope string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cancel != nil {
		s.cancel()
		s.cancel = nil
	}
	s.gen++
	s.backend, s.ready = b, false
	if b == nil {
		return
	}
	if s.markerDone(scope) {
		s.ready = true
		return
	}
	mctx, cancel := context.WithCancel(ctx)
	s.cancel = cancel
	gen := s.gen
	go s.migrateLoop(mctx, gen, b, scope)
}

// Ready reports whether requests are being forwarded.
func (s *Server) Ready() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ready
}

func (s *Server) current() (Backend, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.backend, s.ready
}

func (s *Server) markerDone(scope string) bool {
	if s.MarkerPath == "" {
		return false
	}
	b, err := os.ReadFile(s.MarkerPath)
	return err == nil && strings.TrimSpace(string(b)) == scope
}

func (s *Server) migrateLoop(ctx context.Context, gen int, b Backend, scope string) {
	retry := s.RetryInterval
	if retry <= 0 {
		retry = 10 * time.Second
	}
	for {
		n, err := s.Upload(ctx, b)
		if err == nil {
			if s.MarkerPath != "" {
				if werr := os.WriteFile(s.MarkerPath, []byte(scope+"\n"), 0o600); werr != nil {
					s.log().Warn("shared storage: could not record the upload", "err", werr)
				}
			}
			s.mu.Lock()
			if s.gen == gen {
				s.ready = true
			}
			s.mu.Unlock()
			if n > 0 {
				s.log().Info("shared storage: uploaded local certificates", "keys", n)
			}
			return
		}
		s.log().Warn("shared storage: uploading local certificates failed; retrying", "err", err)
		select {
		case <-ctx.Done():
			return
		case <-time.After(retry):
		}
	}
}

// Upload copies every key under CacheDir that the backend does not have yet
// (except LocalPrefixes and lock files) and returns how many it stored.
// Existing panel values win: another node may already have shared a newer
// certificate for the same name.
func (s *Server) Upload(ctx context.Context, b Backend) (int, error) {
	if s.CacheDir == "" {
		return 0, nil
	}
	// CacheDir belongs to the edge user: every read goes through an os.Root
	// (no symlinks out of it) and accepts regular files only, so a
	// compromised edge cannot make root upload e.g. /etc/shadow.
	root, err := os.OpenRoot(s.CacheDir)
	if errors.Is(err, fs.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	defer root.Close()
	var keys []string
	err = fs.WalkDir(root.FS(), ".", func(key string, d fs.DirEntry, err error) error {
		if err != nil || key == "." {
			return err
		}
		top, _, _ := strings.Cut(key, "/")
		if d.IsDir() {
			if top == "locks" || slices.Contains(s.LocalPrefixes, top) || strings.HasPrefix(d.Name(), ".") {
				return fs.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() || strings.HasPrefix(d.Name(), ".") || nodeproto.ValidateStorageKey(key) != nil {
			return nil
		}
		keys = append(keys, key)
		return nil
	})
	if err != nil {
		return 0, err
	}
	n := 0
	for _, key := range keys {
		res, err := s.call(ctx, b, nodeproto.StorageRequest{Op: nodeproto.StorageExists, Key: key})
		if err != nil {
			return n, err
		}
		if res.Exists {
			continue
		}
		v, err := safefs.ReadFile(root, key, nodeproto.StorageMaxValue)
		if errors.Is(err, safefs.ErrTooLarge) || errors.Is(err, safefs.ErrNotRegular) {
			s.log().Warn("shared storage: not uploading file", "key", key, "err", err)
			continue
		}
		if err != nil {
			return n, err
		}
		res, err = s.call(ctx, b, nodeproto.StorageRequest{Op: nodeproto.StorageStore, Key: key, Value: v})
		if err != nil {
			return n, err
		}
		if res.Error != "" {
			return n, fmt.Errorf("store %s: %s", key, res.Error)
		}
		n++
	}
	return n, nil
}

func (s *Server) call(ctx context.Context, b Backend, req nodeproto.StorageRequest) (nodeproto.StorageResponse, error) {
	t := s.Timeout
	if t <= 0 {
		t = 20 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, t)
	defer cancel()
	return b.Storage(ctx, req)
}

// ServeHTTP implements the relay API.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != Path || r.Method != http.MethodPost {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	var req nodeproto.StorageRequest
	// base64 inflates values by 4/3; allow a little framing on top.
	if err := json.NewDecoder(io.LimitReader(r.Body, nodeproto.StorageMaxValue*2)).Decode(&req); err != nil {
		http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
		return
	}
	b, ready := s.current()
	if b == nil || !ready {
		http.Error(w, ErrUnavailable.Error(), http.StatusServiceUnavailable)
		return
	}
	res, err := s.call(r.Context(), b, req)
	if err != nil {
		http.Error(w, "shared storage unavailable: "+err.Error(), http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(res)
}

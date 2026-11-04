// SPDX-License-Identifier: Apache-2.0

// Package edgefallback implements http.handlers.edge_fallback, the Always
// Online handler (DESIGN.md §12.2, fallback chain §6.5). It sits in front of
// the cache and the reverse proxy. In "fallback" mode it passes requests on
// and, when the result is a 502/503/504 (or a handler error with one of
// those statuses, e.g. no reachable upstream), answers from the app's latest
// crawled snapshot instead. In "static_mirror" mode it always answers from
// the snapshot. Snapshot responses carry X-Edge-Served-From: snapshot.
//
// Snapshots are written by the control plane (internal/crawler):
//
//	<root>/latest -> <id>
//	<root>/<id>/manifest.json
//	<root>/<id>/files/<hash>
package edgefallback

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

const (
	ModeFallback     = "fallback"
	ModeStaticMirror = "static_mirror"

	// ServedFromHeader marks responses served from a snapshot.
	ServedFromHeader = "X-Edge-Served-From"
)

func init() {
	caddy.RegisterModule(Fallback{})
}

// Fallback serves an app's Always Online snapshot.
type Fallback struct {
	// Root is the app's snapshot directory (<state-dir>/snapshots/<app>).
	Root string `json:"root"`
	// Mode is "fallback" (default) or "static_mirror".
	Mode string `json:"mode,omitempty"`

	logger *zap.Logger
	cache  *snapCache
}

func (Fallback) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.edge_fallback",
		New: func() caddy.Module { return new(Fallback) },
	}
}

func (f *Fallback) Provision(ctx caddy.Context) error {
	f.logger = ctx.Logger()
	f.cache = &snapCache{}
	if f.Mode == "" {
		f.Mode = ModeFallback
	}
	return nil
}

func (f *Fallback) Validate() error {
	if f.Root == "" {
		return errors.New("root is required")
	}
	if f.Mode != ModeFallback && f.Mode != ModeStaticMirror {
		return fmt.Errorf("mode must be %s or %s, got %q", ModeFallback, ModeStaticMirror, f.Mode)
	}
	return nil
}

func (f *Fallback) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	servable := r.Method == http.MethodGet || r.Method == http.MethodHead
	if f.Mode == ModeStaticMirror && servable {
		if snap := f.snapshot(); snap != nil {
			snap.serve(w, r)
			return nil
		}
		// No snapshot yet: serve live rather than failing.
	}
	if !servable {
		return next.ServeHTTP(w, r)
	}

	orig := w.Header().Clone()
	iw := &interceptor{ResponseWriterWrapper: &caddyhttp.ResponseWriterWrapper{ResponseWriter: w}}
	err := next.ServeHTTP(iw, r)

	failed := iw.intercepted
	if err != nil && !iw.wroteHeader {
		var he caddyhttp.HandlerError
		if errors.As(err, &he) && isUnavailable(he.StatusCode) {
			failed = true
		}
	}
	if !failed {
		return err
	}
	snap := f.snapshot()
	if snap == nil {
		if iw.intercepted { // replay the origin's error response
			w.WriteHeader(iw.status)
			_, _ = w.Write(iw.buf.Bytes())
			return nil
		}
		return err
	}
	f.logger.Debug("origin unavailable; serving snapshot", zap.String("uri", r.RequestURI), zap.Int("status", iw.status), zap.Error(err))
	// Drop whatever the failed upstream response put in the header map.
	h := w.Header()
	for k := range h {
		delete(h, k)
	}
	for k, v := range orig {
		h[k] = v
	}
	snap.serve(w, r)
	return nil
}

func isUnavailable(code int) bool {
	return code == http.StatusBadGateway || code == http.StatusServiceUnavailable || code == http.StatusGatewayTimeout
}

// interceptor holds back 502/503/504 responses so they can be replaced.
type interceptor struct {
	*caddyhttp.ResponseWriterWrapper
	wroteHeader bool
	intercepted bool
	status      int
	buf         bytes.Buffer
}

func (w *interceptor) WriteHeader(code int) {
	if w.wroteHeader {
		return
	}
	if code >= 100 && code < 200 {
		w.ResponseWriterWrapper.WriteHeader(code)
		return
	}
	w.wroteHeader = true
	w.status = code
	if isUnavailable(code) {
		w.intercepted = true
		return
	}
	w.ResponseWriterWrapper.WriteHeader(code)
}

func (w *interceptor) Write(b []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	if w.intercepted {
		if w.buf.Len() < 64<<10 {
			w.buf.Write(b)
		}
		return len(b), nil
	}
	return w.ResponseWriterWrapper.Write(b)
}

// Flush must not commit headers of a response we may still replace.
func (w *interceptor) Flush() {
	if !w.wroteHeader || w.intercepted {
		return
	}
	_ = http.NewResponseController(w.ResponseWriterWrapper).Flush()
}

func (w *interceptor) FlushError() error {
	w.Flush()
	return nil
}

// ReadFrom keeps io.Copy from bypassing Write via the wrapper's ReadFrom.
func (w *interceptor) ReadFrom(r io.Reader) (int64, error) {
	return io.Copy(writerOnly{w}, r)
}

type writerOnly struct{ io.Writer }

// manifest mirrors internal/crawler.Manifest (the on-disk contract).
type manifest struct {
	ID      string           `json:"id"`
	Entries map[string]entry `json:"entries"`
}

type entry struct {
	Status      int    `json:"status"`
	ContentType string `json:"content_type,omitempty"`
	File        string `json:"file,omitempty"`
	Location    string `json:"location,omitempty"`
}

// snapCache remembers the parsed manifest of the latest snapshot.
type snapCache struct {
	mu   sync.Mutex
	snap *snapshot
}

type snapshot struct {
	dir     string // resolved snapshot directory
	man     manifest
	created time.Time
}

// snapshot returns the latest snapshot, re-reading the manifest only when
// the latest pointer moves. It returns nil when there is none.
func (f *Fallback) snapshot() *snapshot {
	id, err := os.Readlink(filepath.Join(f.Root, "latest"))
	if err != nil {
		return nil
	}
	dir := filepath.Join(f.Root, filepath.Base(id))
	f.cache.mu.Lock()
	defer f.cache.mu.Unlock()
	if c := f.cache.snap; c != nil && c.dir == dir {
		return c
	}
	b, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		f.logger.Warn("reading snapshot manifest", zap.Error(err))
		return nil
	}
	s := &snapshot{dir: dir}
	if err := json.Unmarshal(b, &s.man); err != nil {
		f.logger.Warn("parsing snapshot manifest", zap.String("dir", dir), zap.Error(err))
		return nil
	}
	if fi, err := os.Stat(filepath.Join(dir, "manifest.json")); err == nil {
		s.created = fi.ModTime()
	}
	f.cache.snap = s
	return s
}

// lookup finds the entry for a request: exact path+query, then path, then
// the directory index.
func (s *snapshot) lookup(r *http.Request) (entry, bool) {
	p := r.URL.EscapedPath()
	if p == "" {
		p = "/"
	}
	cands := []string{}
	if r.URL.RawQuery != "" {
		cands = append(cands, p+"?"+r.URL.RawQuery)
	}
	cands = append(cands, p)
	if strings.HasSuffix(p, "/") {
		cands = append(cands, p+"index.html")
	} else {
		cands = append(cands, p+"/", p+"/index.html")
	}
	for _, c := range cands {
		if e, ok := s.man.Entries[c]; ok {
			return e, true
		}
	}
	return entry{}, false
}

const notFoundPage = `<!doctype html><html><head><meta charset="utf-8"><title>Not available offline</title></head>` +
	`<body style="font:16px/1.5 system-ui,sans-serif;max-width:40em;margin:4em auto;padding:0 1em">` +
	`<h1>Page not available</h1><p>This site is temporarily offline and this page is not in the cached copy.</p>` +
	`<p><a href="/">Go to the home page</a></p></body></html>`

func (s *snapshot) serve(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set(ServedFromHeader, "snapshot")
	h.Set("Cache-Control", "no-cache")
	e, ok := s.lookup(r)
	if ok && e.Location != "" {
		h.Set("Location", e.Location)
		w.WriteHeader(e.Status)
		return
	}
	var f *os.File
	if ok {
		var err error
		f, err = os.Open(filepath.Join(s.dir, filepath.FromSlash(e.File)))
		if err != nil {
			ok = false
		}
	}
	if !ok {
		h.Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusNotFound)
		if r.Method != http.MethodHead {
			_, _ = io.WriteString(w, notFoundPage)
		}
		return
	}
	defer f.Close()
	ct := e.ContentType
	if ct == "" {
		ct = "application/octet-stream"
	}
	h.Set("Content-Type", ct)
	h.Del("Content-Length")
	// ServeContent handles HEAD, Range and conditional requests.
	http.ServeContent(w, r, "", s.created, f)
}

var (
	_ caddy.Provisioner           = (*Fallback)(nil)
	_ caddy.Validator             = (*Fallback)(nil)
	_ caddyhttp.MiddlewareHandler = (*Fallback)(nil)
)

// SPDX-License-Identifier: Apache-2.0

// Package controlsrv is the control plane's single HTTP server. Caddy
// forwards the control hostnames (admin panel, access portal, login-to-play)
// to it over a unix socket, and it dispatches each request by Host.
package controlsrv

import (
	"context"
	"errors"
	"net"
	"net/http"
	"os"
	"os/user"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Mux routes requests to a handler by Host. The host table is replaced on
// every config apply.
type Mux struct {
	mu    sync.RWMutex
	hosts map[string]http.Handler
}

// SetHosts replaces the host → handler table. Hosts are matched
// case-insensitively, without port.
func (m *Mux) SetHosts(hosts map[string]http.Handler) {
	t := make(map[string]http.Handler, len(hosts))
	for h, handler := range hosts {
		t[strings.ToLower(h)] = handler
	}
	m.mu.Lock()
	m.hosts = t
	m.mu.Unlock()
}

func (m *Mux) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	host := strings.ToLower(r.Host)
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	m.mu.RLock()
	h := m.hosts[host]
	m.mu.RUnlock()
	if h == nil {
		http.NotFound(w, r)
		return
	}
	h.ServeHTTP(w, r)
}

// ClientIP returns the original client address. Requests only arrive via
// Caddy on a unix socket, which sets X-Forwarded-For, so the header is trusted.
func ClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if i := strings.IndexByte(xff, ','); i >= 0 {
			xff = xff[:i]
		}
		return strings.TrimSpace(xff)
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// EdgeGroup is the group ingressd-edge runs as (see deploy/install.sh).
const EdgeGroup = "ingressd"

// ShareSocket makes a control-plane socket usable by the edge: mode 0660 and,
// when the EdgeGroup exists, group-owned by it. Without the group (tests,
// dev machines) the socket stays root-only, which is fine when Caddy also
// runs as root.
//
// The run directory is shared with the (less trusted) edge, so path must not
// be trusted to still name our socket: symlinks are never followed and
// anything but a socket is refused (see shareSocket).
func ShareSocket(path string) error {
	return shareSocket(path, edgeGID())
}

// edgeGID is EdgeGroup's gid, or -1 when the group does not exist.
func edgeGID() int {
	g, err := user.LookupGroup(EdgeGroup)
	if err != nil {
		return -1
	}
	gid, err := strconv.Atoi(g.Gid)
	if err != nil {
		return -1
	}
	return gid
}

// Listen replaces any stale entry at path with a new unix socket shared with
// the edge (see ShareSocket).
func Listen(path string) (net.Listener, error) {
	// Remove does not follow a final symlink: at worst it unlinks the link.
	_ = os.Remove(path)
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := ShareSocket(path); err != nil {
		ln.Close()
		return nil, err
	}
	return ln, nil
}

// Serve listens on a unix socket at path (see Listen) until ctx is
// cancelled.
func Serve(ctx context.Context, path string, h http.Handler) error {
	ln, err := Listen(path)
	if err != nil {
		return err
	}
	srv := &http.Server{Handler: h, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()
	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

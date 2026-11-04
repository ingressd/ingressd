// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/ingressd/ingressd/internal/connector/proto"
	"github.com/ingressd/ingressd/internal/controlsrv"
	"github.com/ingressd/ingressd/pkg/config"
)

// Server serves the connector endpoints on the admin hostname. It lives as
// long as the control plane; Update swaps in each newly applied config and
// wakes long polls.
type Server struct {
	Store *Store
	// Reapply re-renders and applies the edge so a newly enrolled site key
	// takes effect. It is called before the enroll response is sent.
	Reapply func(ctx context.Context) error
	Log     *slog.Logger
	// Now is overridable in tests.
	Now func() time.Time
	// OnDiscovery, if set, receives every connector discovery report after
	// it is stored (managed mode forwards it to the panel).
	OnDiscovery func(tunnel string, rep proto.DiscoveryReport)

	relMu sync.Mutex // serialises release relay downloads (update.go)

	replay replayCache // v2 IngressdKey nonces already used (tunnelctl.go)

	mu      sync.Mutex
	cfg     *config.Config
	keys    EdgeKeys
	changed chan struct{}
}

// Update installs the current config and notifies waiting polls.
func (s *Server) Update(cfg *config.Config, keys EdgeKeys) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cfg, s.keys = cfg, keys
	if s.changed != nil {
		close(s.changed)
	}
	s.changed = make(chan struct{})
}

func (s *Server) snapshot() (*config.Config, EdgeKeys, chan struct{}) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.changed == nil {
		s.changed = make(chan struct{})
	}
	return s.cfg, s.keys, s.changed
}

func (s *Server) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Server) log() *slog.Logger {
	if s.Log != nil {
		return s.Log
	}
	return slog.Default()
}

// ConnectorHandler serves /.ingressd/connector/ (enroll, poll, report).
func (s *Server) ConnectorHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST "+proto.EnrollPath, s.enroll)
	mux.HandleFunc("GET "+proto.PollPath, s.poll)
	mux.HandleFunc("POST "+proto.ReportPath, s.report)
	mux.HandleFunc("POST "+proto.DiscoveryPath, s.discovery)
	mux.HandleFunc("GET "+proto.WSPath, s.tunnel)
	mux.HandleFunc("GET "+proto.ReleasePathPrefix+"{asset}", s.serveRelease)
	return mux
}

// TunnelHandler serves /.ingressd/tunnel/<tunnel>: WireGuard over WebSocket.
func (s *Server) TunnelHandler() http.Handler { return http.HandlerFunc(s.tunnel) }

func (s *Server) enroll(w http.ResponseWriter, r *http.Request) {
	var req proto.EnrollRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
		http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
		return
	}
	key, err := wgtypes.ParseKey(req.PublicKey)
	if err != nil {
		http.Error(w, "public_key: "+err.Error(), http.StatusBadRequest)
		return
	}
	cfg, keys, _ := s.snapshot()
	if cfg == nil {
		http.Error(w, "edge is not configured yet", http.StatusServiceUnavailable)
		return
	}
	tunnel, cred, err := s.Store.Enroll(req.Token, key.String(), req.Hostname, s.now())
	if errors.Is(err, ErrBadToken) {
		s.log().Warn("connector enrollment rejected", "client", controlsrv.ClientIP(r))
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	if err != nil {
		s.log().Error("connector enrollment", "err", err)
		http.Error(w, "enrollment failed", http.StatusInternalServerError)
		return
	}
	s.log().Info("connector enrolled", "tunnel", tunnel, "hostname", req.Hostname, "client", controlsrv.ClientIP(r))
	if s.Reapply != nil {
		ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
		err := s.Reapply(ctx)
		cancel()
		if err != nil {
			// The key is recorded; the next successful apply picks it up.
			s.log().Error("apply after enrollment failed", "tunnel", tunnel, "err", err)
		}
		cfg, keys, _ = s.snapshot()
	}
	tc, err := TunnelConfig(cfg, keys, tunnel)
	if err != nil {
		http.Error(w, "tunnel "+tunnel+": "+err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, proto.EnrollResponse{Credential: cred, Config: tc})
}

// authorize identifies the connector and returns its tunnel name: through
// the tunnel itself (TunnelControlHandler), by the credential from
// enrolment on this node, or by a IngressdKey header made with the
// connector's WireGuard key (a connector that enrolled on another node of
// the site, whose key is the tunnel's configured public_key).
func (s *Server) authorize(w http.ResponseWriter, r *http.Request) (string, bool) {
	if tunnel, ok := r.Context().Value(tunnelPeerKey{}).(string); ok {
		return tunnel, true
	}
	if tunnel, cred, ok := proto.ParseBearer(r.Header.Get("Authorization")); ok && s.Store.Authenticate(tunnel, cred) {
		return tunnel, true
	}
	if tunnel, ok := s.keyAuth(r); ok {
		return tunnel, true
	}
	http.Error(w, "unauthorized", http.StatusUnauthorized)
	return "", false
}

// poll returns the tunnel config when its revision differs from ?rev=,
// otherwise waits up to PollWait for a change and answers 204.
func (s *Server) poll(w http.ResponseWriter, r *http.Request) {
	tunnel, ok := s.authorize(w, r)
	if !ok {
		return
	}
	rev := r.URL.Query().Get("rev")
	timer := time.NewTimer(PollWaitFor(r))
	defer timer.Stop()
	for {
		cfg, keys, changed := s.snapshot()
		if cfg == nil {
			http.Error(w, "edge is not configured yet", http.StatusServiceUnavailable)
			return
		}
		if _, ok := cfg.Tunnels[tunnel]; !ok {
			http.Error(w, "tunnel "+tunnel+" no longer exists", http.StatusGone)
			return
		}
		tc, err := TunnelConfig(cfg, keys, tunnel)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		tc.DiscoverID = s.pendingDiscovery(r, tunnel)
		tc.Update = s.pendingUpdate(r, tunnel)
		if tc.Revision != rev || tc.DiscoverID != "" || tc.Update != nil {
			writeJSON(w, tc)
			return
		}
		select {
		case <-changed:
		case <-timer.C:
			w.WriteHeader(http.StatusNoContent)
			return
		case <-r.Context().Done():
			return
		}
	}
}

// PollWaitFor returns the requested ?wait= duration, capped at PollWait.
func PollWaitFor(r *http.Request) time.Duration {
	if d, err := time.ParseDuration(r.URL.Query().Get("wait")); err == nil && d >= 0 && d < proto.PollWait {
		return d
	}
	return proto.PollWait
}

func (s *Server) report(w http.ResponseWriter, r *http.Request) {
	tunnel, ok := s.authorize(w, r)
	if !ok {
		return
	}
	var h proto.Health
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 256<<10)).Decode(&h); err != nil {
		http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
		return
	}
	h.Time = s.now().UTC() // the edge's clock is authoritative for staleness
	if err := s.Store.Report(tunnel, h); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// tunnel bridges WebSocket binary messages (one WireGuard datagram each) to
// the tunnel's UDP listen port on loopback. WireGuard authenticates the
// packets itself; the credential check keeps the relay to enrolled sites.
func (s *Server) tunnel(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, proto.TunnelPathPrefix)
	if r.URL.Path == proto.WSPath { // tunnel named by the authentication
		name, _ = proto.ParseKeyAuth(r.Header.Get("Authorization"))
		if b, _, ok := proto.ParseBearer(r.Header.Get("Authorization")); ok {
			name = b
		}
	}
	cfg, _, _ := s.snapshot()
	if cfg == nil {
		http.NotFound(w, r)
		return
	}
	t, ok := cfg.Tunnels[name]
	if !ok || !t.FallbackWS {
		http.NotFound(w, r)
		return
	}
	authTunnel, ok := s.authorize(w, r)
	if !ok {
		return
	}
	if authTunnel != name {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	udp, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: t.ListenPort})
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer udp.Close()
	ws, err := websocket.Accept(w, r, nil)
	if err != nil {
		return
	}
	ws.SetReadLimit(1 << 16)
	s.log().Info("websocket tunnel connected", "tunnel", name, "client", controlsrv.ClientIP(r))
	err = Bridge(r.Context(), ws, udp)
	s.log().Info("websocket tunnel closed", "tunnel", name, "err", err)
}

// Bridge copies datagrams between a WebSocket and a connected UDP socket
// until either side fails.
func Bridge(ctx context.Context, ws *websocket.Conn, udp *net.UDPConn) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	errc := make(chan error, 2)
	go func() {
		for {
			_, b, err := ws.Read(ctx)
			if err != nil {
				errc <- err
				return
			}
			if _, err := udp.Write(b); err != nil {
				errc <- err
				return
			}
		}
	}()
	go func() {
		buf := make([]byte, 1<<16)
		for {
			n, err := udp.Read(buf)
			if err != nil {
				errc <- err
				return
			}
			if err := ws.Write(ctx, websocket.MessageBinary, buf[:n]); err != nil {
				errc <- err
				return
			}
		}
	}()
	err := <-errc
	cancel()
	ws.CloseNow()
	udp.Close()
	return err
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(v)
}

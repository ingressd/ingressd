// SPDX-License-Identifier: Apache-2.0

package mesh

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/ingressd/ingressd/pkg/config"
	"github.com/ingressd/ingressd/pkg/nodeproto"
)

const (
	probeInterval = 5 * time.Second
	probeTimeout  = 2 * time.Second
	// downAfter consecutive failed probes mark a peer down.
	downAfter = 2
)

type peer struct {
	id        string
	addr      netip.Addr
	publicKey string
	probed    bool
	fails     int
	lastOK    time.Time
	rtt       time.Duration
	lastErr   string
}

func (p *peer) up() bool { return p.probed && p.fails < downAfter && !p.lastOK.IsZero() }

// Mesh is the runtime side of the node mesh. Create it with New.
type Mesh struct {
	log *slog.Logger
	mux *http.ServeMux
	// Device reads WireGuard state (tests replace it).
	Device func(name string) (*wgtypes.Device, error)

	mu     sync.Mutex
	self   netip.Addr
	peers  map[string]*peer
	byAddr map[netip.Addr]string
	srv    *http.Server
	bound  netip.Addr
	kick   chan struct{}
	client *http.Client
}

// New returns a mesh runtime; Run starts it, Reconfigure feeds it config.
func New(log *slog.Logger) *Mesh {
	m := &Mesh{
		log:    log,
		mux:    http.NewServeMux(),
		Device: WGDevice,
		peers:  map[string]*peer{},
		byAddr: map[netip.Addr]string{},
		kick:   make(chan struct{}, 1),
		client: &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{
			DialContext:         (&net.Dialer{Timeout: 3 * time.Second}).DialContext,
			MaxIdleConnsPerHost: 4,
			IdleConnTimeout:     60 * time.Second,
		}},
	}
	m.mux.HandleFunc("GET /v1/ping", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"ok": true, "time": time.Now().UTC()})
	})
	return m
}

// Handle registers a handler on the mesh API. Requests only ever come from
// mesh peers; PeerID(r) names the caller.
func (m *Mesh) Handle(pattern string, h http.Handler) { m.mux.Handle(pattern, h) }

type peerKey struct{}

// PeerID returns the mesh peer id of a mesh API request.
func PeerID(r *http.Request) string {
	id, _ := r.Context().Value(peerKey{}).(string)
	return id
}

// Reconfigure applies the mesh section of cfg (nil stops the API).
func (m *Mesh) Reconfigure(cfg *config.Config) {
	m.mu.Lock()
	defer m.mu.Unlock()
	old := m.peers
	m.peers, m.byAddr, m.self = map[string]*peer{}, map[netip.Addr]string{}, netip.Addr{}
	if cfg != nil && cfg.Mesh != nil {
		if p, ok := cfg.Mesh.MeshPrefix(); ok {
			m.self = p.Addr()
		}
		for id, pc := range cfg.Mesh.Peers {
			a, ok := pc.PeerAddr()
			if !ok {
				continue
			}
			p := &peer{id: id, addr: a, publicKey: pc.PublicKey}
			if o, ok := old[id]; ok && o.addr == a {
				p.probed, p.fails, p.lastOK, p.rtt, p.lastErr = o.probed, o.fails, o.lastOK, o.rtt, o.lastErr
			}
			m.peers[id] = p
			m.byAddr[a] = id
		}
	}
	m.bindLocked()
	m.kickLocked()
}

func (m *Mesh) kickLocked() {
	select {
	case m.kick <- struct{}{}:
	default:
	}
}

// bindLocked (re)starts the API server on the mesh address.
func (m *Mesh) bindLocked() {
	if m.srv != nil && m.bound == m.self {
		return
	}
	if m.srv != nil {
		m.srv.Close()
		m.srv, m.bound = nil, netip.Addr{}
	}
	if !m.self.IsValid() {
		return
	}
	ln, err := net.Listen("tcp4", net.JoinHostPort(m.self.String(), strconv.Itoa(config.MeshAPIPort)))
	if err != nil {
		m.log.Warn("mesh API cannot listen yet; retrying", "addr", m.self, "err", err)
		return
	}
	srv := &http.Server{Handler: m.peerOnly(m.mux), ReadHeaderTimeout: 5 * time.Second}
	m.srv, m.bound = srv, m.self
	go srv.Serve(ln)
	m.log.Info("mesh API listening", "addr", ln.Addr().String())
}

// peerOnly rejects callers that are not mesh peers. WireGuard
// authenticates the source address: a packet from a peer's /32 can only
// come from the holder of that peer's key.
func (m *Mesh) peerOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, ok := m.PeerByAddr(RemoteAddr(r.RemoteAddr))
		if !ok {
			http.Error(w, "not a mesh peer", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), peerKey{}, id)))
	})
}

// RemoteAddr parses an "ip:port" remote address.
func RemoteAddr(s string) netip.Addr {
	ap, err := netip.ParseAddrPort(s)
	if err != nil {
		return netip.Addr{}
	}
	return ap.Addr().Unmap()
}

// Self returns this node's mesh address (invalid when no mesh).
func (m *Mesh) Self() netip.Addr {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.self
}

// PeerByAddr maps a mesh source address to its peer id.
func (m *Mesh) PeerByAddr(a netip.Addr) (string, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	id, ok := m.byAddr[a]
	return id, ok
}

// PeerAddr returns a peer's mesh address.
func (m *Mesh) PeerAddr(id string) (netip.Addr, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	p, ok := m.peers[id]
	if !ok {
		return netip.Addr{}, false
	}
	return p.addr, true
}

// Up reports whether a peer answered its recent health probes.
func (m *Mesh) Up(id string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	p, ok := m.peers[id]
	return ok && p.up()
}

// MarkDown records a failed exchange with a peer (e.g. an unreachable
// relay), so it counts as down until the next successful probe.
func (m *Mesh) MarkDown(id string, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if p, ok := m.peers[id]; ok {
		p.probed, p.fails = true, downAfter
		if err != nil {
			p.lastErr = err.Error()
		}
	}
	m.kickLocked()
}

// Client is an HTTP client for the mesh API of peers.
func (m *Mesh) Client() *http.Client { return m.client }

// URL returns the mesh API URL of a peer.
func (m *Mesh) URL(id, path string) (string, error) {
	a, ok := m.PeerAddr(id)
	if !ok {
		return "", fmt.Errorf("unknown mesh peer %q", id)
	}
	return "http://" + net.JoinHostPort(a.String(), strconv.Itoa(config.MeshAPIPort)) + path, nil
}

// DialPeer opens a TCP connection to a port on a peer's mesh address.
func (m *Mesh) DialPeer(ctx context.Context, id string, port int) (net.Conn, error) {
	a, ok := m.PeerAddr(id)
	if !ok {
		return nil, fmt.Errorf("unknown mesh peer %q", id)
	}
	d := net.Dialer{Timeout: 3 * time.Second}
	return d.DialContext(ctx, "tcp4", net.JoinHostPort(a.String(), strconv.Itoa(port)))
}

// Run probes peers and keeps the API bound until ctx ends.
func (m *Mesh) Run(ctx context.Context) {
	t := time.NewTicker(probeInterval)
	defer t.Stop()
	for {
		m.mu.Lock()
		m.bindLocked()
		ids := make([]string, 0, len(m.peers))
		for id := range m.peers {
			ids = append(ids, id)
		}
		m.mu.Unlock()
		var wg sync.WaitGroup
		for _, id := range ids {
			wg.Add(1)
			go func() { defer wg.Done(); m.probe(ctx, id) }()
		}
		wg.Wait()
		select {
		case <-ctx.Done():
			m.mu.Lock()
			if m.srv != nil {
				m.srv.Close()
				m.srv = nil
			}
			m.mu.Unlock()
			return
		case <-t.C:
		case <-m.kick:
		}
	}
}

func (m *Mesh) probe(ctx context.Context, id string) {
	u, err := m.URL(id, "/v1/ping")
	if err != nil {
		return
	}
	pctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	req, _ := http.NewRequestWithContext(pctx, http.MethodGet, u, nil)
	start := time.Now()
	resp, err := m.client.Do(req)
	rtt := time.Since(start)
	if err == nil {
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			err = fmt.Errorf("ping: HTTP %d", resp.StatusCode)
		}
	}
	if err != nil && errors.Is(ctx.Err(), context.Canceled) {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	p, ok := m.peers[id]
	if !ok {
		return
	}
	p.probed = true
	if err != nil {
		p.fails++
		p.lastErr = err.Error()
		return
	}
	p.fails, p.lastOK, p.rtt, p.lastErr = 0, time.Now(), rtt, ""
}

// Status reports each peer: up (probe answered), last WireGuard handshake
// and probe round-trip time over the mesh.
func (m *Mesh) Status() []nodeproto.MeshPeer {
	hs := map[string]time.Time{}
	if m.Device != nil {
		if dev, err := m.Device(config.MeshInterface); err == nil {
			for _, p := range dev.Peers {
				hs[p.PublicKey.String()] = p.LastHandshakeTime
			}
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]nodeproto.MeshPeer, 0, len(m.peers))
	for _, p := range m.peers {
		mp := nodeproto.MeshPeer{NodeID: p.id, Up: p.up(), LastHandshake: hs[p.publicKey]}
		if mp.Up {
			mp.RTTMillis = float64(p.rtt.Microseconds()) / 1000
		}
		out = append(out, mp)
	}
	slices.SortFunc(out, func(a, b nodeproto.MeshPeer) int { return cmp.Compare(a.NodeID, b.NodeID) })
	return out
}

// LastError returns the last probe error for a peer, for diagnostics.
func (m *Mesh) LastError(id string) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if p, ok := m.peers[id]; ok {
		return p.lastErr
	}
	return ""
}

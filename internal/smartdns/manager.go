// SPDX-License-Identifier: Apache-2.0

// Package smartdns is the Smart DNS add-on of the node agent (see
// docs/rev1/ARCHITECTURE.md §7), ported from an earlier prototype:
//
//   - a resolver on the home node's tunnel transit addresses answers names of
//     enabled services with its own transit address, after resolving them at
//     the service's exit (so CDNs pick edges in the exit's country);
//   - an SNI/Host relay on the same addresses forwards those connections over
//     the node mesh to the exit node, which connects to the destination
//     (optionally through a VPN interface). TLS stays end to end;
//   - on exit nodes, a resolve endpoint (mesh API) and a relay listener on the
//     mesh address serve the other nodes of the org.
//
// It fails closed: when an exit is down, service names get SERVFAIL and
// their traffic is never sent anywhere else.
package smartdns

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/ingressd/ingressd/internal/mesh"
	"github.com/ingressd/ingressd/internal/render"
	"github.com/ingressd/ingressd/internal/smartdns/wgconf"
	"github.com/ingressd/ingressd/pkg/config"
	"github.com/ingressd/ingressd/pkg/nodeproto"
)

// Options configure a Manager.
type Options struct {
	Log *slog.Logger
	// StatusPath, if set, receives a JSON status snapshot every few seconds
	// (read by `ingressd smartdns status`).
	StatusPath string
	// Device reads WireGuard state; default wgctrl.
	Device func(name string) (*wgtypes.Device, error)
	// Configure changes a WireGuard interface (VPN endpoint refresh);
	// default wgctrl.
	Configure func(name string, cfg wgtypes.Config) error
	// TraceURL is fetched through each exit's egress to learn its public
	// IP and country; default $INGRESSD_SMARTDNS_TRACE_URL or Cloudflare's
	// https://1.1.1.1/cdn-cgi/trace.
	TraceURL string
	// Lookup resolves VPN endpoint host names; default net.DefaultResolver.
	Lookup func(ctx context.Context, host string) ([]netip.Addr, error)
}

// state is the configuration in effect, swapped atomically on reconfigure.
type state struct {
	cfg      *config.Config
	match    matcher
	upstream []string
	egress   map[string]*egress    // self exits
	site     map[netip.Addr]string // listen address -> tunnel name
	listen   []netip.Addr
	routes   string // fingerprint of services/exits, to invalidate the cache
}

func (s *state) exit(name string) (config.SmartDNSExit, bool) {
	if s.cfg == nil || s.cfg.SmartDNS == nil {
		return config.SmartDNSExit{}, false
	}
	e, ok := s.cfg.SmartDNS.Exits[name]
	return e, ok
}

type svcCounter struct{ bytes, conns atomic.Int64 }

// Manager runs Smart DNS and the mesh runtime for one node.
type Manager struct {
	log         *slog.Logger
	statusPath  string
	device      func(name string) (*wgtypes.Device, error)
	configure   func(name string, cfg wgtypes.Config) error
	resolveHost func(ctx context.Context, host string) ([]netip.Addr, error)
	traceURL    string
	probeMu     sync.Mutex
	probes      map[string]*probeState // exit name -> latest egress trace
	mesh        *mesh.Mesh
	remote      exitClient
	edges       *edgeChecker
	cache       *swrCache
	recent      *ring
	listeners   *listenerSet
	st          atomic.Pointer[state]
	baseCtx     atomic.Value // context.Context

	// test hooks: ports for the resolver and relay listeners
	dnsPort, tlsPort, httpPort int

	usageMu  sync.Mutex
	usage    map[string]*svcCounter
	reported map[string][2]int64

	downMu            sync.Mutex
	remoteDown        map[string]downMark // exit name -> when (and why) its node said it is down
	healthUnsupported map[string]bool     // exit nodes answering 404 on GET /v1/exits

	activeMu sync.Mutex
	active   map[string]*activeExit // service -> exit in use

	now func() time.Time

	refused, errors atomic.Int64
}

// New creates a Manager; call Run, then Reconfigure after every apply.
func New(o Options) *Manager {
	if o.Log == nil {
		o.Log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	if o.Device == nil {
		o.Device = mesh.WGDevice
	}
	if o.Configure == nil {
		o.Configure = mesh.WGConfigure
	}
	if o.TraceURL == "" {
		o.TraceURL = traceURLFromEnv()
	}
	if o.Lookup == nil {
		o.Lookup = func(ctx context.Context, host string) ([]netip.Addr, error) {
			return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		}
	}
	m := &Manager{
		log:               o.Log.With("component", "smartdns"),
		statusPath:        o.StatusPath,
		device:            o.Device,
		configure:         o.Configure,
		resolveHost:       o.Lookup,
		traceURL:          o.TraceURL,
		probes:            map[string]*probeState{},
		mesh:              mesh.New(o.Log.With("component", "mesh")),
		edges:             newEdgeChecker(),
		cache:             newCache(),
		recent:            newRing(recentSize),
		usage:             map[string]*svcCounter{},
		reported:          map[string][2]int64{},
		remoteDown:        map[string]downMark{},
		healthUnsupported: map[string]bool{},
		active:            map[string]*activeExit{},
		now:               time.Now,
		dnsPort:           53,
		tlsPort:           config.SmartDNSRelayTLSPort,
		httpPort:          config.SmartDNSRelayHTTPPort,
	}
	m.mesh.Device = o.Device
	m.remote = meshExitClient{m.mesh}
	m.listeners = &listenerSet{log: m.log, running: map[string]io.Closer{}, failed: map[string]string{}}
	m.baseCtx.Store(ctxBox{context.Background()})
	m.st.Store(&state{match: matcher{}, egress: map[string]*egress{}, site: map[netip.Addr]string{}})
	m.mesh.Handle("POST /v1/resolve", m.resolveHandler())
	m.mesh.Handle("GET /v1/exits", m.exitsHandler())
	return m
}

// Mesh returns the mesh runtime (status, peers).
func (m *Manager) Mesh() *mesh.Mesh { return m.mesh }

// ctxBox gives atomic.Value one concrete type.
type ctxBox struct{ context.Context }

func (m *Manager) ctx() context.Context { return m.baseCtx.Load().(ctxBox).Context }

func (m *Manager) state() *state { return m.st.Load() }

// Run runs background work (mesh probes, listener retries, status file)
// until ctx ends.
func (m *Manager) Run(ctx context.Context) {
	m.baseCtx.Store(ctxBox{ctx})
	go m.mesh.Run(ctx)
	go m.runHealthPoll(ctx)
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	for n := 0; ; n++ {
		select {
		case <-ctx.Done():
			m.listeners.closeAll()
			return
		case <-t.C:
		}
		if n%3 == 0 {
			m.listeners.retry()
		}
		m.watchEgress(time.Now())
		m.refreshActive(m.state())
		m.writeStatus()
	}
}

// Reconfigure applies cfg; res resolves secret:// references (VPN configs).
// Call it after every successful apply (the kernel side, ix-mesh and VPN
// interfaces, is applied by the pipeline first).
func (m *Manager) Reconfigure(cfg *config.Config, res func(string) (string, error)) {
	st := &state{cfg: cfg, match: newMatcher(cfg.SmartDNS), egress: map[string]*egress{}, site: map[netip.Addr]string{}}
	if s := cfg.SmartDNS; s != nil {
		for _, u := range s.Upstream {
			st.upstream = append(st.upstream, hostPort(u))
		}
		for _, name := range sortedKeys(s.Exits) {
			ex := s.Exits[name]
			if !ex.IsSelf() {
				continue
			}
			e := &egress{exit: name, country: ex.Country, dns: st.upstream, public: cfg.Edge.PublicIPv4, device: m.device}
			if ex.VPN != "" {
				e.ifname = config.VPNInterfaceName(name)
				e.mark, _ = render.VPNMark(cfg, name)
				e.public = ""
				if text, err := res(ex.VPN); err != nil {
					m.log.Error("exit VPN config unavailable", "exit", name, "err", err)
				} else if wc, err := wgconf.Parse(text); err != nil {
					m.log.Error("exit VPN config invalid", "exit", name, "err", err)
				} else {
					e.endpoint, e.peerKey = wc.Peer.Endpoint, wc.Peer.PublicKey
					// The tunnel's DNS servers resolve service names (the
					// provider's resolver sees the exit's location); without
					// a DNS line the upstream resolvers are asked through
					// the tunnel. The node's own resolver is never changed.
					if len(wc.DNS) > 0 {
						e.dns = nil
						for _, d := range wc.DNS {
							e.dns = append(e.dns, hostPort(d.String()))
						}
					}
				}
			}
			st.egress[name] = e
		}
		var fp []string
		for _, name := range sortedKeys(s.Exits) {
			ex := s.Exits[name]
			fp = append(fp, "e:"+name+"="+ex.Node+","+ex.VPN)
		}
		st.routes = strings.Join(fp, ";")
	}
	st.listen = cfg.SmartDNSListen()
	for _, name := range sortedKeys(cfg.Tunnels) {
		if a, ok := cfg.TransitEdgeAddr(name); ok {
			st.site[a] = name
		}
	}
	if old := m.state(); old.routes != st.routes {
		m.cache.clear()
	}
	m.st.Store(st)
	m.pruneActive(st.match)
	m.edges.setChecks(cfg.SmartDNS)
	m.mesh.Reconfigure(cfg)

	want := map[string]func() (io.Closer, error){}
	for _, a := range st.listen {
		a := a
		want["dns-udp "+addrPort(a, m.dnsPort)] = func() (io.Closer, error) { return m.listenDNS("udp", addrPort(a, m.dnsPort)) }
		want["dns-tcp "+addrPort(a, m.dnsPort)] = func() (io.Closer, error) { return m.listenDNS("tcp", addrPort(a, m.dnsPort)) }
		want["relay-tls "+addrPort(a, m.tlsPort)] = func() (io.Closer, error) { return m.listenRelay(addrPort(a, m.tlsPort), true) }
		want["relay-http "+addrPort(a, m.httpPort)] = func() (io.Closer, error) { return m.listenRelay(addrPort(a, m.httpPort), false) }
	}
	if self, ok := cfg.Mesh.MeshPrefix(); ok && len(st.egress) > 0 {
		ap := addrPort(self.Addr(), config.MeshRelayPort)
		want["exit-relay "+ap] = func() (io.Closer, error) { return m.listenExitRelay(ap) }
	}
	m.listeners.set(want)
}

func addrPort(a netip.Addr, port int) string { return net.JoinHostPort(a.String(), strconv.Itoa(port)) }

// --- usage ---

func (m *Manager) counter(service string) *svcCounter {
	m.usageMu.Lock()
	defer m.usageMu.Unlock()
	c, ok := m.usage[service]
	if !ok {
		c = &svcCounter{}
		m.usage[service] = c
	}
	return c
}

// usageTotals returns cumulative bytes and connections per service.
func (m *Manager) usageTotals() []nodeproto.ServiceUsage {
	m.usageMu.Lock()
	defer m.usageMu.Unlock()
	out := []nodeproto.ServiceUsage{}
	for _, name := range sortedKeys(m.usage) {
		c := m.usage[name]
		out = append(out, nodeproto.ServiceUsage{Service: name, Bytes: c.bytes.Load(), Conns: c.conns.Load()})
	}
	return out
}

// --- node agent hooks ---
//
// Manager implements the node agent's Smart DNS hook interfaces
// (internal/nodeagent/hooks.go: ExitReporter, MeshReporter,
// ServiceUsageReporter, RecentLookupReporter, Capability), so wiring is
// nodeagent.SetSmartDNS(manager).

var _ interface {
	Exits() []nodeproto.ExitStatus
	MeshPeers() []nodeproto.MeshPeer
	TakeServiceUsage() []nodeproto.ServiceUsage
	RecentLookups(limit int) []nodeproto.RecentLookup
	Capabilities() []string
	Services() []nodeproto.ServiceStatus
} = (*Manager)(nil)

// Capabilities are announced in hello.
func (m *Manager) Capabilities() []string { return []string{"smartdns", "mesh"} }

// TakeServiceUsage returns relay bytes and connections per service since the
// previous call (usage deltas for nodeproto.Usage.Smart). The caller owns
// persisting unsent deltas.
func (m *Manager) TakeServiceUsage() []nodeproto.ServiceUsage {
	m.usageMu.Lock()
	defer m.usageMu.Unlock()
	var out []nodeproto.ServiceUsage
	for _, name := range sortedKeys(m.usage) {
		c := m.usage[name]
		cur := [2]int64{c.bytes.Load(), c.conns.Load()}
		prev := m.reported[name]
		if cur != prev {
			out = append(out, nodeproto.ServiceUsage{Service: name, Bytes: cur[0] - prev[0], Conns: cur[1] - prev[1]})
			m.reported[name] = cur
		}
	}
	return out
}

// RecentLookups returns up to limit recent resolver queries, newest first.
func (m *Manager) RecentLookups(limit int) []nodeproto.RecentLookup {
	ls := m.recent.list(limit)
	out := make([]nodeproto.RecentLookup, len(ls))
	for i, l := range ls {
		out[i] = nodeproto.RecentLookup{Time: l.Time, Site: l.Site, Name: l.Name, Type: l.Type, Routed: l.Routed, Service: l.Service}
	}
	return out
}

// MeshPeers reports the mesh peers.
func (m *Manager) MeshPeers() []nodeproto.MeshPeer { return m.mesh.Status() }

// Exits reports the exits this node egresses for.
func (m *Manager) Exits() []nodeproto.ExitStatus {
	st := m.state()
	out := []nodeproto.ExitStatus{}
	for _, name := range sortedKeys(st.egress) {
		e := st.egress[name]
		up, msg := e.up()
		country, edges := m.edges.summary(name)
		ip, traced, traceErr := m.probe(e).snapshot()
		if country == "" {
			country = traced
		}
		egressIP, health := exitHealth(e, ip, traced, traceErr, up)
		es := nodeproto.ExitStatus{Name: name, Country: country, Up: up, Egress: egressIP, VPN: e.ifname != "", Endpoint: e.endpointNow()}
		es.Message = strings.Trim(strings.Join([]string{msg, health, edges}, "; "), "; ")
		out = append(out, es)
	}
	return out
}

// EdgeResults returns every edge check result (for diagnostics).
func (m *Manager) EdgeResults() []EdgeResult { return m.edges.snapshot() }

// --- status file ---

// RemoteExit is an exit on another node, as this node sees it.
type RemoteExit struct {
	Name    string `json:"name"`
	Node    string `json:"node"`
	Country string `json:"country"`
	Up      bool   `json:"up"`
	Message string `json:"message,omitempty"`
}

// Status is the snapshot written to the status file.
type Status struct {
	Updated     time.Time                 `json:"updated"`
	Listen      []string                  `json:"listen"`
	Exits       []nodeproto.ExitStatus    `json:"exits"`
	RemoteExits []RemoteExit              `json:"remote_exits"`
	Services    []nodeproto.ServiceStatus `json:"services"`
	Mesh        []nodeproto.MeshPeer      `json:"mesh"`
	Usage       []nodeproto.ServiceUsage  `json:"usage"` // cumulative since start
	Edges       []EdgeResult              `json:"edges"`
	Refused     int64                     `json:"relay_refused"`
	Errors      int64                     `json:"relay_errors"`
	Recent      []Lookup                  `json:"recent"`
}

// Snapshot returns the current status.
func (m *Manager) Snapshot() Status {
	st := m.state()
	s := Status{
		Updated: time.Now().UTC(), Listen: []string{}, Exits: m.Exits(), RemoteExits: []RemoteExit{}, Services: m.Services(),
		Mesh: m.MeshPeers(), Usage: m.usageTotals(), Edges: m.EdgeResults(),
		Refused: m.refused.Load(), Errors: m.errors.Load(), Recent: m.recent.list(100),
	}
	for _, a := range st.listen {
		s.Listen = append(s.Listen, a.String())
	}
	if st.cfg != nil && st.cfg.SmartDNS != nil {
		for _, name := range sortedKeys(st.cfg.SmartDNS.Exits) {
			ex := st.cfg.SmartDNS.Exits[name]
			if ex.IsSelf() {
				continue
			}
			up, msg := m.exitUp(st, name)
			s.RemoteExits = append(s.RemoteExits, RemoteExit{Name: name, Node: ex.Node, Country: ex.Country, Up: up, Message: msg})
		}
	}
	return s
}

func (m *Manager) writeStatus() {
	if m.statusPath == "" {
		return
	}
	b, err := json.MarshalIndent(m.Snapshot(), "", "  ")
	if err != nil {
		return
	}
	if err := os.MkdirAll(filepath.Dir(m.statusPath), 0o750); err != nil {
		return
	}
	tmp := m.statusPath + ".tmp"
	if err := os.WriteFile(tmp, b, 0o640); err == nil {
		os.Rename(tmp, m.statusPath)
	}
}

// ReadStatus reads a status file written by a running Manager.
func ReadStatus(path string) (*Status, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var s Status
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &s, nil
}

// --- listeners ---

type closerFunc func() error

func (f closerFunc) Close() error { return f() }

// listenerSet keeps a set of listeners running, retrying the ones that
// cannot bind yet (e.g. before the interface carrying the address exists).
type listenerSet struct {
	log     *slog.Logger
	mu      sync.Mutex
	want    map[string]func() (io.Closer, error)
	running map[string]io.Closer
	failed  map[string]string
}

func (l *listenerSet) set(want map[string]func() (io.Closer, error)) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.want = want
	l.syncLocked()
}

func (l *listenerSet) retry() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.syncLocked()
}

func (l *listenerSet) syncLocked() {
	for k, c := range l.running {
		if _, ok := l.want[k]; !ok {
			c.Close()
			delete(l.running, k)
			l.log.Info("stopped", "listener", k)
		}
	}
	keys := make([]string, 0, len(l.want))
	for k := range l.want {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if _, ok := l.running[k]; ok {
			continue
		}
		c, err := l.want[k]()
		if err != nil {
			if l.failed[k] != err.Error() {
				l.log.Warn("cannot listen yet; retrying", "listener", k, "err", err)
				l.failed[k] = err.Error()
			}
			continue
		}
		delete(l.failed, k)
		l.running[k] = c
		l.log.Info("listening", "listener", k)
	}
}

func (l *listenerSet) closeAll() {
	l.mu.Lock()
	defer l.mu.Unlock()
	for k, c := range l.running {
		c.Close()
		delete(l.running, k)
	}
}

func (l *listenerSet) names() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]string, 0, len(l.running))
	for k := range l.running {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

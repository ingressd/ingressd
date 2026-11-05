// SPDX-License-Identifier: Apache-2.0

// Package smartdns is Smart DNS (docs/rev1/CONNECTOR-SMARTDNS.md):
//
//   - Manager is the home side, run by the connector: a resolver on a LAN
//     address answers names of enabled services with that address, after
//     resolving them at the service's exit (so CDNs pick edges in the exit's
//     country), and an SNI/Host relay on the same address connects those
//     streams through the exit. TLS stays end to end. Exits are local (a VPN
//     tunnel on the connector) or remote (a node exit, through the
//     connector's tunnel to that node).
//   - ExitServer is the node side: it lets its own connector sites resolve
//     and connect from the node's public IP.
//
// It fails closed: when every exit of a service is down, its names get
// SERVFAIL and its traffic is never sent anywhere else.
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

	"github.com/ingressd/ingressd/pkg/config"
	"github.com/ingressd/ingressd/pkg/nodeproto"
)

// Plan is what the home side runs, built by the connector from its signed
// site config.
type Plan struct {
	// Site names the connector site (recent lookups).
	Site string
	// Listen are the addresses the resolver and relay bind.
	Listen []netip.Addr
	// ForwardAll forwards names no service routes to Upstream; otherwise
	// they are refused.
	ForwardAll    bool
	Upstream      []string
	FailbackAfter time.Duration
	Services      map[string]config.SmartDNSSiteService
	Exits         map[string]PlanExit
	Checks        []config.SmartDNSCheck
}

// PlanExit is a local egress (Egress set) or a node exit (Node set).
type PlanExit struct {
	Country string
	Node    string
	Egress  *EgressOptions
}

// Options configure a Manager.
type Options struct {
	Log *slog.Logger
	// StatusPath, if set, receives a JSON status snapshot every few seconds.
	StatusPath string
	// TraceURL is fetched through each local exit to learn its public IP
	// and country; default $INGRESSD_SMARTDNS_TRACE_URL or Cloudflare's
	// https://1.1.1.1/cdn-cgi/trace.
	TraceURL string
	// Remote reaches node exits.
	Remote ExitClient
	// DNSPort, TLSPort and HTTPPort are where the resolver and relay listen
	// (default 53, 443, 80).
	DNSPort, TLSPort, HTTPPort int
	// Listen opens listeners; default net.Listen / net.ListenPacket.
	Listen       func(network, addr string) (net.Listener, error)
	ListenPacket func(network, addr string) (net.PacketConn, error)
}

// state is the plan in effect, swapped atomically on reconfigure.
type state struct {
	plan     Plan
	match    matcher
	upstream []string
	exits    map[string]PlanExit
	egress   map[string]*egress // local exits
	listen   []netip.Addr
	routes   string // fingerprint of services/exits, to invalidate the cache
}

func (s *state) exit(name string) (PlanExit, bool) {
	e, ok := s.exits[name]
	return e, ok
}

// allRoutes returns one route per enabled service, sorted by service.
func (s *state) allRoutes() []route { return s.match.routes() }

type svcCounter struct{ bytes, conns atomic.Int64 }

// Manager runs the home side of Smart DNS.
type Manager struct {
	log          *slog.Logger
	statusPath   string
	probes       *prober
	remote       ExitClient
	edges        *edgeChecker
	cache        *swrCache
	recent       *ring
	listeners    *listenerSet
	listenFn     func(network, addr string) (net.Listener, error)
	listenPktFn  func(network, addr string) (net.PacketConn, error)
	st           atomic.Pointer[state]
	baseCtx      atomic.Value // context.Context
	dnsPort      int
	tlsPort      int
	httpPort     int
	usageMu      sync.Mutex
	usage        map[string]*svcCounter
	reported     map[string][2]int64
	downMu       sync.Mutex
	remoteDown   map[string]downMark // exit name -> when (and why) its node said it is down
	activeMu     sync.Mutex
	active       map[string]*activeExit // service -> exit in use
	now          func() time.Time
	refused, err atomic.Int64
}

// New creates a Manager; call Run, then Reconfigure whenever the plan
// changes.
func New(o Options) *Manager {
	if o.Log == nil {
		o.Log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	if o.DNSPort == 0 {
		o.DNSPort = 53
	}
	if o.TLSPort == 0 {
		o.TLSPort = 443
	}
	if o.HTTPPort == 0 {
		o.HTTPPort = 80
	}
	if o.Listen == nil {
		o.Listen = net.Listen
	}
	if o.ListenPacket == nil {
		o.ListenPacket = net.ListenPacket
	}
	m := &Manager{
		log:         o.Log.With("component", "smartdns"),
		statusPath:  o.StatusPath,
		remote:      o.Remote,
		edges:       newEdgeChecker(),
		cache:       newCache(),
		recent:      newRing(recentSize),
		usage:       map[string]*svcCounter{},
		reported:    map[string][2]int64{},
		remoteDown:  map[string]downMark{},
		active:      map[string]*activeExit{},
		now:         time.Now,
		dnsPort:     o.DNSPort,
		tlsPort:     o.TLSPort,
		httpPort:    o.HTTPPort,
		listenFn:    o.Listen,
		listenPktFn: o.ListenPacket,
	}
	m.probes = newProber(m.log, o.TraceURL, m.ctx)
	m.listeners = &listenerSet{log: m.log, running: map[string]io.Closer{}, failed: map[string]string{}}
	m.baseCtx.Store(ctxBox{context.Background()})
	m.st.Store(&state{exits: map[string]PlanExit{}, egress: map[string]*egress{}, match: matcher{}})
	return m
}

// ctxBox gives atomic.Value one concrete type.
type ctxBox struct{ context.Context }

func (m *Manager) ctx() context.Context { return m.baseCtx.Load().(ctxBox).Context }

func (m *Manager) state() *state { return m.st.Load() }

// Run runs background work (exit health, listener retries, traces, status
// file) until ctx ends.
func (m *Manager) Run(ctx context.Context) {
	m.baseCtx.Store(ctxBox{ctx})
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
		st := m.state()
		m.probes.watch(st.egress, time.Now())
		m.refreshActive(st)
		m.writeStatus()
	}
}

// Reconfigure applies p.
func (m *Manager) Reconfigure(p Plan) {
	st := &state{plan: p, exits: map[string]PlanExit{}, egress: map[string]*egress{}, listen: slices.Clone(p.Listen)}
	for _, u := range p.Upstream {
		st.upstream = append(st.upstream, hostPort(u))
	}
	st.match = newMatcher(p.Services)
	var fp []string
	for _, name := range sortedKeys(p.Exits) {
		ex := p.Exits[name]
		st.exits[name] = ex
		if ex.Egress != nil {
			o := *ex.Egress
			o.Name, o.Country = name, ex.Country
			st.egress[name] = newEgress(o)
			fp = append(fp, "e:"+name+"=local:"+o.Sig)
		} else {
			fp = append(fp, "e:"+name+"=node:"+ex.Node)
		}
	}
	slices.SortFunc(st.listen, func(a, b netip.Addr) int { return a.Compare(b) })
	st.routes = strings.Join(fp, ";")
	if old := m.state(); old.routes != st.routes {
		m.cache.clear()
	}
	m.st.Store(st)
	m.pruneActive(st.allRoutes())
	m.edges.setChecks(p.Checks)

	want := map[string]func() (io.Closer, error){}
	for _, a := range st.listen {
		a := a
		want["dns-udp "+addrPort(a, m.dnsPort)] = func() (io.Closer, error) { return m.listenDNS("udp", addrPort(a, m.dnsPort)) }
		want["dns-tcp "+addrPort(a, m.dnsPort)] = func() (io.Closer, error) { return m.listenDNS("tcp", addrPort(a, m.dnsPort)) }
		want["relay-tls "+addrPort(a, m.tlsPort)] = func() (io.Closer, error) { return m.listenRelay(addrPort(a, m.tlsPort), true) }
		want["relay-http "+addrPort(a, m.httpPort)] = func() (io.Closer, error) { return m.listenRelay(addrPort(a, m.httpPort), false) }
	}
	m.listeners.set(want)
}

// BindErrors returns the listeners that could not start, keyed by kind
// (dns-udp, dns-tcp, relay-tls, relay-http).
func (m *Manager) BindErrors() map[string]string {
	out := map[string]string{}
	for k, err := range m.listeners.failures() {
		kind, _, _ := strings.Cut(k, " ")
		out[kind] = err
	}
	return out
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

// TakeServiceUsage returns relay bytes and connections per service since the
// previous call. The caller owns resending deltas it could not deliver.
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

// Exits reports the local exits.
func (m *Manager) Exits() []nodeproto.ExitStatus {
	st := m.state()
	out := []nodeproto.ExitStatus{}
	for _, name := range sortedKeys(st.egress) {
		out = append(out, exitStatus(name, st.egress[name], m.probes, m.edges))
	}
	return out
}

// exitStatus describes a local egress for status reports.
func exitStatus(name string, e *egress, pr *prober, edges *edgeChecker) nodeproto.ExitStatus {
	up, msg := e.up()
	country, edgeMsg := edges.summary(name)
	ip, traced, traceErr := pr.probe(e).snapshot()
	if country == "" {
		country = traced
	}
	egressIP, health := exitHealth(e, ip, traced, traceErr, up)
	es := nodeproto.ExitStatus{Name: name, Country: country, Up: up, Egress: egressIP, VPN: e.vpn, Endpoint: e.endpointNow()}
	es.Message = strings.Trim(strings.Join([]string{msg, health, edgeMsg}, "; "), "; ")
	return es
}

// EdgeResults returns every edge check result (for diagnostics).
func (m *Manager) EdgeResults() []EdgeResult { return m.edges.snapshot() }

// --- status file ---

// RemoteExit is a node exit, as the connector sees it.
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
	BindErrors  map[string]string         `json:"bind_errors,omitempty"`
	Exits       []nodeproto.ExitStatus    `json:"exits"`
	RemoteExits []RemoteExit              `json:"remote_exits"`
	Services    []nodeproto.ServiceStatus `json:"services"`
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
		Updated: time.Now().UTC(), Listen: []string{}, BindErrors: m.BindErrors(), Exits: m.Exits(), RemoteExits: []RemoteExit{},
		Services: m.Services(), Usage: m.usageTotals(), Edges: m.EdgeResults(),
		Refused: m.refused.Load(), Errors: m.err.Load(), Recent: m.recent.list(100),
	}
	for _, a := range st.listen {
		s.Listen = append(s.Listen, a.String())
	}
	for _, name := range sortedKeys(st.exits) {
		ex := st.exits[name]
		if ex.Egress != nil {
			continue
		}
		up, msg := m.exitUp(st, name)
		s.RemoteExits = append(s.RemoteExits, RemoteExit{Name: name, Node: ex.Node, Country: ex.Country, Up: up, Message: msg})
	}
	return s
}

func (m *Manager) writeStatus() {
	if m.statusPath == "" {
		return
	}
	writeStatusFile(m.statusPath, m.Snapshot())
}

func writeStatusFile(path string, v any) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o640); err == nil {
		os.Rename(tmp, path)
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
	for k := range l.failed {
		if _, ok := l.want[k]; !ok {
			delete(l.failed, k)
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

func (l *listenerSet) failures() map[string]string {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make(map[string]string, len(l.failed))
	for k, v := range l.failed {
		out[k] = v
	}
	return out
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

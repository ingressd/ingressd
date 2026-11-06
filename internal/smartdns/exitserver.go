// SPDX-License-Identifier: Apache-2.0

package smartdns

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ingressd/ingressd/pkg/config"
	"github.com/ingressd/ingressd/pkg/nodeproto"
)

// ExitServerOptions configure an ExitServer.
type ExitServerOptions struct {
	Log *slog.Logger
	// StatusPath, if set, receives a JSON status snapshot every few seconds
	// (read by `ingressd smartdns status`).
	StatusPath string
	// TraceURL: see Options.TraceURL.
	TraceURL string
	// Dial connects from the node; default the host's own route. Tests
	// replace it.
	Dial DialFunc
	// APIPort and RelayPort default to config.SmartDNSExitAPIPort and
	// config.SmartDNSExitRelayPort.
	APIPort, RelayPort int
}

// exitServerState is the config in effect.
type exitServerState struct {
	egress *egress
	// sites maps each listen (edge transit) address to its tunnel, and
	// peer the tunnel's site address that alone may call it.
	sites map[netip.Addr]string
	peer  map[netip.Addr]netip.Addr
}

// ExitServer is a node exit: it resolves and connects for its own connector
// sites from the node's public IP, reached by each site through its tunnel
// only.
type ExitServer struct {
	log        *slog.Logger
	statusPath string
	dial       DialFunc
	probes     *prober
	edges      *edgeChecker
	listeners  *listenerSet
	st         atomic.Pointer[exitServerState]
	baseCtx    atomic.Value // context.Context
	apiPort    int
	relayPort  int
	refused    atomic.Int64
	usageMu    sync.Mutex
	usage      map[string]*siteUsage // by tunnel
}

// maxSiteStreams caps one site's open relay streams. A household's devices
// use far fewer; the cap keeps one site from using up the node's sockets.
const maxSiteStreams = 1024

// siteUsage counts one site's use of the exit.
type siteUsage struct {
	conns, active, bytes atomic.Int64
}

func (s *ExitServer) usageFor(site string) *siteUsage {
	s.usageMu.Lock()
	defer s.usageMu.Unlock()
	u := s.usage[site]
	if u == nil {
		u = &siteUsage{}
		s.usage[site] = u
	}
	return u
}

// NewExitServer creates an ExitServer; call Run, then Reconfigure after
// every apply.
func NewExitServer(o ExitServerOptions) *ExitServer {
	if o.Log == nil {
		o.Log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	if o.APIPort == 0 {
		o.APIPort = config.SmartDNSExitAPIPort
	}
	if o.RelayPort == 0 {
		o.RelayPort = config.SmartDNSExitRelayPort
	}
	s := &ExitServer{
		log:        o.Log.With("component", "smartdns-exit"),
		statusPath: o.StatusPath,
		dial:       o.Dial,
		edges:      newEdgeChecker(),
		apiPort:    o.APIPort,
		relayPort:  o.RelayPort,
		usage:      map[string]*siteUsage{},
	}
	s.probes = newProber(s.log, o.TraceURL, s.ctx)
	s.listeners = &listenerSet{log: s.log, running: map[string]io.Closer{}, failed: map[string]string{}}
	s.baseCtx.Store(ctxBox{context.Background()})
	s.st.Store(&exitServerState{sites: map[netip.Addr]string{}, peer: map[netip.Addr]netip.Addr{}})
	return s
}

func (s *ExitServer) ctx() context.Context { return s.baseCtx.Load().(ctxBox).Context }

func (s *ExitServer) state() *exitServerState { return s.st.Load() }

// Run traces the egress, retries listeners and writes the status file until
// ctx ends.
func (s *ExitServer) Run(ctx context.Context) {
	s.baseCtx.Store(ctxBox{ctx})
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	for n := 0; ; n++ {
		select {
		case <-ctx.Done():
			s.listeners.closeAll()
			return
		case <-t.C:
		}
		if n%3 == 0 {
			s.listeners.retry()
		}
		st := s.state()
		if st.egress != nil {
			s.probes.watch(map[string]*egress{st.egress.exit: st.egress}, time.Now())
		} else {
			s.probes.watch(nil, time.Now())
		}
		if s.statusPath != "" {
			writeStatusFile(s.statusPath, s.Snapshot())
		}
	}
}

// exitName is how the node names its exit in status reports.
const exitName = "node"

// Reconfigure applies cfg's smartdns.exit.
func (s *ExitServer) Reconfigure(cfg *config.Config) {
	st := &exitServerState{sites: map[netip.Addr]string{}, peer: map[netip.Addr]netip.Addr{}}
	var checks []config.SmartDNSCheck
	if cfg != nil && cfg.SmartDNS != nil && cfg.SmartDNS.Exit != nil {
		x := cfg.SmartDNS.Exit
		checks = x.Checks
		st.egress = newEgress(EgressOptions{Name: exitName, Country: x.Country, DNS: x.Upstream, Dial: s.dial, Public: cfg.Edge.PublicIPv4, Sig: x.Country})
		st.egress.health = func() (bool, string) { return s.countryOK(st.egress) }
		st.egress.alwaysTrace = true
		for _, t := range cfg.SmartDNSExitSites() {
			edge, ok1 := cfg.TransitEdgeAddr(t)
			site, ok2 := cfg.TransitSiteAddr(t)
			if ok1 && ok2 {
				st.sites[edge], st.peer[edge] = t, site
			}
		}
	}
	s.st.Store(st)
	s.edges.setChecks(checks)
	want := map[string]func() (io.Closer, error){}
	for a := range st.sites {
		a := a
		want["exit-api "+addrPort(a, s.apiPort)] = func() (io.Closer, error) { return s.listenAPI(addrPort(a, s.apiPort)) }
		want["exit-relay "+addrPort(a, s.relayPort)] = func() (io.Closer, error) { return s.listenRelay(addrPort(a, s.relayPort)) }
	}
	s.listeners.set(want)
}

// countryOK fails the exit closed once a trace or an edge check places the
// node's IP outside the expected country.
func (s *ExitServer) countryOK(e *egress) (bool, string) {
	country, _ := s.edges.summary(e.exit)
	ip, traced, _ := s.probes.probe(e).snapshot()
	if country == "" {
		country = traced
	}
	if country != "" && e.country != "" && country != e.country {
		if ip == "" {
			ip = e.public
		}
		return false, fmt.Sprintf("egress %s geolocates to %s, expected %s", ip, country, e.country)
	}
	return true, ""
}

// allowed reports whether a connection from remote to local is the site of
// the tunnel local belongs to.
func (s *ExitServer) allowed(local, remote netip.Addr) (string, bool) {
	st := s.state()
	site, ok := st.sites[local]
	if !ok || st.peer[local] != remote {
		return "", false
	}
	return site, st.egress != nil
}

func (s *ExitServer) listenAPI(addr string) (io.Closer, error) {
	ln, err := net.Listen("tcp4", addr)
	if err != nil {
		return nil, err
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/resolve", s.resolveHandler)
	mux.HandleFunc("GET /v1/exit", s.exitHandler)
	srv := &http.Server{
		Handler:           s.guard(mux),
		ReadHeaderTimeout: 5 * time.Second,
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			return context.WithValue(ctx, connAddrsKey{}, [2]netip.Addr{netAddr(c.LocalAddr()), netAddr(c.RemoteAddr())})
		},
	}
	go func() { _ = srv.Serve(ln) }()
	return closerFunc(srv.Close), nil
}

type connAddrsKey struct{}

func (s *ExitServer) guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		addrs, _ := r.Context().Value(connAddrsKey{}).([2]netip.Addr)
		if _, ok := s.allowed(addrs[0], addrs[1]); !ok {
			s.refused.Add(1)
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *ExitServer) resolveHandler(w http.ResponseWriter, r *http.Request) {
	var req resolveRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil || req.Name == "" {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	resp := resolveResponse{Error: "no exit on this node"}
	if e := s.state().egress; e != nil {
		resp = resolveVia(r.Context(), e, s.edges, normalize(req.Name))
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func (s *ExitServer) exitHandler(w http.ResponseWriter, _ *http.Request) {
	out := exitState{Error: "no exit on this node"}
	if e := s.state().egress; e != nil {
		es := exitStatus(e.exit, e, s.probes, s.edges)
		up, msg := e.up()
		out = exitState{Up: up, Country: es.Country, Egress: es.Egress, Error: msg}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

func (s *ExitServer) listenRelay(addr string) (io.Closer, error) {
	ln, err := net.Listen("tcp4", addr)
	if err != nil {
		return nil, err
	}
	go acceptLoop(ln, s.handleRelay)
	return ln, nil
}

// handleRelay serves one relayed stream from a connector.
func (s *ExitServer) handleRelay(c net.Conn) {
	defer c.Close()
	site, ok := s.allowed(netAddr(c.LocalAddr()), netAddr(c.RemoteAddr()))
	if !ok {
		s.refused.Add(1)
		return
	}
	_ = c.SetDeadline(time.Now().Add(peekTimeout))
	req, err := ReadConnectRequest(c)
	if err != nil {
		return
	}
	refuse := func(msg string, exitDown bool) {
		_ = WriteConnectResponse(c, ConnectResponse{Error: msg, ExitDown: exitDown})
		s.log.Warn("exit relay refused", "site", site, "host", req.Host, "reason", msg)
	}
	e := s.state().egress
	if e == nil {
		refuse("no exit on this node", true)
		return
	}
	if err := checkConnect(req); err != nil {
		refuse(err.Error(), false)
		return
	}
	if slices.ContainsFunc(req.Addrs, nodeAddrs(e)) {
		refuse("upstream is this node", false)
		return
	}
	usage := s.usageFor(site)
	defer usage.active.Add(-1)
	if usage.active.Add(1) > maxSiteStreams {
		refuse("too many open streams", false)
		return
	}
	ctx, cancel := context.WithTimeout(s.ctx(), dialTimeout*2+probeTimeout)
	up, addr, err := dialOrdered(ctx, e, s.edges, normalize(req.Host), req.Addrs, req.Port)
	cancel()
	if err != nil {
		refuse(err.Error(), errors.Is(err, errExitDown))
		return
	}
	defer up.Close()
	usage.conns.Add(1)
	if err := WriteConnectResponse(c, ConnectResponse{OK: true, Addr: addr.String()}); err != nil {
		return
	}
	_ = c.SetDeadline(time.Time{})
	pipe(c, up, &usage.bytes)
}

// nodeAddrs returns a test for this node's own addresses: its public IP and
// those of its interfaces.
func nodeAddrs(e *egress) func(netip.Addr) bool {
	own := map[netip.Addr]bool{}
	if a, err := netip.ParseAddr(e.public); err == nil {
		own[a.Unmap()] = true
	}
	if ifs, err := net.InterfaceAddrs(); err == nil {
		for _, ia := range ifs {
			if n, ok := ia.(*net.IPNet); ok {
				if a, ok := netip.AddrFromSlice(n.IP); ok {
					own[a.Unmap()] = true
				}
			}
		}
	}
	return func(a netip.Addr) bool { return own[a.Unmap()] }
}

// Exits reports the node exit (node agent hook).
func (s *ExitServer) Exits() []nodeproto.ExitStatus {
	e := s.state().egress
	if e == nil {
		return nil
	}
	es := exitStatus(e.exit, e, s.probes, s.edges)
	return []nodeproto.ExitStatus{es}
}

// ExitStatusFile is the node's status file.
type ExitStatusFile struct {
	Updated   time.Time              `json:"updated"`
	Sites     []string               `json:"sites"`
	Listening []string               `json:"listening"`
	Exits     []nodeproto.ExitStatus `json:"exits"`
	Edges     []EdgeResult           `json:"edges"`
	Refused   int64                  `json:"refused"`
	// Usage is each site's use of the exit since this process started.
	Usage map[string]ExitUsage `json:"usage,omitempty"`
}

// ExitUsage is one site's relay use.
type ExitUsage struct {
	Conns  int64 `json:"conns"`
	Active int64 `json:"active"`
	Bytes  int64 `json:"bytes"`
}

// Snapshot returns the node exit's status.
func (s *ExitServer) Snapshot() ExitStatusFile {
	st := s.state()
	out := ExitStatusFile{Updated: time.Now().UTC(), Sites: []string{}, Listening: s.listeners.names(), Exits: s.Exits(), Edges: s.edges.snapshot(), Refused: s.refused.Load()}
	for _, t := range st.sites {
		out.Sites = append(out.Sites, t)
	}
	if out.Exits == nil {
		out.Exits = []nodeproto.ExitStatus{}
	}
	slices.Sort(out.Sites)
	s.usageMu.Lock()
	defer s.usageMu.Unlock()
	for site, u := range s.usage {
		if out.Usage == nil {
			out.Usage = map[string]ExitUsage{}
		}
		out.Usage[site] = ExitUsage{Conns: u.conns.Load(), Active: u.active.Load(), Bytes: u.bytes.Load()}
	}
	return out
}

// ReadExitStatus reads a status file written by a running ExitServer.
func ReadExitStatus(path string) (*ExitStatusFile, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var s ExitStatusFile
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &s, nil
}

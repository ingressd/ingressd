// SPDX-License-Identifier: Apache-2.0

package client

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/ingressd/ingressd/internal/connector/proto"
	"github.com/ingressd/ingressd/internal/version"
)

// Timings for transport selection and the edge list.
const (
	// DefaultUDPTimeout is how long to wait for a UDP handshake before
	// falling back to WebSocket.
	DefaultUDPTimeout = 15 * time.Second
	// DefaultUDPRetry is how often a connector on WebSocket retries UDP.
	DefaultUDPRetry = 10 * time.Minute
	// staleAfter: WireGuard rekeys every 2 minutes while keepalives flow, so
	// an older handshake means the path is dead.
	staleAfter     = 3*time.Minute + 30*time.Second
	reportInterval = 30 * time.Second
	wsMTU          = 1280
	// refreshInterval is how often the edge list is reconciled with the
	// sibling lists (also on any tunnel loss). Every edge is long-polled
	// continuously, so configs themselves are at most PollWait old.
	refreshInterval = 60 * time.Second
	// freshFor: an edge polled this recently vouches for its sibling list.
	freshFor = 2 * time.Minute
	// removeAfter: an edge no fresh edge lists any more is dropped once it
	// has not answered for this long itself.
	removeAfter = 3 * time.Minute
)

// Runner runs an enrolled connector until its context is cancelled.
type Runner struct {
	StatePath string
	// Mode overrides the enrolled mode when non-empty.
	Mode       string
	UDPTimeout time.Duration
	UDPRetry   time.Duration
	Log        *slog.Logger
	// NoDiscovery refuses LAN discovery requests (also set per state file).
	NoDiscovery bool

	upd *updater // self-update state, kept across link restarts (update.go)
	// sd runs Smart DNS, kept across link restarts (smartdns.go).
	sd *sdController
}

// errRestart asks Run to rebuild the link after a config change.
var errRestart = errors.New("tunnel config changed")

// Run keeps the connector up, rebuilding it when the edges change a setting
// shared by the whole link (subnets, transparent sources, MTU).
func (r *Runner) Run(ctx context.Context) error {
	if r.Log == nil {
		r.Log = slog.Default()
	}
	if r.sd == nil {
		r.sd = newSDController(ctx, r.StatePath, r.Log)
	}
	if err := SecureStateDir(r.StatePath); err != nil {
		// Not fatal: the upgrade helper refuses plans it cannot trust
		// either way, and a connector that stops here would only be
		// rolled back to a version that does not check at all.
		r.Log.Warn("could not make the state directory private", "dir", filepath.Dir(r.StatePath), "err", err)
	}
	for {
		err := r.runOnce(ctx)
		if errors.Is(err, errRestart) && ctx.Err() == nil {
			r.Log.Info("tunnel config changed; restarting link")
			continue
		}
		if ctx.Err() != nil {
			return nil
		}
		return err
	}
}

// session is one run of the link. It owns the WireGuard device and one
// edge runner (peer, transport, control channel, reports) per edge.
type session struct {
	r        *Runner
	log      *slog.Logger
	mode     string
	priv     wgtypes.Key
	link     link
	restart  context.CancelCauseFunc
	discover bool
	started  time.Time
	hostname string
	refresh  chan struct{}
	upd      *updater

	mu    sync.Mutex
	st    *State // guarded by mu
	edges map[wgtypes.Key]*edge
	// owner is the edge whose peer carries 0.0.0.0/0 for transparent L4
	// replies (TUN mode): WireGuard routes by destination, so only one
	// edge can take replies to arbitrary client addresses at a time.
	owner wgtypes.Key
	// gone marks edges that answered 410 (the site left that node);
	// restartEdge marks edges whose peer settings changed.
	gone        map[string]bool
	restartEdge map[string]bool

	mtuMu  sync.Mutex
	udpMTU int // probed path MTU over UDP (TUN mode), 0 = not yet

	// isolated is when the last tunnel went down, rescued the last time the
	// panel was asked for edges (rescue.go). Guarded by mu.
	isolated, rescued time.Time

	statusMu sync.Mutex // serialises status file writes
}

func (r *Runner) runOnce(ctx context.Context) error {
	st, err := LoadState(r.StatePath)
	if err != nil {
		return err
	}
	for i := range st.Edges {
		sanitizeConfig(&st.Edges[i].Config, r.Log)
	}
	s := &session{
		r: r, st: st, log: r.Log, mode: cmp.Or(r.Mode, st.Mode, ModeNetstack),
		edges: map[wgtypes.Key]*edge{}, gone: map[string]bool{}, restartEdge: map[string]bool{},
		refresh: make(chan struct{}, 1), started: time.Now().UTC(),
	}
	s.discover = !r.NoDiscovery && !st.NoDiscovery
	if r.upd == nil {
		r.upd = newUpdater(r.StatePath)
	}
	s.upd = r.upd
	if s.priv, err = wgtypes.ParseKey(st.PrivateKey); err != nil {
		return fmt.Errorf("state private key: %w", err)
	}
	ageID, created, err := ensureAgeIdentity(st)
	if err != nil {
		return fmt.Errorf("state age identity: %w", err)
	}
	if created {
		if err := st.Save(r.StatePath); err != nil {
			return err
		}
	}
	switch s.mode {
	case ModeTUN:
		s.link, err = openTUN(st, s.priv, s.log)
	case ModeNetstack:
		s.link, err = openNetstack(st, s.priv, s.log)
	default:
		err = fmt.Errorf("unknown mode %q (tun or netstack)", s.mode)
	}
	if err != nil {
		return err
	}
	defer s.link.Close()
	s.hostname, _ = os.Hostname()
	s.log.Info("connector starting", "tunnel", st.Tunnel(), "mode", s.mode, "link", s.link.Kind(), "edges", len(st.Edges))

	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	s.restart = cancel
	s.reconcile(ctx)
	if r.sd != nil {
		r.sd.attach(s, ageID)
		defer r.sd.detach(s)
	}
	s.manage(ctx)
	s.mu.Lock()
	edges := make([]*edge, 0, len(s.edges))
	for _, e := range s.edges {
		edges = append(edges, e)
	}
	s.mu.Unlock()
	for _, e := range edges {
		e.stop()
	}
	if err := context.Cause(ctx); errors.Is(err, errRestart) {
		return errRestart
	}
	return nil
}

// manage writes the status, moves the transparent route between edges and
// reconciles the edge list until ctx ends.
func (s *session) manage(ctx context.Context) {
	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()
	refresh := time.NewTicker(refreshInterval)
	defer refresh.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			s.updateOwner()
			s.applyMTU()
			s.rescueTick(ctx, time.Now())
			s.writeStatus()
			s.upd.tick(s.healthy())
		case <-refresh.C:
			s.reconcile(ctx)
		case <-s.refresh:
			s.reconcile(ctx)
		}
	}
}

// healthy reports whether some edge has a live tunnel and answered a
// poll recently (what a new version must reach before it is kept).
func (s *session) healthy() bool {
	s.mu.Lock()
	edges := make([]*edge, 0, len(s.edges))
	for _, e := range s.edges {
		edges = append(edges, e)
	}
	s.mu.Unlock()
	for _, e := range edges {
		if !e.tunnelUp() {
			continue
		}
		e.mu.Lock()
		ok := e.pollErr == "" && !e.lastPoll.IsZero() && time.Since(e.lastPoll) < freshFor
		e.mu.Unlock()
		if ok {
			return true
		}
	}
	return false
}

// triggerRefresh asks the manager to reconcile the edge list now.
func (s *session) triggerRefresh() {
	select {
	case s.refresh <- struct{}{}:
	default:
	}
}

// reconcile merges the sibling lists into the edge list (adding new edges,
// dropping ones no edge lists any more) and starts or stops edge runners
// to match.
func (s *session) reconcile(ctx context.Context) {
	s.mu.Lock()
	changed := mergeSiblings(s.st, s.gone, time.Now())
	if changed {
		if err := s.st.Save(s.r.StatePath); err != nil {
			s.log.Warn("save state", "err", err)
		}
	}
	want := map[wgtypes.Key]EdgeState{}
	var order []wgtypes.Key
	for _, es := range s.st.Edges {
		k, err := wgtypes.ParseKey(es.Config.EdgePublicKey)
		if err != nil {
			s.log.Warn("edge with an invalid public key ignored", "url", es.URL, "endpoint", es.Config.Endpoint)
			continue
		}
		want[k] = es
		order = append(order, k)
	}
	var stop []*edge
	for k, e := range s.edges {
		if _, ok := want[k]; !ok || s.restartEdge[k.String()] {
			stop = append(stop, e)
			delete(s.edges, k)
		}
	}
	s.restartEdge = map[string]bool{}
	s.mu.Unlock()

	for _, e := range stop {
		e.stop()
		if _, ok := want[e.key]; !ok {
			s.log.Info("edge removed", "edge", e.label())
		}
		_ = s.link.RemovePeer(e.key)
	}
	// Addresses: add every wanted one, remove the ones no edge uses.
	inUse := map[netip.Prefix]bool{}
	for _, k := range order {
		if p, ok := transitPrefix(want[k].Config.Address); ok {
			inUse[p] = true
			if err := s.link.AddAddress(p); err != nil {
				s.log.Warn("add transit address", "address", p, "err", err)
			}
		}
	}
	for _, e := range stop {
		if p, ok := transitPrefix(e.config().Config.Address); ok && !inUse[p] {
			_ = s.link.RemoveAddress(p)
		}
	}
	if changed {
		reapplyNFT(s.stateCopy(), s.link.MTU(), s.log)
	}
	for _, k := range order {
		s.mu.Lock()
		_, running := s.edges[k]
		s.mu.Unlock()
		if running || ctx.Err() != nil {
			continue
		}
		e := newEdge(s, k, want[k])
		s.mu.Lock()
		s.edges[k] = e
		s.mu.Unlock()
		s.log.Info("edge added", "edge", e.label(), "endpoint", want[k].Config.Endpoint, "address", want[k].Config.Address)
		e.start(ctx)
	}
}

// mergeSiblings updates st.Edges from the edges' sibling lists. It adds
// edges any edge lists, refreshes never-polled learned edges from those
// lists, and drops an edge when it answered 410 (gone), or when no edge
// polled within freshFor lists it and it has not answered for removeAfter.
// The last edge is never dropped. It reports whether st changed.
func mergeSiblings(st *State, gone map[string]bool, now time.Time) bool {
	isFresh := func(es EdgeState) bool { return !es.LastSeen.IsZero() && now.Sub(es.LastSeen) < freshFor }
	listed := map[string]proto.Sibling{}      // by any edge
	listedFresh := map[string]bool{}          // by a fresh edge
	parent := map[string]proto.TunnelConfig{} // config of the edge listing it
	anyFresh := false
	for _, es := range st.Edges {
		fresh := isFresh(es)
		anyFresh = anyFresh || fresh
		for _, sb := range es.Config.Siblings {
			if _, err := wgtypes.ParseKey(sb.EdgePublicKey); err != nil || sb.Endpoint == "" || !privateTransit(sb.Address) {
				continue
			}
			if _, ok := listed[sb.EdgePublicKey]; !ok || fresh {
				listed[sb.EdgePublicKey], parent[sb.EdgePublicKey] = sb, es.Config
			}
			if fresh {
				listedFresh[sb.EdgePublicKey] = true
			}
		}
	}
	changed := false
	var keep []EdgeState
	for _, es := range st.Edges {
		k := es.Config.EdgePublicKey
		drop := gone[k] ||
			(anyFresh && !listedFresh[k] && !isFresh(es) && (es.LastSeen.IsZero() || now.Sub(es.LastSeen) > removeAfter))
		if drop {
			changed = true
			continue
		}
		if sb, ok := listed[k]; ok && es.Learned && es.LastSeen.IsZero() {
			if nc := siblingConfig(parent[k], sb); peerChanged(es.Config, nc) {
				es.Config, es.Node, es.URL = nc, sb.Node, urlFromWS(sb.WSURL)
				changed = true
			}
		}
		keep = append(keep, es)
	}
	if len(keep) == 0 && len(st.Edges) > 0 {
		keep = append(keep, st.Edges[0])
	}
	st.Edges = keep
	var add []string
	for k := range listed {
		if st.Edge(k) == nil && !gone[k] {
			add = append(add, k)
		}
	}
	slices.Sort(add)
	for _, k := range add {
		sb := listed[k]
		st.Edges = append(st.Edges, EdgeState{
			URL: urlFromWS(sb.WSURL), Node: sb.Node, Learned: true, Config: siblingConfig(parent[k], sb),
		})
		changed = true
	}
	for k := range gone {
		delete(gone, k)
	}
	return changed
}

// siblingConfig is the tunnel config for an edge known only from a sibling
// list: its own link settings plus the listing edge's shared settings. The
// empty revision makes the first poll of that edge return its full config.
func siblingConfig(parent proto.TunnelConfig, sb proto.Sibling) proto.TunnelConfig {
	return proto.TunnelConfig{
		Tunnel:        parent.Tunnel,
		EdgePublicKey: sb.EdgePublicKey,
		Endpoint:      sb.Endpoint,
		Address:       sb.Address,
		EdgeAddress:   sb.EdgeAddress,
		Subnets:       parent.Subnets,
		Keepalive:     parent.Keepalive,
		MTU:           parent.MTU,
		FallbackWS:    sb.WSURL != "",
		WSURL:         sb.WSURL,
		Transparent:   parent.Transparent,
		Targets:       parent.Targets,
	}
}

// urlFromWS turns a sibling's wss:// URL into the HTTPS base URL of its
// public control channel.
func urlFromWS(ws string) string {
	u, err := url.Parse(ws)
	if err != nil || u.Host == "" {
		return ""
	}
	return "https://" + u.Host
}

// peerChanged reports whether a config change affects an edge's peer
// (endpoint, keys, addresses, WebSocket fallback).
func peerChanged(a, b proto.TunnelConfig) bool {
	return a.EdgePublicKey != b.EdgePublicKey || a.Endpoint != b.Endpoint || a.Address != b.Address ||
		a.EdgeAddress != b.EdgeAddress || a.WSURL != b.WSURL || a.FallbackWS != b.FallbackWS || a.Keepalive != b.Keepalive
}

// sharedSettings are the settings of the whole link; a change rebuilds it.
func sharedSettings(st *State) string {
	b, _ := json.Marshal([]any{st.Tunnel(), st.Subnets(), st.Transparent(), st.MTU()})
	return string(b)
}

// applyEdgeConfig stores a polled config for an edge. A change to the
// shared settings restarts the link, a change to the edge's peer restarts
// that edge, and new siblings are picked up at once. A config that could
// not run is refused and never saved.
func (s *session) applyEdgeConfig(e *edge, tc proto.TunnelConfig) error {
	sanitizeConfig(&tc, s.log)
	s.mu.Lock()
	es := s.st.Edge(e.key.String())
	if es == nil {
		s.mu.Unlock()
		return nil
	}
	if err := checkConfig(tc, es.Config); err != nil {
		s.mu.Unlock()
		return fmt.Errorf("config refused: %w", err)
	}
	before := sharedSettings(s.st)
	old := es.Config
	es.Config, es.LastSeen = tc, time.Now().UTC()
	if tc.Node != "" {
		es.Node = tc.Node
	}
	after := sharedSettings(s.st)
	if err := s.st.Save(s.r.StatePath); err != nil {
		s.log.Warn("save state", "err", err)
	}
	cp := *es
	if peerChanged(old, tc) {
		s.restartEdge[e.key.String()] = true
	}
	s.mu.Unlock()
	e.setConfig(cp)
	if before != after {
		s.log.Info("shared tunnel settings changed", "edge", e.label(), "revision", tc.Revision)
		s.restart(errRestart)
		return nil
	}
	if s.r.sd != nil && !bytes.Equal(old.SmartDNS, tc.SmartDNS) {
		go s.r.sd.update()
	}
	if old.Revision != tc.Revision {
		s.log.Info("tunnel config updated", "edge", e.label(), "revision", tc.Revision, "siblings", len(tc.Siblings))
	}
	s.triggerRefresh()
	return nil
}

// markSeen records a successful poll without a config change.
func (s *session) markSeen(e *edge) {
	s.mu.Lock()
	if es := s.st.Edge(e.key.String()); es != nil {
		es.LastSeen = time.Now().UTC()
	}
	s.mu.Unlock()
}

// markGone drops an edge that no longer has this tunnel.
func (s *session) markGone(e *edge) {
	s.mu.Lock()
	s.gone[e.key.String()] = true
	s.mu.Unlock()
	s.triggerRefresh()
}

func (s *session) stateCopy() *State {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := *s.st
	cp.Edges = slices.Clone(s.st.Edges)
	return &cp
}

// transparent reports whether replies from transparent L4 sources must be
// routed into the tunnel (TUN mode only).
func (s *session) transparent() bool {
	if s.mode != ModeTUN {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.st.Transparent()) > 0
}

// allowedIPs is an edge peer's AllowedIPs: its /30, plus 0.0.0.0/0 for the
// owner of transparent replies.
func (s *session) allowedIPs(e *edge) []netip.Prefix {
	var out []netip.Prefix
	if p, ok := transitPrefix(e.config().Config.Address); ok {
		out = append(out, p.Masked())
	}
	if s.transparent() {
		s.mu.Lock()
		owner := s.owner
		s.mu.Unlock()
		if owner == e.key {
			out = append(out, netip.MustParsePrefix("0.0.0.0/0"))
		}
	}
	return out
}

// updateOwner gives 0.0.0.0/0 to the best edge (priority, then RTT) that
// is up, keeping the current owner while it stays up: moving the route
// breaks every transparent flow in progress.
func (s *session) updateOwner() {
	if !s.transparent() {
		return
	}
	s.mu.Lock()
	cur := s.edges[s.owner]
	s.mu.Unlock()
	if cur != nil && cur.tunnelUp() {
		return
	}
	order := s.rankedEdges()
	for _, e := range order {
		if e.tunnelUp() {
			s.mu.Lock()
			s.owner = e.key
			s.mu.Unlock()
			s.log.Info("transparent replies now leave via edge", "edge", e.label())
			if cur != nil {
				_ = cur.setPeerIPs()
			}
			_ = e.setPeerIPs()
			return
		}
	}
}

// applyMTU sets the device MTU to the smallest any connected edge needs:
// 1280 while one is on WebSocket, else the probed UDP path MTU.
func (s *session) applyMTU() {
	s.mu.Lock()
	want := 0
	for _, e := range s.edges {
		if m := e.wantMTU(); m > 0 && (want == 0 || m < want) {
			want = m
		}
	}
	st := s.st
	s.mu.Unlock()
	if want == 0 {
		return
	}
	s.mtuMu.Lock()
	defer s.mtuMu.Unlock()
	if s.link.MTU() != want {
		if err := s.link.SetMTU(want); err == nil {
			s.mu.Lock()
			cp := *st
			s.mu.Unlock()
			reapplyNFT(&cp, s.link.MTU(), s.log)
		}
	}
}

// probeUDPMTU probes the path MTU once per session (TUN mode).
func (s *session) probeUDPMTU(edgeAddr string) int {
	s.mtuMu.Lock()
	defer s.mtuMu.Unlock()
	if s.udpMTU == 0 {
		mtu := s.link.MTU()
		if a, err := netip.ParseAddr(edgeAddr); err == nil && s.mode == ModeTUN {
			mtu = probeMTU(s.link, a, s.log)
		}
		s.udpMTU = mtu
	}
	return s.udpMTU
}

func (s *session) stats() map[wgtypes.Key]peerStats {
	ps, err := s.link.Stats()
	if err != nil {
		return nil
	}
	return ps
}

// snapshot builds the status: every edge, and a summary of the best one.
func (s *session) snapshot() Status {
	ps := s.stats()
	s.mu.Lock()
	var edges []*edge
	for _, es := range s.st.Edges {
		if k, err := wgtypes.ParseKey(es.Config.EdgePublicKey); err == nil && s.edges[k] != nil {
			edges = append(edges, s.edges[k])
		}
	}
	tunnel := s.st.Tunnel()
	info := siblingInfo(s.st)
	s.mu.Unlock()
	now := time.Now().UTC()
	st := Status{
		Health: proto.Health{Time: now, Mode: s.mode, Version: version.String(), Hostname: s.hostname, MTU: s.link.MTU(), Discovery: s.discover,
			OS: runtime.GOOS, Arch: runtime.GOARCH, Install: s.upd.install, Update: s.upd.snapshot()},
		Tunnel:    tunnel,
		Started:   s.started,
		Interface: s.link.Kind(),
	}
	var best *EdgeStatus
	pollOK := false
	for _, e := range edges {
		es := e.status(ps[e.key])
		es.Priority, es.PoP = info[es.EdgePublicKey].Priority, info[es.EdgePublicKey].PoP
		st.Edges = append(st.Edges, es)
		if es.LastPoll.After(st.LastPoll) {
			st.LastPoll = es.LastPoll
		}
		if es.PollError == "" && !es.LastPoll.IsZero() && now.Sub(es.LastPoll) < freshFor {
			pollOK = true
		}
	}
	for i := range st.Edges {
		if !st.Edges[i].Up(now) {
			continue
		}
		if best == nil || compareRank(statusRank(st.Edges[i]), statusRank(*best)) < 0 {
			best = &st.Edges[i]
		}
	}
	if best == nil && len(st.Edges) > 0 {
		best = &st.Edges[0]
	}
	if best != nil {
		st.Transport, st.Endpoint = best.Transport, best.Endpoint
		st.LastHandshake, st.RxBytes, st.TxBytes = best.LastHandshake, best.RxBytes, best.TxBytes
	}
	if !pollOK {
		for _, es := range st.Edges {
			if es.PollError != "" {
				st.PollError = es.PollError
				break
			}
		}
	}
	return st
}

func (s *session) writeStatus() {
	s.statusMu.Lock()
	defer s.statusMu.Unlock()
	st := s.snapshot()
	if err := writeJSONFile(StatusPath(s.r.StatePath), st); err != nil {
		s.log.Debug("write status", "err", err)
	}
}

func sleep(ctx context.Context, d time.Duration) {
	select {
	case <-ctx.Done():
	case <-time.After(d):
	}
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// testReachability TCP-dials each target from this host.
func testReachability(ctx context.Context, targets []string) []proto.Reach {
	out := make([]proto.Reach, len(targets))
	var wg sync.WaitGroup
	for i, t := range targets {
		wg.Add(1)
		go func() {
			defer wg.Done()
			start := time.Now()
			d := net.Dialer{Timeout: 3 * time.Second}
			c, err := d.DialContext(ctx, "tcp", t)
			out[i] = proto.Reach{Target: t, OK: err == nil}
			if err != nil {
				out[i].Error = "unreachable"
				return
			}
			out[i].Latency = time.Since(start)
			c.Close()
		}()
	}
	wg.Wait()
	return out
}

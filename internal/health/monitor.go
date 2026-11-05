// SPDX-License-Identifier: Apache-2.0

// Package health owns origin health for load-balanced pools (docs/DESIGN.md
// §6.3): active HTTP/TCP checks with flap protection, tunnel awareness,
// priority-tier failover with failback hold, and runtime overrides. It is
// the single source of truth for the UI, alerts and the edge: every change
// is pushed to Caddy's edge_state app, which the edge_tiered selection
// policy reads.
package health

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"maps"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sync"
	"time"

	"github.com/ingressd/ingressd/internal/render"
	"github.com/ingressd/ingressd/internal/tunnel"
	"github.com/ingressd/ingressd/pkg/config"
)

// Options configure a Monitor. Only StateDir and Push are required.
type Options struct {
	// StateDir holds pool-overrides.json, pool-health.json and the sticky key.
	StateDir string
	// Push sends state to the edge (Pusher.Push).
	Push func(context.Context, EdgeState) error
	// Tunnels reads tunnel status; default tunnel.ReadStatus.
	Tunnels func(*config.Config) ([]tunnel.Status, error)
	// Probe runs one check; default Probe.
	Probe func(context.Context, *config.HealthCheck, Target) (time.Duration, error)
	Log   *slog.Logger
	Now   func() time.Time
	// Tick is how often overrides are re-read and timers (failback hold,
	// override expiry) evaluated. Default 500ms.
	Tick time.Duration
	// TunnelPoll is how often tunnel status is read. Default 2s.
	TunnelPoll time.Duration
	// Resync re-pushes unchanged state this often, so a restarted Caddy
	// gets it back. Default 5s.
	Resync time.Duration
	// TunnelTimeout is the handshake age after which a tunnel is down.
	// Default tunnel.HandshakeTimeout.
	TunnelTimeout time.Duration
}

// Monitor runs health checks and pushes pool state to the edge.
type Monitor struct {
	opts Options

	mu         sync.Mutex
	cfg        *config.Config
	pendingCfg *config.Config
	cfgCh      chan struct{}
	pools      map[string]*poolRT
	tunnelDown map[string]string // tunnel → reason; absent = up
	tunnelErr  string
	overrides  *Overrides
	ovStamp    string
	stickyKey  []byte
	lastPush   []byte
	lastPushAt time.Time
	pushErr    string
	saved      []byte
	lastSave   time.Time
	events     []Event
	sinks      []Sink
	evCh       chan Event
	results    chan result
	gen        int
	stopProbes context.CancelFunc
}

type poolRT struct {
	cfg     config.Pool
	origins []*originRT
	// tier is the active tier (0 until known).
	tier         int
	best         int
	allDown      bool
	pendingSince *time.Time
	// failbackUsed is the manual failback request already acted on.
	failbackUsed time.Time
}

type originRT struct {
	o      config.Origin
	target Target
	hc     *config.HealthCheck // nil: no active check
	hist   *ring

	// Active check state, with flap protection.
	known      bool
	healthy    bool
	okStreak   int
	failStreak int
	lastErr    string
	downReason string
	lastCheck  time.Time
	latency    time.Duration

	// Effective state as last evaluated (and reported in events).
	state     string
	effective bool
	reason    string
	since     time.Time
	reported  bool
}

type result struct {
	gen     int
	pool    string
	origin  string
	at      time.Time
	latency time.Duration
	err     error
}

// New creates a monitor. Call Run, then SetConfig after every apply.
func New(opts Options) *Monitor {
	if opts.Tunnels == nil {
		opts.Tunnels = tunnel.ReadStatus
	}
	if opts.Probe == nil {
		opts.Probe = Probe
	}
	if opts.Log == nil {
		opts.Log = slog.Default()
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	opts.Tick = cmp.Or(opts.Tick, 500*time.Millisecond)
	opts.TunnelPoll = cmp.Or(opts.TunnelPoll, 2*time.Second)
	opts.Resync = cmp.Or(opts.Resync, 5*time.Second)
	opts.TunnelTimeout = cmp.Or(opts.TunnelTimeout, tunnel.HandshakeTimeout)
	return &Monitor{
		opts:       opts,
		cfgCh:      make(chan struct{}, 1),
		pools:      map[string]*poolRT{},
		tunnelDown: map[string]string{},
		overrides:  &Overrides{},
		evCh:       make(chan Event, 1024),
		results:    make(chan result, 256),
	}
}

// SetConfig replaces the config (after a successful apply). It does not block.
func (m *Monitor) SetConfig(cfg *config.Config) {
	m.mu.Lock()
	m.pendingCfg = cfg
	m.mu.Unlock()
	select {
	case m.cfgCh <- struct{}{}:
	default:
	}
}

// Subscribe adds an event sink (alerts, UI live updates).
func (m *Monitor) Subscribe(s Sink) {
	m.mu.Lock()
	m.sinks = append(m.sinks, s)
	m.mu.Unlock()
}

// Run checks origins and pushes state until ctx is cancelled.
func (m *Monitor) Run(ctx context.Context) {
	if k, err := LoadStickyKey(m.opts.StateDir); err != nil {
		m.opts.Log.Warn("sticky key unavailable; the edge uses a per-process key", "err", err)
	} else {
		m.stickyKey = k
	}
	if st, err := LoadStatus(m.opts.StateDir); err == nil {
		m.events = st.Events
	}
	go m.dispatch(ctx)

	tick := time.NewTicker(m.opts.Tick)
	defer tick.Stop()
	tunnels := time.NewTicker(m.opts.TunnelPoll)
	defer tunnels.Stop()
	for {
		select {
		case <-ctx.Done():
			m.mu.Lock()
			if m.stopProbes != nil {
				m.stopProbes()
			}
			m.saveStatus(true)
			m.mu.Unlock()
			return
		case <-m.cfgCh:
			m.mu.Lock()
			cfg := m.pendingCfg
			m.applyConfig(ctx, cfg)
			m.pollOverrides()
			m.pollTunnels()
			m.mu.Unlock()
		case r := <-m.results:
			m.mu.Lock()
			m.onResult(r)
		drain: // batch results that arrived together
			for {
				select {
				case r := <-m.results:
					m.onResult(r)
				default:
					break drain
				}
			}
			m.mu.Unlock()
		case <-tick.C:
			m.mu.Lock()
			m.pollOverrides()
			m.mu.Unlock()
		case <-tunnels.C:
			m.mu.Lock()
			m.pollTunnels()
			m.mu.Unlock()
		}
		m.mu.Lock()
		m.evaluate()
		m.push(ctx)
		m.saveStatus(false)
		m.mu.Unlock()
	}
}

// applyConfig rebuilds pools, keeping state for unchanged origins, and
// restarts the probes.
func (m *Monitor) applyConfig(ctx context.Context, cfg *config.Config) {
	if cfg == nil {
		return
	}
	if m.stopProbes != nil {
		m.stopProbes()
	}
	m.gen++
	m.cfg = cfg
	pctx, cancel := context.WithCancel(ctx)
	m.stopProbes = cancel

	old := m.pools
	m.pools = map[string]*poolRT{}
	for _, name := range slices.Sorted(maps.Keys(cfg.Pools)) {
		pc := cfg.Pools[name]
		p := &poolRT{cfg: pc}
		if op := old[name]; op != nil {
			p.tier, p.allDown, p.pendingSince, p.failbackUsed = op.tier, op.allDown, op.pendingSince, op.failbackUsed
		}
		for _, o := range pc.Origins {
			if o.State == config.OriginDisabled {
				continue // not rendered, never selected
			}
			dial, scheme, err := render.DialAddress(cfg, o)
			if err != nil {
				m.opts.Log.Error("health: bad origin address", "pool", name, "origin", o.Name, "err", err)
				continue
			}
			host := o.Address
			if u, err := url.Parse(o.Address); err == nil {
				host = u.Host
			}
			rt := &originRT{o: o, target: Target{Dial: dial, Scheme: scheme, Host: host}, hc: pc.Health}
			if prev := findOrigin(old[name], o.Name); prev != nil && prev.o.Address == o.Address &&
				prev.o.Tunnel == o.Tunnel && reflect.DeepEqual(prev.hc, pc.Health) {
				prev.o, prev.target = o, rt.target
				rt = prev
			} else if pc.Health != nil {
				rt.hist = newRing(time.Duration(pc.Health.Interval))
			}
			p.origins = append(p.origins, rt)
			if rt.hc != nil {
				go m.probeLoop(pctx, m.gen, name, rt.o.Name, rt.hc, rt.target)
			}
		}
		m.pools[name] = p
	}
	for t := range m.tunnelDown {
		if _, ok := cfg.Tunnels[t]; !ok {
			delete(m.tunnelDown, t)
		}
	}
}

func findOrigin(p *poolRT, name string) *originRT {
	if p == nil {
		return nil
	}
	for _, o := range p.origins {
		if o.o.Name == name {
			return o
		}
	}
	return nil
}

func (m *Monitor) probeLoop(ctx context.Context, gen int, pool, origin string, hc *config.HealthCheck, t Target) {
	tick := time.NewTicker(time.Duration(hc.Interval))
	defer tick.Stop()
	for {
		lat, err := m.opts.Probe(ctx, hc, t)
		if ctx.Err() != nil {
			return
		}
		select {
		case m.results <- result{gen: gen, pool: pool, origin: origin, at: m.opts.Now(), latency: lat, err: err}:
		case <-ctx.Done():
			return
		}
		select {
		case <-tick.C:
		case <-ctx.Done():
			return
		}
	}
}

// onResult applies one check result with flap protection.
func (m *Monitor) onResult(r result) {
	if r.gen != m.gen {
		return
	}
	o := findOrigin(m.pools[r.pool], r.origin)
	if o == nil || o.hc == nil {
		return
	}
	ok := r.err == nil
	o.lastCheck, o.latency = r.at, r.latency
	if o.hist != nil {
		o.hist.add(Sample{Time: r.at, OK: ok, LatencyMS: float64(r.latency.Microseconds()) / 1000})
	}
	if ok {
		o.lastErr = ""
		o.okStreak++
		o.failStreak = 0
	} else {
		o.lastErr = r.err.Error()
		o.failStreak++
		o.okStreak = 0
	}
	switch {
	case !o.known:
		// The first result decides, so startup does not wait for N checks.
		o.known, o.healthy = true, ok
		if !ok {
			o.downReason = "check failed: " + o.lastErr
		}
	case ok && !o.healthy && o.okStreak >= o.hc.HealthyAfter:
		o.healthy = true
	case !ok && o.healthy && o.failStreak >= o.hc.UnhealthyAfter:
		o.healthy = false
		o.downReason = fmt.Sprintf("%d failed checks: %s", o.failStreak, o.lastErr)
	}
}

// pollOverrides re-reads the overrides file when it changes.
func (m *Monitor) pollOverrides() {
	path := filepath.Join(m.opts.StateDir, OverridesFile)
	stamp := ""
	if fi, err := os.Stat(path); err == nil {
		stamp = fmt.Sprint(fi.ModTime().UnixNano(), fi.Size())
	}
	if stamp == m.ovStamp {
		return
	}
	ov, err := LoadOverrides(m.opts.StateDir)
	if err != nil {
		m.opts.Log.Error("health: reading overrides", "err", err)
		return
	}
	m.ovStamp, m.overrides = stamp, ov
}

func (m *Monitor) pollTunnels() {
	if m.cfg == nil || len(m.cfg.Tunnels) == 0 {
		return
	}
	sts, err := m.opts.Tunnels(m.cfg)
	if err != nil {
		if err.Error() != m.tunnelErr {
			m.opts.Log.Warn("health: reading tunnel status", "err", err)
		}
		m.tunnelErr = err.Error()
		return
	}
	m.tunnelErr = ""
	now := m.opts.Now()
	for _, s := range sts {
		reason := ""
		switch {
		case !s.Up:
			reason = "interface missing"
		case s.LastHandshake.IsZero():
			reason = "no handshake yet"
		case now.Sub(s.LastHandshake) >= m.opts.TunnelTimeout:
			reason = fmt.Sprintf("last handshake %s ago", now.Sub(s.LastHandshake).Round(time.Second))
		}
		prev, wasDown := m.tunnelDown[s.Tunnel]
		switch {
		case reason != "" && !wasDown:
			m.tunnelDown[s.Tunnel] = reason
			m.emit(Event{Type: EventTunnelDown, Tunnel: s.Tunnel, Reason: reason})
		case reason != "":
			if prev != reason && s.Up && !s.LastHandshake.IsZero() {
				m.tunnelDown[s.Tunnel] = reason
			}
		case wasDown:
			delete(m.tunnelDown, s.Tunnel)
			m.emit(Event{Type: EventTunnelUp, Tunnel: s.Tunnel})
		}
	}
}

// evaluate derives effective origin health and each pool's active tier,
// emitting events for changes.
func (m *Monitor) evaluate() {
	now := m.opts.Now()
	for _, name := range slices.Sorted(maps.Keys(m.pools)) {
		p := m.pools[name]
		p.best = 0
		for _, o := range p.origins {
			o.state = o.o.State
			if ov, ok := m.overrides.OriginState(name, o.o.Name, now); ok {
				o.state = ov.State
			}
			healthy, reason := m.originHealth(o)
			if !o.reported || healthy != o.effective {
				if o.reported {
					t := EventOriginDown
					if healthy {
						t = EventOriginUp
					}
					m.emit(Event{Type: t, Pool: name, Origin: o.o.Name, Tunnel: o.o.Tunnel, Reason: reason})
				}
				o.since = now
			}
			o.reported, o.effective, o.reason = true, healthy, reason
			if healthy && o.state == config.OriginActive && (p.best == 0 || o.o.Priority < p.best) {
				p.best = o.o.Priority
			}
		}

		if p.best == 0 {
			if !p.allDown && len(p.origins) > 0 {
				p.allDown = true
				m.emit(Event{Type: EventPoolAllDown, Pool: name, Reason: "no healthy active origin in any tier"})
			}
			p.pendingSince = nil
			continue
		}
		if p.allDown {
			p.allDown = false
			m.emit(Event{Type: EventPoolRecovered, Pool: name, ToTier: p.best})
		}
		switch {
		case p.tier == 0:
			p.tier = p.best
		case p.best > p.tier:
			m.emit(Event{Type: EventPoolFailover, Pool: name, FromTier: p.tier, ToTier: p.best,
				Reason: fmt.Sprintf("no healthy active origin in tier %d", p.tier)})
			p.tier, p.pendingSince = p.best, nil
		case p.best < p.tier:
			if p.pendingSince == nil {
				t := now
				p.pendingSince = &t
			}
			reason := ""
			if po := m.overrides.Pools[name]; po != nil && po.FailbackAt != nil &&
				!po.FailbackAt.Before(*p.pendingSince) && !po.FailbackAt.Equal(p.failbackUsed) {
				reason = "manual failback"
				p.failbackUsed = *po.FailbackAt
			} else if p.cfg.Failback != config.FailbackManual && now.Sub(*p.pendingSince) >= time.Duration(p.cfg.FailbackHold) {
				reason = fmt.Sprintf("tier %d healthy for %s", p.best, time.Duration(p.cfg.FailbackHold))
			}
			if reason != "" {
				m.emit(Event{Type: EventPoolFailback, Pool: name, FromTier: p.tier, ToTier: p.best, Reason: reason})
				p.tier, p.pendingSince = p.best, nil
			}
		default:
			p.pendingSince = nil
		}
	}
}

func (m *Monitor) originHealth(o *originRT) (bool, string) {
	if r, down := m.tunnelDown[o.o.Tunnel]; down && o.o.Tunnel != "" {
		return false, fmt.Sprintf("tunnel %s down: %s", o.o.Tunnel, r)
	}
	if o.hc == nil || !o.known || o.healthy {
		return true, ""
	}
	return false, o.downReason
}

// edgeState builds what the edge needs from the evaluated state.
func (m *Monitor) edgeState() EdgeState {
	now := m.opts.Now()
	st := EdgeState{Pools: map[string]EdgePool{}}
	for name, p := range m.pools {
		ep := EdgePool{Tier: p.tier, Origins: map[string]EdgeOrigin{}}
		for _, o := range p.origins {
			h := o.effective
			eo := EdgeOrigin{Healthy: &h, Reason: o.reason}
			if o.state != o.o.State {
				eo.State = o.state
			}
			ep.Origins[o.o.Name] = eo
		}
		if po := m.overrides.Pools[name]; po != nil && po.Force.Active(now) {
			f := po.Force
			ep.Override = &EdgeOverride{Tier: f.Tier, Origins: f.Origins, Until: f.Until, Reason: f.Reason}
		}
		st.Pools[name] = ep
	}
	for t := range m.tunnelDown {
		if st.Tunnels == nil {
			st.Tunnels = map[string]EdgeTunnel{}
		}
		st.Tunnels[t] = EdgeTunnel{Down: true}
	}
	return st
}

// push sends the edge state when it changed, or periodically.
func (m *Monitor) push(ctx context.Context) {
	if m.cfg == nil || m.opts.Push == nil {
		return
	}
	st := m.edgeState()
	b, _ := json.Marshal(st)
	now := m.opts.Now()
	if bytes.Equal(b, m.lastPush) && now.Sub(m.lastPushAt) < m.opts.Resync {
		return
	}
	st.StickyKey = m.stickyKey
	pctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if err := m.opts.Push(pctx, st); err != nil {
		if err.Error() != m.pushErr {
			m.opts.Log.Warn("health: pushing state to the edge", "err", err)
		}
		m.pushErr, m.lastPush = err.Error(), nil
		return
	}
	if m.pushErr != "" {
		m.opts.Log.Info("health: edge state push recovered")
	}
	m.pushErr, m.lastPush, m.lastPushAt = "", b, now
}

func (m *Monitor) emit(e Event) {
	if e.Time.IsZero() {
		e.Time = m.opts.Now()
	}
	m.events = append(m.events, e)
	if len(m.events) > maxEvents {
		m.events = slices.Clone(m.events[len(m.events)-maxEvents:])
	}
	m.opts.Log.Info("health event", "type", e.Type, "pool", e.Pool, "origin", e.Origin, "tunnel", e.Tunnel,
		"from_tier", e.FromTier, "to_tier", e.ToTier, "reason", e.Reason)
	select {
	case m.evCh <- e:
	default:
		m.opts.Log.Warn("health: event queue full; dropping event", "type", e.Type)
	}
}

func (m *Monitor) dispatch(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case e := <-m.evCh:
			m.mu.Lock()
			sinks := slices.Clone(m.sinks)
			m.mu.Unlock()
			for _, s := range sinks {
				s.HealthEvent(e)
			}
		}
	}
}

// Status returns the current view of every pool.
func (m *Monitor) Status() Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.status()
}

// History returns an origin's check results from the last 24h.
func (m *Monitor) History(pool, origin string) []Sample {
	m.mu.Lock()
	defer m.mu.Unlock()
	if o := findOrigin(m.pools[pool], origin); o != nil && o.hist != nil {
		return o.hist.since(m.opts.Now().Add(-HistoryWindow))
	}
	return nil
}

func (m *Monitor) status() Status {
	now := m.opts.Now()
	st := Status{Updated: now, Pools: map[string]PoolStatus{}, Tunnels: map[string]TunnelInfo{}, Events: slices.Clone(m.events)}
	if m.cfg != nil {
		for t := range m.cfg.Tunnels {
			r, down := m.tunnelDown[t]
			st.Tunnels[t] = TunnelInfo{Up: !down, Reason: r}
		}
	}
	for name, p := range m.pools {
		ps := PoolStatus{Steering: p.cfg.Steering, ActiveTier: p.tier, BestTier: p.best, AllDown: p.allDown,
			FailbackPending: p.pendingSince, FailbackManual: p.pendingSince != nil && p.cfg.Failback == config.FailbackManual}
		if p.allDown {
			ps.ActiveTier = 0
		}
		if po := m.overrides.Pools[name]; po != nil && po.Force.Active(now) {
			ps.Override = po.Force
		}
		for _, o := range p.origins {
			ost := OriginStatus{
				Name: o.o.Name, Tunnel: o.o.Tunnel, Address: o.o.Address, Dial: o.target.Dial,
				Priority: o.o.Priority, Weight: o.o.Weight, State: o.state, ConfigState: o.o.State,
				Checked: o.hc != nil, Healthy: o.effective, Reason: o.reason, Since: o.since,
				LastCheck: o.lastCheck, LastError: o.lastErr, LatencyMS: float64(o.latency.Microseconds()) / 1000,
			}
			if o.hist != nil {
				for _, s := range o.hist.since(now.Add(-HistoryWindow)) {
					ost.Checks24h++
					if !s.OK {
						ost.Failures24h++
					}
				}
			}
			ps.Origins = append(ps.Origins, ost)
		}
		st.Pools[name] = ps
	}
	return st
}

// saveStatus persists the status at most once a second (or when forced).
func (m *Monitor) saveStatus(force bool) {
	if m.opts.StateDir == "" || m.cfg == nil {
		return
	}
	now := m.opts.Now()
	if !force && now.Sub(m.lastSave) < time.Second {
		return
	}
	st := m.status()
	st.Updated = time.Time{}
	b, _ := json.Marshal(st)
	if bytes.Equal(b, m.saved) && !force && now.Sub(m.lastSave) < 30*time.Second {
		return
	}
	st.Updated = now
	if err := writeJSON(filepath.Join(m.opts.StateDir, StatusFile), st); err != nil {
		m.opts.Log.Warn("health: saving status", "err", err)
		return
	}
	m.saved, m.lastSave = b, now
}

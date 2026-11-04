// SPDX-License-Identifier: Apache-2.0

package health

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ingressd/ingressd/internal/tunnel"
	"github.com/ingressd/ingressd/pkg/config"
)

const poolConfig = `
version: 1
edge:
  public_ipv4: 203.0.113.10
  acme: { ca: internal }
tunnels:
  home:
    site: router
    listen_port: 51820
    transit: 10.100.1.0/24
    subnets: [192.168.0.0/24]
    virtual_prefix: 10.201.0.0/24
  cloud:
    site: router
    listen_port: 51821
    transit: 10.100.2.0/24
    subnets: [10.0.1.0/24]
pools:
  web:
    steering: weighted
    failback: FAILBACK
    failback_hold: 10s
    health: { interval: 1s, timeout: 500ms, unhealthy_after: 2, healthy_after: 2 }
    origins:
      - { name: a, tunnel: home, address: http://192.168.0.17:80, priority: 1 }
      - { name: b, tunnel: cloud, address: http://10.0.1.5:80, priority: 2 }
  plain:
    origins:
      - { name: x, tunnel: home, address: http://192.168.0.30:80 }
apps:
  web: { hosts: [web.example.com], pool: web }
  plain: { hosts: [plain.example.com], pool: plain }
`

type harness struct {
	t      *testing.T
	m      *Monitor
	now    time.Time
	events []Event
	pushes []EdgeState
	tuns   []tunnel.Status
}

func newHarness(t *testing.T, failback string) *harness {
	t.Helper()
	cfg, err := config.Parse([]byte(strings.Replace(poolConfig, "FAILBACK", failback, 1)))
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	h := &harness{t: t, now: time.Unix(1_700_000_000, 0)}
	h.m = New(Options{
		StateDir: t.TempDir(),
		Push:     func(_ context.Context, st EdgeState) error { h.pushes = append(h.pushes, st); return nil },
		Tunnels:  func(*config.Config) ([]tunnel.Status, error) { return h.tuns, nil },
		// Probes never report; tests feed results directly.
		Probe: func(ctx context.Context, _ *config.HealthCheck, _ Target) (time.Duration, error) {
			<-ctx.Done()
			return 0, ctx.Err()
		},
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Now: func() time.Time { return h.now },
	})
	h.m.Subscribe(SinkFunc(func(e Event) { h.events = append(h.events, e) }))
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	h.m.applyConfig(ctx, cfg)
	h.step()
	return h
}

// result feeds a check result and re-evaluates.
func (h *harness) result(origin string, ok bool) {
	var err error
	if !ok {
		err = errors.New("HTTP 503")
	}
	pool := "web"
	h.m.onResult(result{gen: h.m.gen, pool: pool, origin: origin, at: h.now, err: err})
	h.step()
}

func (h *harness) step() {
	h.m.evaluate()
	h.m.push(context.Background())
	// Deliver events synchronously.
	for {
		select {
		case e := <-h.m.evCh:
			h.events = append(h.events, e)
		default:
			return
		}
	}
}

func (h *harness) advance(d time.Duration) {
	h.now = h.now.Add(d)
	h.step()
}

func (h *harness) tier() int { return h.m.pools["web"].tier }

func (h *harness) healthy(origin string) bool {
	return *h.m.edgeState().Pools["web"].Origins[origin].Healthy
}

func (h *harness) lastEvent() Event {
	if len(h.events) == 0 {
		return Event{}
	}
	return h.events[len(h.events)-1]
}

func TestFlapProtection(t *testing.T) {
	h := newHarness(t, "auto")
	if !h.healthy("a") {
		t.Fatal("unknown origin should count as healthy")
	}
	h.result("a", true) // first result decides
	h.result("a", false)
	if !h.healthy("a") {
		t.Fatal("one failure marked a down (unhealthy_after: 2)")
	}
	h.result("a", false)
	if h.healthy("a") {
		t.Fatal("two failures did not mark a down")
	}
	if e := h.events[0]; e.Type != EventOriginDown || e.Origin != "a" || !strings.Contains(e.Reason, "2 failed checks: HTTP 503") {
		t.Fatalf("event = %+v", e)
	}
	h.result("a", true)
	if h.healthy("a") {
		t.Fatal("one success marked a up (healthy_after: 2)")
	}
	h.result("a", false)
	h.result("a", true)
	h.result("a", true)
	if !h.healthy("a") {
		t.Fatal("two successes did not mark a up")
	}
}

func TestFailoverAndFailbackHold(t *testing.T) {
	h := newHarness(t, "auto")
	if h.tier() != 1 {
		t.Fatalf("initial tier %d", h.tier())
	}
	h.result("a", false) // first result: down at once
	if h.tier() != 2 {
		t.Fatalf("tier after a down = %d", h.tier())
	}
	if e := h.lastEvent(); e.Type != EventPoolFailover || e.FromTier != 1 || e.ToTier != 2 {
		t.Fatalf("event = %+v", e)
	}
	if p := h.pushes[len(h.pushes)-1].Pools["web"]; p.Tier != 2 || *p.Origins["a"].Healthy {
		t.Fatalf("pushed %+v", p)
	}

	h.result("a", true)
	h.result("a", true) // a healthy again: failback pending
	if h.tier() != 2 || h.m.pools["web"].pendingSince == nil {
		t.Fatal("failed back without hold")
	}
	h.advance(5 * time.Second)
	if h.tier() != 2 {
		t.Fatal("failed back before failback_hold")
	}
	h.advance(6 * time.Second)
	if h.tier() != 1 {
		t.Fatal("did not fail back after failback_hold")
	}
	if e := h.lastEvent(); e.Type != EventPoolFailback || e.ToTier != 1 {
		t.Fatalf("event = %+v", e)
	}

	// Everything down, then recovery.
	h.result("a", false)
	h.result("a", false)
	h.m.onResult(result{gen: h.m.gen, pool: "web", origin: "b", at: h.now, err: errors.New("refused")})
	h.step()
	if !h.m.pools["web"].allDown || h.lastEvent().Type != EventPoolAllDown {
		t.Fatalf("all down not detected: %+v", h.lastEvent())
	}
}

func TestManualFailback(t *testing.T) {
	h := newHarness(t, "manual")
	h.result("a", false)
	h.result("a", true)
	h.result("a", true)
	h.advance(time.Hour)
	if h.tier() != 2 {
		t.Fatal("manual pool failed back on its own")
	}
	if st := h.m.status().Pools["web"]; !st.FailbackManual || st.BestTier != 1 {
		t.Fatalf("status = %+v", st)
	}
	now := h.now
	h.m.overrides.Pool("web").FailbackAt = &now
	h.step()
	if h.tier() != 1 || !strings.Contains(h.lastEvent().Reason, "manual") {
		t.Fatalf("manual failback: tier %d, event %+v", h.tier(), h.lastEvent())
	}
	// The old request does not skip the next hold.
	h.result("a", false)
	h.result("a", false)
	h.result("a", true)
	h.result("a", true)
	h.advance(time.Minute)
	if h.tier() != 2 {
		t.Fatal("stale failback request reused")
	}
}

func TestTunnelDown(t *testing.T) {
	h := newHarness(t, "auto")
	h.result("a", true)
	h.result("b", true)
	h.tuns = []tunnel.Status{
		{Tunnel: "home", Up: true, LastHandshake: h.now.Add(-200 * time.Second)},
		{Tunnel: "cloud", Up: true, LastHandshake: h.now.Add(-10 * time.Second)},
	}
	h.m.pollTunnels()
	h.step()
	if h.healthy("a") || !h.healthy("b") || h.tier() != 2 {
		t.Fatalf("tunnel down: a=%v b=%v tier=%d", h.healthy("a"), h.healthy("b"), h.tier())
	}
	if *h.m.edgeState().Pools["plain"].Origins["x"].Healthy {
		t.Fatal("unchecked origin on a down tunnel should be down")
	}
	var sawTunnel bool
	for _, e := range h.events {
		sawTunnel = sawTunnel || (e.Type == EventTunnelDown && e.Tunnel == "home" && strings.Contains(e.Reason, "last handshake"))
	}
	if !sawTunnel {
		t.Fatalf("no tunnel_down event: %+v", h.events)
	}
	if r := h.m.edgeState().Pools["web"].Origins["a"].Reason; !strings.Contains(r, "tunnel home down") {
		t.Fatalf("reason = %q", r)
	}
	h.tuns[0].LastHandshake = h.now
	h.m.pollTunnels()
	h.step()
	if !h.healthy("a") {
		t.Fatal("origin not back after tunnel recovery")
	}
}

func TestOverridesInEdgeState(t *testing.T) {
	h := newHarness(t, "auto")
	until := h.now.Add(time.Minute)
	ov := h.m.overrides
	ov.Pool("web").Origins = map[string]OriginOverride{"a": {State: config.OriginDraining, Until: &until}}
	ov.Pool("web").Force = &Force{Tier: 2, Until: &until}
	h.step()
	p := h.pushes[len(h.pushes)-1].Pools["web"]
	if p.Origins["a"].State != "draining" || p.Override == nil || p.Override.Tier != 2 {
		t.Fatalf("pushed %+v", p)
	}
	// Draining a's tier leaves tier 2 as the only tier taking new sessions.
	if h.tier() != 2 {
		t.Fatalf("tier with a drained = %d", h.tier())
	}
	h.advance(2 * time.Minute) // both expire
	p = h.pushes[len(h.pushes)-1].Pools["web"]
	if p.Origins["a"].State != "" || p.Override != nil {
		t.Fatalf("expired overrides still pushed: %+v", p)
	}
}

func TestPushOnlyOnChangeOrResync(t *testing.T) {
	h := newHarness(t, "auto")
	n := len(h.pushes)
	h.result("a", true)
	h.result("a", true)
	if len(h.pushes) != n {
		t.Fatalf("pushed unchanged state %d times", len(h.pushes)-n)
	}
	h.result("a", false)
	h.result("a", false)
	if len(h.pushes) != n+1 {
		t.Fatalf("pushes after change = %d", len(h.pushes)-n)
	}
	h.advance(6 * time.Second)
	if len(h.pushes) != n+2 {
		t.Fatal("no resync push")
	}
}

func TestOverridesPrune(t *testing.T) {
	cfg, _ := config.Parse([]byte(strings.Replace(poolConfig, "FAILBACK", "auto", 1)))
	now := time.Now()
	past := now.Add(-time.Second)
	ov := &Overrides{Pools: map[string]*PoolOverrides{
		"web":  {Origins: map[string]OriginOverride{"a": {State: "draining", Until: &past}, "zz": {State: "disabled"}, "b": {State: "draining"}}},
		"gone": {Force: &Force{Tier: 1}},
	}}
	ov.Prune(cfg, now)
	if _, ok := ov.Pools["gone"]; ok || len(ov.Pools["web"].Origins) != 1 {
		t.Fatalf("pruned = %+v", ov.Pools["web"])
	}
	dir := t.TempDir()
	if err := SaveOverrides(dir, ov); err != nil {
		t.Fatal(err)
	}
	got, err := LoadOverrides(dir)
	if err != nil || got.Pools["web"].Origins["b"].State != "draining" {
		t.Fatalf("round trip: %+v %v", got, err)
	}
}

// TestRunEndToEnd runs real HTTP probes against a test server and checks
// that a failure reaches the edge quickly.
func TestRunEndToEnd(t *testing.T) {
	var mu sync.Mutex
	status := 200
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.Host != "check.example.com" || r.URL.Path != "/healthz" {
			w.WriteHeader(400)
			return
		}
		w.WriteHeader(status)
		io.WriteString(w, "ready")
	}))
	defer srv.Close()
	addr := strings.TrimPrefix(srv.URL, "http://")

	cfg, err := config.Parse([]byte(`
version: 1
edge: { public_ipv4: 203.0.113.10, acme: { ca: internal } }
pools:
  web:
    health: { path: /healthz, host: check.example.com, interval: 100ms, timeout: 50ms, expect_body: "^ready$", unhealthy_after: 1, healthy_after: 1 }
    origins:
      - { name: a, address: "http://` + addr + `" }
apps:
  web: { hosts: [web.example.com], pool: web }
`))
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	pushed := make(chan EdgeState, 100)
	dir := t.TempDir()
	m := New(Options{
		StateDir: dir,
		Push: func(_ context.Context, st EdgeState) error {
			pushed <- st
			return nil
		},
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	ctx, cancel := context.WithCancel(context.Background())
	runDone := make(chan struct{})
	go func() { m.Run(ctx); close(runDone) }()
	// Stop the monitor before t.TempDir's cleanup removes its state files
	// (cleanups run last-registered first).
	t.Cleanup(func() { cancel(); <-runDone })
	m.SetConfig(cfg)

	wait := func(want bool) time.Time {
		t.Helper()
		deadline := time.After(3 * time.Second)
		for {
			select {
			case st := <-pushed:
				if len(st.StickyKey) != 32 {
					t.Fatal("sticky key not pushed")
				}
				if h := st.Pools["web"].Origins["a"].Healthy; h != nil && *h == want {
					return time.Now()
				}
			case <-deadline:
				t.Fatalf("no push with healthy=%v", want)
			}
		}
	}
	wait(true)
	time.Sleep(300 * time.Millisecond)
	if hist := m.History("web", "a"); len(hist) == 0 || !hist[0].OK {
		t.Fatalf("history = %+v", hist)
	}
	mu.Lock()
	status = 503
	mu.Unlock()
	changed := time.Now()
	if d := wait(false).Sub(changed); d > 500*time.Millisecond {
		t.Fatalf("failure took %s to reach the edge", d)
	}
	time.Sleep(1100 * time.Millisecond) // status file is written at most once a second
	st, err := LoadStatus(dir)
	if err != nil || st.Pools["web"].Origins[0].Healthy || !strings.Contains(st.Pools["web"].Origins[0].LastError, "HTTP 503") {
		t.Fatalf("persisted status = %+v, %v", st, err)
	}
}

func TestProbeTCPAndBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "status: degraded")
	}))
	defer srv.Close()
	addr := strings.TrimPrefix(srv.URL, "http://")
	hc := &config.HealthCheck{Type: config.HealthHTTP, Method: "GET", Path: "/", Timeout: config.Duration(time.Second), ExpectStatus: []int{200}, ExpectBody: "ok"}
	if _, err := Probe(context.Background(), hc, Target{Dial: addr, Scheme: "http", Host: addr}); err == nil || !strings.Contains(err.Error(), "body does not match") {
		t.Fatalf("body mismatch: %v", err)
	}
	tcp := &config.HealthCheck{Type: config.HealthTCP, Timeout: config.Duration(time.Second)}
	if _, err := Probe(context.Background(), tcp, Target{Dial: addr}); err != nil {
		t.Fatalf("tcp: %v", err)
	}
	srv.Close()
	if _, err := Probe(context.Background(), tcp, Target{Dial: addr}); err == nil {
		t.Fatal("tcp to closed port succeeded")
	}
}

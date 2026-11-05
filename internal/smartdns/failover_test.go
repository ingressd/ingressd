// SPDX-License-Identifier: Apache-2.0

package smartdns

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/ingressd/ingressd/pkg/config"
)

func failoverPlan() Plan {
	return Plan{
		Site:          "home",
		Upstream:      []string{"127.0.0.1:9"},
		FailbackAfter: 5 * time.Minute,
		Exits: map[string]PlanExit{
			"gb-a": {Node: "nod_a", Country: "GB"},
			"gb-b": {Node: "nod_b", Country: "GB"},
			"gb-c": {Node: "nod_c", Country: "GB"},
			"nl":   {Node: "nod_d", Country: "NL"},
		},
		Services: map[string]config.SmartDNSSiteService{
			"bbc": {Domains: []string{"bbc.example"}, Exits: []string{"gb-a", "gb-b", "gb-c"}},
		},
	}
}

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func newFailoverManager(t *testing.T) (*Manager, *fakeExits, *fakeClock) {
	t.Helper()
	m := New(Options{})
	clk := &fakeClock{t: time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)}
	m.now = clk.now
	fx := &fakeExits{
		up: true, exitOf: map[string]string{"nod_a": "gb-a", "nod_b": "gb-b", "nod_c": "gb-c", "nod_d": "nl"},
		downNodes: map[string]bool{}, brokenNodes: map[string]bool{}, downExits: map[string]bool{},
		exitAddrs: map[string][]netip.Addr{
			"gb-a": addrs("192.0.2.1"),
			"gb-b": addrs("198.51.100.1"),
			"gb-c": addrs("203.0.113.1"),
		},
	}
	m.remote = fx
	m.Reconfigure(failoverPlan())
	t.Cleanup(m.listeners.closeAll)
	return m, fx, clk
}

func bbcRoute(m *Manager) route {
	r, _ := m.state().match.match("bbc.example")
	return r
}

func activeOf(t *testing.T, m *Manager) string {
	t.Helper()
	exit, err := m.pick(m.state(), bbcRoute(m))
	if err != nil {
		return "down: " + err.Error()
	}
	return exit
}

func (f *fakeExits) resolvedAt() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := slices.Clone(f.resolved)
	f.resolved = nil
	return out
}

func TestFailoverOrderAndStickiness(t *testing.T) {
	m, fx, clk := newFailoverManager(t)
	if r := query(m, "www.bbc.example", dns.TypeA); r.Rcode != dns.RcodeSuccess {
		t.Fatalf("answer %v", r)
	}
	if got := fx.resolvedAt(); strings.Join(got, ",") != "gb-a" {
		t.Errorf("resolved at %v, want the first exit", got)
	}
	if e := m.recent.list(1)[0].Exit; e != "gb-a" {
		t.Errorf("recent exit %q", e)
	}

	// The first exit's node goes away: the next query fails over.
	fx.set(func() { fx.downNodes["nod_a"] = true })
	if r := query(m, "www.bbc.example", dns.TypeA); r.Rcode != dns.RcodeSuccess {
		t.Fatalf("after failover %v", r)
	}
	if got := fx.resolvedAt(); strings.Join(got, ",") != "gb-b" {
		t.Errorf("resolved at %v, want gb-b", got)
	}
	s := m.Services()
	if len(s) != 1 || s[0].Active != "gb-b" || !s[0].Failover || !strings.Contains(s[0].Message, "tunnel to exit node nod_a is down") ||
		strings.Join(s[0].Exits, ",") != "gb-a,gb-b,gb-c" {
		t.Errorf("status %+v", s)
	}

	// Back, but not for failback_after yet: stay on gb-b.
	fx.set(func() { delete(fx.downNodes, "nod_a") })
	if got := activeOf(t, m); got != "gb-b" {
		t.Fatalf("active %s right after gb-a came back", got)
	}
	clk.add(4 * time.Minute)
	if got := activeOf(t, m); got != "gb-b" {
		t.Fatalf("active %s after 4m", got)
	}
	if s := m.Services(); !strings.Contains(s[0].Message, "failing back in 1m0s") {
		t.Errorf("message %q", s[0].Message)
	}
	clk.add(time.Minute)
	if got := activeOf(t, m); got != "gb-a" {
		t.Fatalf("active %s after failback_after, want gb-a", got)
	}
	if s := m.Services(); s[0].Failover || s[0].Message != "" || !s[0].Since.Equal(clk.now()) {
		t.Errorf("status after failback %+v", s)
	}
}

func TestFailbackImmediateWithZero(t *testing.T) {
	m, fx, _ := newFailoverManager(t)
	m.state().plan.FailbackAfter = 0
	fx.set(func() { fx.downNodes["nod_a"] = true })
	if got := activeOf(t, m); got != "gb-b" {
		t.Fatalf("active %s", got)
	}
	fx.set(func() { delete(fx.downNodes, "nod_a") })
	if got := activeOf(t, m); got != "gb-a" {
		t.Fatalf("failback_after 0: active %s, want gb-a at once", got)
	}
}

func TestFlappingPrimaryDoesNotFailBackEarly(t *testing.T) {
	m, fx, clk := newFailoverManager(t)
	st := m.state()
	fx.set(func() { fx.downNodes["nod_a"] = true })
	m.refreshActive(st)
	// gb-a flaps: up for 4 minutes, down briefly, up again.
	for range 3 {
		fx.set(func() { delete(fx.downNodes, "nod_a") })
		m.refreshActive(st)
		clk.add(4 * time.Minute)
		m.refreshActive(st)
		if got := activeOf(t, m); got != "gb-b" {
			t.Fatalf("failed back to %s while gb-a was flapping", got)
		}
		fx.set(func() { fx.downNodes["nod_a"] = true })
		m.refreshActive(st)
		clk.add(2 * time.Second)
	}
	fx.set(func() { delete(fx.downNodes, "nod_a") })
	m.refreshActive(st)
	clk.add(4*time.Minute + 59*time.Second)
	if got := activeOf(t, m); got != "gb-b" {
		t.Fatalf("active %s before gb-a was stable for 5m", got)
	}
	clk.add(time.Second)
	if got := activeOf(t, m); got != "gb-a" {
		t.Fatalf("active %s after gb-a was stable for 5m", got)
	}
}

func TestAllExitsDownFailsClosed(t *testing.T) {
	m, fx, _ := newFailoverManager(t)
	query(m, "www.bbc.example", dns.TypeA) // cache an answer at gb-a
	fx.set(func() {
		fx.downNodes["nod_a"] = true
		fx.downNodes["nod_b"] = true
		fx.downNodes["nod_c"] = true
	})
	r := query(m, "www.bbc.example", dns.TypeA)
	if r.Rcode != dns.RcodeServerFailure || len(r.Answer) != 0 {
		t.Fatalf("every exit down: %v", r)
	}
	res := m.recent.list(1)[0].Result
	for _, want := range []string{"SERVFAIL", "gb-a: the tunnel to exit node nod_a", "gb-b: the tunnel to exit node nod_b", "gb-c: the tunnel to exit node nod_c"} {
		if !strings.Contains(res, want) {
			t.Errorf("result %q lacks %q", res, want)
		}
	}
	if s := m.Services(); s[0].Active != "" || s[0].Failover || !strings.Contains(s[0].Message, "gb-c:") {
		t.Errorf("status %+v", s)
	}
	// The first exit to come back is used at once (nothing is in use to
	// stick to).
	fx.set(func() { delete(fx.downNodes, "nod_c") })
	if got := activeOf(t, m); got != "gb-c" {
		t.Errorf("active %s", got)
	}
}

func TestResolveFailsOverWithinOneQuery(t *testing.T) {
	m, fx, _ := newFailoverManager(t)
	// gb-a's node is reachable but says its VPN is down.
	fx.set(func() { fx.downExits["gb-a"] = true })
	r := query(m, "www.bbc.example", dns.TypeA)
	if r.Rcode != dns.RcodeSuccess {
		t.Fatalf("answer %v", r)
	}
	if got := fx.resolvedAt(); strings.Join(got, ",") != "gb-a,gb-b" {
		t.Errorf("resolved at %v", got)
	}
	if up, msg := m.exitUp(m.state(), "gb-a"); up || !strings.Contains(msg, "vpn down") {
		t.Errorf("gb-a up=%v %q", up, msg)
	}
}

func TestResolveTransportFailureFailsOver(t *testing.T) {
	m2, fx2, _ := newFailoverManager(t)
	fx2.set(func() { fx2.brokenNodes["nod_a"] = true })
	if r := query(m2, "www.bbc.example", dns.TypeA); r.Rcode != dns.RcodeSuccess {
		t.Fatalf("answer %v", r)
	}
	if got := fx2.resolvedAt(); strings.Join(got, ",") != "gb-a,gb-b" {
		t.Errorf("resolved at %v", got)
	}
	if up, msg := m2.exitUp(m2.state(), "gb-a"); up || !strings.Contains(msg, "no route to host") {
		t.Errorf("gb-a not marked down after a transport failure: %v %q", up, msg)
	}
}

// relayExits serves the relay on a test listener; connect decides per exit.
func relayExits(t *testing.T, m *Manager, fx *fakeExits, connect func(req ConnectRequest) (net.Conn, error)) (addr string, connects func() []ConnectRequest) {
	t.Helper()
	var mu sync.Mutex
	var reqs []ConnectRequest
	fx.connect = func(req ConnectRequest) (net.Conn, error) {
		mu.Lock()
		reqs = append(reqs, req)
		mu.Unlock()
		return connect(req)
	}
	c, err := m.listenRelay("127.0.0.1:0", false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c.(net.Listener).Addr().String(), func() []ConnectRequest {
		mu.Lock()
		defer mu.Unlock()
		return slices.Clone(reqs)
	}
}

func echoConn() net.Conn {
	a, b := net.Pipe()
	go func() {
		defer b.Close()
		line, _ := bufio.NewReader(b).ReadString('\n')
		io.WriteString(b, "echo "+line)
	}()
	return a
}

func relayGet(t *testing.T, addr, host string) string {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	io.WriteString(conn, "GET /x HTTP/1.1\r\nHost: "+host+"\r\n\r\n")
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	b, _ := io.ReadAll(conn)
	return string(b)
}

func exitsOf(reqs []ConnectRequest) string {
	var s []string
	for _, r := range reqs {
		s = append(s, r.Exit)
	}
	return strings.Join(s, ",")
}

func TestRelayRetriesOnExitDown(t *testing.T) {
	m, fx, _ := newFailoverManager(t)
	addr, connects := relayExits(t, m, fx, func(req ConnectRequest) (net.Conn, error) {
		if req.Exit == "gb-a" {
			return nil, &relayRefused{msg: "VPN tunnel ix-x-gb-a has no recent handshake", exitDown: true}
		}
		return echoConn(), nil
	})
	if got := relayGet(t, addr, "www.bbc.example"); got != "echo GET /x HTTP/1.1\r\n" {
		t.Fatalf("got %q", got)
	}
	reqs := connects()
	if exitsOf(reqs) != "gb-a,gb-b" {
		t.Fatalf("connects %v", exitsOf(reqs))
	}
	// Each attempt carries the addresses resolved at its own exit.
	if reqs[0].Addrs[0].String() != "192.0.2.1" || reqs[1].Addrs[0].String() != "198.51.100.1" {
		t.Errorf("addrs %v / %v", reqs[0].Addrs, reqs[1].Addrs)
	}
	if up, msg := m.exitUp(m.state(), "gb-a"); up || !strings.Contains(msg, "no recent handshake") {
		t.Errorf("gb-a not marked down: %v %q", up, msg)
	}
	if got := activeOf(t, m); got != "gb-b" {
		t.Errorf("active %s", got)
	}
}

func TestRelayTransportFailureRetries(t *testing.T) {
	m, fx, _ := newFailoverManager(t)
	addr, connects := relayExits(t, m, fx, func(req ConnectRequest) (net.Conn, error) {
		if req.Exit == "gb-a" {
			return nil, errors.New("dial 10.255.0.2:51901: connection refused")
		}
		return echoConn(), nil
	})
	if got := relayGet(t, addr, "www.bbc.example"); got != "echo GET /x HTTP/1.1\r\n" {
		t.Fatalf("got %q", got)
	}
	if exitsOf(connects()) != "gb-a,gb-b" {
		t.Errorf("connects %v", exitsOf(connects()))
	}
	if up, msg := m.exitUp(m.state(), "gb-a"); up || !strings.Contains(msg, "connection refused") {
		t.Errorf("gb-a not marked down: %v %q", up, msg)
	}
}

func TestRelayOtherRefusalNotRetried(t *testing.T) {
	m, fx, _ := newFailoverManager(t)
	addr, connects := relayExits(t, m, fx, func(req ConnectRequest) (net.Conn, error) {
		if req.Exit == "gb-a" {
			return nil, &relayRefused{msg: "upstream 192.0.2.1 is not a public address"}
		}
		return echoConn(), nil
	})
	if got := relayGet(t, addr, "www.bbc.example"); got != "" {
		t.Fatalf("relayed %q after a final refusal", got)
	}
	if exitsOf(connects()) != "gb-a" || m.err.Load() != 1 {
		t.Errorf("connects %v errors %d", exitsOf(connects()), m.err.Load())
	}
	if got := activeOf(t, m); got != "gb-a" {
		t.Errorf("a final refusal moved the service to %s", got)
	}
}

func TestRelayNoRetryAfterBytesSent(t *testing.T) {
	m, fx, _ := newFailoverManager(t)
	addr, connects := relayExits(t, m, fx, func(req ConnectRequest) (net.Conn, error) {
		a, b := net.Pipe()
		b.Close() // the stream dies as the client's first bytes go up
		return a, nil
	})
	if got := relayGet(t, addr, "www.bbc.example"); got != "" {
		t.Fatalf("got %q", got)
	}
	time.Sleep(50 * time.Millisecond)
	if exitsOf(connects()) != "gb-a" {
		t.Errorf("connects %v, want a single attempt", exitsOf(connects()))
	}
}

func TestRelayAllExitsDown(t *testing.T) {
	m, fx, _ := newFailoverManager(t)
	addr, connects := relayExits(t, m, fx, func(req ConnectRequest) (net.Conn, error) {
		return nil, &relayRefused{msg: "vpn down", exitDown: true}
	})
	if got := relayGet(t, addr, "www.bbc.example"); got != "" {
		t.Fatalf("got %q", got)
	}
	if exitsOf(connects()) != "gb-a,gb-b,gb-c" {
		t.Errorf("connects %v, want one per exit", exitsOf(connects()))
	}
}

func TestCacheNeverCrossesExits(t *testing.T) {
	m, fx, _ := newFailoverManager(t)
	query(m, "www.bbc.example", dns.TypeA) // cached for gb-a
	fx.resolvedAt()
	fx.set(func() { fx.downNodes["nod_a"] = true })
	addr, connects := relayExits(t, m, fx, func(req ConnectRequest) (net.Conn, error) { return echoConn(), nil })
	relayGet(t, addr, "www.bbc.example")
	reqs := connects()
	if exitsOf(reqs) != "gb-b" || reqs[0].Addrs[0].String() != "198.51.100.1" {
		t.Fatalf("relayed %+v; gb-a's cached answer must not be used for gb-b", reqs)
	}
	if got := fx.resolvedAt(); strings.Join(got, ",") != "gb-b" {
		t.Errorf("resolved at %v", got)
	}
	if _, cs := m.cache.get(cacheKey{"gb-a", "www.bbc.example"}); cs != cacheFresh {
		t.Errorf("gb-a entry %v", cs)
	}
	if a, _ := m.cache.get(cacheKey{"gb-b", "www.bbc.example"}); a.Addrs[0].String() != "198.51.100.1" {
		t.Errorf("gb-b entry %v", a)
	}
}

func TestExitHealthPolling(t *testing.T) {
	m, fx, _ := newFailoverManager(t)
	var mu sync.Mutex
	var polled []string
	report := map[string]exitState{
		"nod_a": {Up: false, Error: "egress 198.51.100.6 geolocates to DE, expected GB"},
		"nod_b": {Up: true},
	}
	fx.health = func(node string) (exitState, error) {
		mu.Lock()
		defer mu.Unlock()
		polled = append(polled, node)
		if node == "nod_c" {
			return exitState{}, errors.New("exit node answered HTTP 404")
		}
		return report[node], nil
	}
	m.pollExitHealth(context.Background())
	slices.Sort(polled)
	if strings.Join(polled, ",") != "nod_a,nod_b,nod_c" {
		t.Errorf("polled %v (nod_d hosts no exit a service uses)", polled)
	}
	st := m.state()
	if up, msg := m.exitUp(st, "gb-a"); up || !strings.Contains(msg, "geolocates to DE") {
		t.Errorf("gb-a %v %q", up, msg)
	}
	if up, _ := m.exitUp(st, "gb-b"); !up {
		t.Error("gb-b down")
	}
	// A node whose health cannot be read holds its exit down.
	if up, msg := m.exitUp(st, "gb-c"); up || !strings.Contains(msg, "HTTP 404") {
		t.Errorf("gb-c %v %q", up, msg)
	}
	if got := activeOf(t, m); got != "gb-b" {
		t.Errorf("active %s", got)
	}

	// Nodes whose tunnel is down are not polled: that already holds their
	// exits down.
	mu.Lock()
	polled = nil
	report["nod_a"] = exitState{Up: true}
	mu.Unlock()
	fx.set(func() { fx.downNodes["nod_c"] = true })
	m.pollExitHealth(context.Background())
	slices.Sort(polled)
	if strings.Join(polled, ",") != "nod_a,nod_b" {
		t.Errorf("polled %v", polled)
	}
	if up, _ := m.exitUp(st, "gb-a"); !up {
		t.Error("gb-a still down after the node reported it up")
	}
}

func TestRemoteDownHoldExpires(t *testing.T) {
	m, _, clk := newFailoverManager(t)
	m.setRemoteDown("gb-a", true, "vpn down")
	if up, _ := m.exitUp(m.state(), "gb-a"); up {
		t.Fatal("not down")
	}
	clk.add(remoteDownHold)
	if up, _ := m.exitUp(m.state(), "gb-a"); !up {
		t.Error("still down after the hold")
	}
}

func TestActiveStateAcrossReconfigure(t *testing.T) {
	m, fx, _ := newFailoverManager(t)
	fx.set(func() { fx.downNodes["nod_a"] = true })
	activeOf(t, m)
	fx.set(func() { delete(fx.downNodes, "nod_a") })
	m.Reconfigure(failoverPlan())
	if got := activeOf(t, m); got != "gb-b" {
		t.Errorf("unchanged list: active %s, want the sticky gb-b", got)
	}
	p := failoverPlan()
	p.Services = map[string]config.SmartDNSSiteService{"bbc": {Domains: []string{"bbc.example"}, Exits: []string{"gb-a", "gb-c"}}}
	m.Reconfigure(p)
	if got := activeOf(t, m); got != "gb-a" {
		t.Errorf("changed list: active %s, want a fresh choice", got)
	}
}

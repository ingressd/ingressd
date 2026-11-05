// SPDX-License-Identifier: Apache-2.0

package smartdns

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http/httptest"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/ingressd/ingressd/pkg/config"
)

const failoverConfig = `version: 1
tunnels:
  home: { site: router, listen_port: 51820, transit: 10.100.1.0/24 }
mesh:
  address: 10.255.0.1/16
  peers:
    nod_a: { public_key: "aEvqkSJVw/7cGUEcJXmeHiNFDLBGOz8GpScshecvNHU=", endpoint: "198.51.100.6:51900", address: 10.255.0.2/32 }
    nod_b: { public_key: "bEvqkSJVw/7cGUEcJXmeHiNFDLBGOz8GpScshecvNHU=", endpoint: "198.51.100.7:51900", address: 10.255.0.3/32 }
    nod_c: { public_key: "cEvqkSJVw/7cGUEcJXmeHiNFDLBGOz8GpScshecvNHU=", endpoint: "198.51.100.8:51900", address: 10.255.0.4/32 }
    nod_d: { public_key: "dEvqkSJVw/7cGUEcJXmeHiNFDLBGOz8GpScshecvNHU=", endpoint: "198.51.100.9:51900", address: 10.255.0.5/32 }
smartdns:
  enabled: true
  upstream: ["127.0.0.1:9"]
  failback_after: 5m
  exits:
    gb-a: { node: nod_a, country: GB }
    gb-b: { node: nod_b, country: GB }
    gb-c: { node: nod_c, country: GB }
    nl: { node: nod_d, country: NL }
  services:
    bbc: { domains: [bbc.example], exits: [gb-a, gb-b, gb-c] }
`

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
	cfg, err := config.Parse([]byte(failoverConfig))
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	m := New(Options{})
	clk := &fakeClock{t: time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)}
	m.now = clk.now
	fx := &fakeExits{
		up: true, downNodes: map[string]bool{}, brokenNodes: map[string]bool{}, downExits: map[string]bool{},
		exitAddrs: map[string][]netip.Addr{
			"gb-a": addrs("192.0.2.1"),
			"gb-b": addrs("198.51.100.1"),
			"gb-c": addrs("203.0.113.1"),
		},
	}
	m.remote = fx
	m.dnsPort, m.tlsPort, m.httpPort = 0, 0, 0
	m.Reconfigure(cfg, func(string) (string, error) { return "", errors.New("no secrets") })
	m.listeners.closeAll()
	t.Cleanup(m.listeners.closeAll)
	return m, fx, clk
}

func bbcRoute(m *Manager) route {
	r, _ := m.state().scopes[0].match.match("bbc.example")
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
	if len(s) != 1 || s[0].Active != "gb-b" || !s[0].Failover || !strings.Contains(s[0].Message, "nod_a is unreachable") ||
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
	m.state().scopes[0].failback = 0
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
	for _, want := range []string{"SERVFAIL", "gb-a: exit node nod_a", "gb-b: exit node nod_b", "gb-c: exit node nod_c"} {
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

	// A mesh transport failure marks the node down and moves on too.
	m2, fx2, _ := newFailoverManager(t)
	fx2.set(func() { fx2.brokenNodes["nod_a"] = true })
	if r := query(m2, "www.bbc.example", dns.TypeA); r.Rcode != dns.RcodeSuccess {
		t.Fatalf("answer %v", r)
	}
	if got := fx2.resolvedAt(); strings.Join(got, ",") != "gb-a,gb-b" {
		t.Errorf("resolved at %v", got)
	}
	if fx2.Up("nod_a") {
		t.Error("node not marked down after a transport failure")
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
	if exitsOf(connects()) != "gb-a,gb-b" || fx.Up("nod_a") {
		t.Errorf("connects %v, nod_a up %v", exitsOf(connects()), fx.Up("nod_a"))
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
	if exitsOf(connects()) != "gb-a" || m.errors.Load() != 1 {
		t.Errorf("connects %v errors %d", exitsOf(connects()), m.errors.Load())
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
	report := map[string]map[string]exitState{
		"nod_a": {"gb-a": {Up: false, Error: "VPN tunnel ix-x-gb-a has no recent handshake"}},
		"nod_b": {"gb-b": {Up: true}},
		"nod_c": {}, // does not host gb-c (yet)
	}
	fx.health = func(node string) (map[string]exitState, error) {
		mu.Lock()
		defer mu.Unlock()
		polled = append(polled, node)
		return report[node], nil
	}
	m.pollExitHealth(context.Background())
	slices.Sort(polled)
	if strings.Join(polled, ",") != "nod_a,nod_b,nod_c" {
		t.Errorf("polled %v (nod_d hosts no exit a service uses)", polled)
	}
	st := m.state()
	if up, msg := m.exitUp(st, "gb-a"); up || !strings.Contains(msg, "no recent handshake") {
		t.Errorf("gb-a %v %q", up, msg)
	}
	if up, _ := m.exitUp(st, "gb-b"); !up {
		t.Error("gb-b down")
	}
	if up, msg := m.exitUp(st, "gb-c"); up || !strings.Contains(msg, "not hosted on node nod_c") {
		t.Errorf("gb-c %v %q", up, msg)
	}
	if got := activeOf(t, m); got != "gb-b" {
		t.Errorf("active %s", got)
	}

	// Unreachable nodes are left to the mesh probe.
	mu.Lock()
	polled = nil
	report["nod_a"] = map[string]exitState{"gb-a": {Up: true}}
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

func TestExitHealthUnsupportedFallsBack(t *testing.T) {
	m, fx, _ := newFailoverManager(t)
	fx.health = nil // old exit nodes answer 404
	m.pollExitHealth(context.Background())
	if !m.healthUnsupported["nod_a"] {
		t.Error("404 not noted")
	}
	if got := activeOf(t, m); got != "gb-a" {
		t.Fatalf("active %s: a 404 must not mark exits down", got)
	}
	// Today's signals still apply: exit_up:false on resolve.
	fx.set(func() { fx.downExits["gb-a"] = true })
	if r := query(m, "www.bbc.example", dns.TypeA); r.Rcode != dns.RcodeSuccess {
		t.Fatalf("answer %v", r)
	}
	if got := activeOf(t, m); got != "gb-b" {
		t.Errorf("active %s", got)
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
	cfg := m.state().cfg
	m.Reconfigure(cfg, func(string) (string, error) { return "", errors.New("no secrets") })
	m.listeners.closeAll()
	if got := activeOf(t, m); got != "gb-b" {
		t.Errorf("unchanged list: active %s, want the sticky gb-b", got)
	}
	cfg2 := *cfg
	sd := *cfg.SmartDNS
	sd.Services = map[string]config.SmartDNSService{"bbc": {Domains: []string{"bbc.example"}, Exits: []string{"gb-a", "gb-c"}}}
	cfg2.SmartDNS = &sd
	m.Reconfigure(&cfg2, func(string) (string, error) { return "", errors.New("no secrets") })
	m.listeners.closeAll()
	if got := activeOf(t, m); got != "gb-a" {
		t.Errorf("changed list: active %s, want a fresh choice", got)
	}
}

func TestExitRelaySetsExitDown(t *testing.T) {
	m, _ := newTestManager(t, fakeUpstream(t, "203.0.113.5"))
	cfg := *m.state().cfg
	mc := *cfg.Mesh
	mc.Peers = map[string]config.MeshPeer{"nod_nl": {PublicKey: "eEvqkSJVw/7cGUEcJXmeHiNFDLBGOz8GpScshecvNHU=", Address: "127.0.0.1/32"}}
	cfg.Mesh = &mc
	m.mesh.Reconfigure(&cfg)
	defer m.mesh.Reconfigure(nil)
	e := m.state().egress["home"]
	e.ifname = "ix-x-home"
	e.device = func(string) (*wgtypes.Device, error) { return nil, errors.New("no such device") }
	c, err := m.listenExitRelay("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	addr := c.(net.Listener).Addr().String()
	for _, tc := range []struct {
		req      ConnectRequest
		exitDown bool
	}{
		{ConnectRequest{Exit: "home", Host: "tv.stream.example", Port: 443, Addrs: addrs("192.0.2.20")}, true},
		{ConnectRequest{Exit: "home", Host: "tv.stream.example", Port: 22, Addrs: addrs("192.0.2.20")}, false},
	} {
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		conn.SetDeadline(time.Now().Add(3 * time.Second))
		WriteConnectRequest(conn, tc.req)
		resp, err := ReadConnectResponse(conn)
		conn.Close()
		if err != nil || resp.OK || resp.ExitDown != tc.exitDown {
			t.Errorf("%+v: %+v, %v", tc.req, resp, err)
		}
	}

	// GET /v1/exits reports the same.
	w := httptest.NewRecorder()
	m.exitsHandler().ServeHTTP(w, httptest.NewRequest("GET", "/v1/exits", nil))
	if !strings.Contains(w.Body.String(), `"home":{"up":false,"error":"VPN interface ix-x-home: no such device"}`) {
		t.Errorf("/v1/exits %s", w.Body.String())
	}
}

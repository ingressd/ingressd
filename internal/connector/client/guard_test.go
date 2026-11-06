// SPDX-License-Identifier: Apache-2.0

package client

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/ingressd/ingressd/internal/connector/proto"
)

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

func TestTransitPrefix(t *testing.T) {
	for in, want := range map[string]string{
		"100.64.0.6/30":  "100.64.0.6/30",
		"10.100.1.2/24":  "10.100.1.2/30",
		"10.100.0.2/16":  "10.100.0.2/30",
		"192.168.7.2/30": "192.168.7.2/30",
		"100.64.0.2/1":   "100.64.0.2/30",
		"100.64.0.2/32":  "100.64.0.2/32",
		"fd00::2/64":     "fd00::2/126",
		"127.0.0.2/30":   "",
		"0.0.0.0/0":      "",
		"224.0.0.2/30":   "",
		"169.254.0.2/30": "",
		"not an address": "",
		"":               "",
	} {
		p, ok := transitPrefix(in)
		if ok != (want != "") || (ok && p.String() != want) {
			t.Errorf("%q: %v %v, want %q", in, p, ok, want)
		}
	}
	// The narrowed prefix still holds the edge's address.
	p, _ := transitPrefix("10.100.1.2/24")
	if !p.Masked().Contains(netip.MustParseAddr("10.100.1.1")) {
		t.Errorf("%v lacks the edge address", p.Masked())
	}
}

func TestCheckConfig(t *testing.T) {
	good := proto.TunnelConfig{EdgePublicKey: key(t), Endpoint: "edge.example.test:51820", Address: "100.64.0.6/30"}
	if err := checkConfig(good, proto.TunnelConfig{}); err != nil {
		t.Error(err)
	}
	for name, change := range map[string]func(*proto.TunnelConfig){
		"key":      func(c *proto.TunnelConfig) { c.EdgePublicKey = "nope" },
		"endpoint": func(c *proto.TunnelConfig) { c.Endpoint = "no port" },
		"address":  func(c *proto.TunnelConfig) { c.Address = "nope" },
		"public":   func(c *proto.TunnelConfig) { c.Address = "198.51.100.2/30" },
	} {
		tc := good
		change(&tc)
		if checkConfig(tc, good) == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// A standalone edge's existing transit keeps working whatever its range.
	tc := good
	tc.Address = "198.51.100.2/30"
	if err := checkConfig(tc, tc); err != nil {
		t.Errorf("unchanged address: %v", err)
	}
}

func TestSanitizeConfig(t *testing.T) {
	tc := proto.TunnelConfig{
		Subnets:     []string{"192.168.0.0/24", "bad", "fd00::/64"},
		Transparent: []string{"tcp/192.168.0.17:25565", "tcp/[::1]:1", "icmp/192.168.0.17:1"},
		MTU:         99999,
	}
	sanitizeConfig(&tc, quiet)
	if !slices.Equal(tc.Subnets, []string{"192.168.0.0/24", "fd00::/64"}) || !slices.Equal(tc.Transparent, []string{"tcp/192.168.0.17:25565"}) || tc.MTU != 0 {
		t.Errorf("%+v", tc)
	}
	tc = proto.TunnelConfig{MTU: 1280}
	sanitizeConfig(&tc, quiet)
	if tc.MTU != 1280 {
		t.Errorf("MTU %d", tc.MTU)
	}
}

// A config that cannot run is not saved, and the link keeps the last good one.
func TestApplyEdgeConfigKeepsGoodConfig(t *testing.T) {
	k, _ := wgtypes.GeneratePrivateKey()
	pub := k.PublicKey()
	good := proto.TunnelConfig{Tunnel: "home", EdgePublicKey: pub.String(), Endpoint: "a:1", Address: "100.64.0.6/30", Revision: "r1", Subnets: []string{"192.168.0.0/24"}}
	path := filepath.Join(t.TempDir(), "connector.json")
	st := &State{Mode: ModeNetstack, Edges: []EdgeState{{Config: good}}}
	if err := st.Save(path); err != nil {
		t.Fatal(err)
	}
	s := &session{r: &Runner{StatePath: path}, st: st, log: quiet, restartEdge: map[string]bool{}, refresh: make(chan struct{}, 1)}
	e := &edge{s: s, key: pub, cfg: st.Edges[0]}

	bad := good
	bad.Revision, bad.Address = "r2", "nope"
	if err := s.applyEdgeConfig(e, bad); err == nil {
		t.Fatal("accepted")
	}
	saved, err := LoadState(path)
	if err != nil || saved.Edges[0].Config.Revision != "r1" || st.Edges[0].Config.Revision != "r1" {
		t.Errorf("saved %+v, %v", saved, err)
	}

	// One bad entry does not cost the site the rest of the update.
	next := good
	next.Revision, next.Subnets = "r3", []string{"192.168.0.0/24", "bad"}
	if err := s.applyEdgeConfig(e, next); err != nil {
		t.Fatal(err)
	}
	if saved, _ := LoadState(path); saved.Edges[0].Config.Revision != "r3" || len(saved.Subnets()) != 1 {
		t.Errorf("saved %+v", saved.Edges[0].Config)
	}
}

func TestNetstackStartsWithBadSubnet(t *testing.T) {
	k, _ := wgtypes.GeneratePrivateKey()
	st := &State{Edges: []EdgeState{{Config: proto.TunnelConfig{Address: "100.64.0.6/30", Subnets: []string{"bad", "192.168.0.0/24"}}}}}
	l, err := openNetstack(st, k, quiet)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if p, err := l.(*userLink).ListenPort(); err != nil || p == 0 {
		t.Errorf("listen port %d, %v", p, err)
	}
}

func TestForwardPrefixes(t *testing.T) {
	st := &State{Edges: []EdgeState{
		{Config: proto.TunnelConfig{Subnets: []string{"192.168.1.5/24", "192.168.1.17/32", "10.0.0.9/32", "bad"}}},
		{Config: proto.TunnelConfig{Subnets: []string{"10.0.0.0/8"}, Transparent: []string{"tcp/172.16.0.4:25565", "tcp/10.1.1.1:1"}}},
	}}
	var got []string
	for _, p := range st.forwardPrefixes() {
		got = append(got, p.String())
	}
	if want := []string{"10.0.0.0/8", "192.168.1.0/24", "172.16.0.4/32"}; !slices.Equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestReachTargets(t *testing.T) {
	targets := []string{"192.168.1.5:80", "192.168.2.5:80", "127.0.0.1:80", "169.254.169.254:80", "nas.example.test:80"}
	st := &State{Edges: []EdgeState{{Config: proto.TunnelConfig{
		Subnets: []string{"192.168.1.0/24", "127.0.0.0/8", "169.254.169.254/32"}, Targets: targets,
	}}}}
	if got := st.reachTargets(); !slices.Equal(got, []string{"192.168.1.5:80"}) {
		t.Errorf("got %v", got)
	}
	st.Edges[0].Config.Targets = nil
	for i := range maxReachTargets + 10 {
		st.Edges[0].Config.Targets = append(st.Edges[0].Config.Targets, netip.AddrPortFrom(netip.MustParseAddr("192.168.1.5"), uint16(1000+i)).String())
	}
	if got := len(st.reachTargets()); got != maxReachTargets {
		t.Errorf("%d targets", got)
	}
}

func TestReachabilityResult(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	got := testReachability(context.Background(), []string{addr})
	if len(got) != 1 || got[0].OK || got[0].Error != "unreachable" {
		t.Errorf("%+v", got)
	}
}

func TestNetstackTargets(t *testing.T) {
	ns := &netstackTUN{allowed: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}}
	for a, want := range map[string]bool{
		"192.168.1.5":     true,
		"127.0.0.1":       false,
		"0.0.0.0":         false,
		"224.0.0.1":       false,
		"169.254.169.254": false,
	} {
		id := tcpID(netip.MustParseAddr(a))
		if _, ok := ns.target(id); ok != want {
			t.Errorf("%s: %v", a, ok)
		}
	}
}

// A learned edge gets v2 until it answers 401, and v1 from then on if v2 is
// what it refused; its own config decides once it has been polled.
func TestLearnedEdgeKeyAuth(t *testing.T) {
	site, _ := wgtypes.GeneratePrivateKey()
	edgeKey, _ := wgtypes.GeneratePrivateKey()
	e := &edge{s: &session{priv: site}, key: edgeKey.PublicKey(), cfg: EdgeState{Learned: true, Config: proto.TunnelConfig{Tunnel: "home"}}}
	header := func() string { return e.authHeader(http.MethodGet, proto.PollPath, nil) }
	h := header()
	if proto.KeyAuthVersion(h) != proto.KeyAuthV2 {
		t.Fatalf("first contact %q", h)
	}
	e.authRejected(h)
	e.authRejected(h) // a second answer to the same version changes nothing
	h = header()
	if proto.KeyAuthVersion(h) != 1 {
		t.Fatalf("after a refusal %q", h)
	}
	e.authRejected(h)
	if h = header(); proto.KeyAuthVersion(h) != proto.KeyAuthV2 {
		t.Errorf("after refusing both %q", h)
	}

	e.cfg.LastSeen = time.Now()
	if h = header(); proto.KeyAuthVersion(h) != 1 {
		t.Errorf("polled edge without v2 %q", h)
	}
	e.cfg.Config.KeyAuth = proto.KeyAuthV2
	e.authRejected(header())
	if h = header(); proto.KeyAuthVersion(h) != proto.KeyAuthV2 {
		t.Errorf("polled edge with v2 %q", h)
	}
}

func TestRelayUnauthorized(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}))
	defer ts.Close()
	_, err := dialRelay(context.Background(), "ws"+strings.TrimPrefix(ts.URL, "http"), http.DefaultClient, nil, nil)
	if err == nil || !strings.Contains(err.Error(), errRelayUnauthorized.Error()) {
		t.Errorf("got %v", err)
	}
}

// The relay answers the WireGuard socket, whoever else writes to its port.
func TestRelayAnswersWireGuardSocket(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer c.CloseNow()
		for {
			typ, b, err := c.Read(r.Context())
			if err != nil {
				return
			}
			if c.Write(r.Context(), typ, b) != nil {
				return
			}
		}
	}))
	defer ts.Close()

	open := func() *net.UDPConn {
		c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close() })
		return c
	}
	wg, other := open(), open()
	port := wg.LocalAddr().(*net.UDPAddr).AddrPort().Port()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	relay, err := dialRelay(ctx, "ws"+strings.TrimPrefix(ts.URL, "http"), http.DefaultClient, nil,
		func(a netip.AddrPort) bool { return a.Port() == port })
	if err != nil {
		t.Fatal(err)
	}
	defer relay.Close()
	to := net.UDPAddrFromAddrPort(relay.Endpoint())

	if _, err := other.WriteToUDP([]byte("other"), to); err != nil {
		t.Fatal(err)
	}
	if _, err := wg.WriteToUDP([]byte("wireguard"), to); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	_ = wg.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, _, err := wg.ReadFromUDP(buf)
	if err != nil || string(buf[:n]) != "wireguard" {
		t.Fatalf("read %q, %v", buf[:n], err)
	}
	_ = other.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	if n, _, err := other.ReadFromUDP(buf); err == nil {
		t.Errorf("other sender got %q", buf[:n])
	}

	if _, err := other.WriteToUDP([]byte("other"), to); err != nil {
		t.Fatal(err)
	}
	if _, err := wg.WriteToUDP([]byte("again"), to); err != nil {
		t.Fatal(err)
	}
	_ = wg.SetReadDeadline(time.Now().Add(3 * time.Second))
	if n, _, err = wg.ReadFromUDP(buf); err != nil || string(buf[:n]) != "again" {
		t.Errorf("read %q, %v", buf[:n], err)
	}
}

func TestRescueNeedsHTTPS(t *testing.T) {
	st := &State{Edges: []EdgeState{{Config: proto.TunnelConfig{PanelURL: "http://panel.example.test"}}}}
	s := &session{st: st}
	if err := s.rescue(context.Background()); err == nil || !strings.Contains(err.Error(), "https") {
		t.Errorf("got %v", err)
	}
}

func TestPanelClientStaysOnThePanel(t *testing.T) {
	hit := false
	other := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hit = true }))
	defer other.Close()
	ts := httptest.NewServer(http.RedirectHandler(other.URL, http.StatusTemporaryRedirect))
	defer ts.Close()
	resp, err := panelClient.Post(ts.URL, "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if hit || resp.StatusCode != http.StatusTemporaryRedirect {
		t.Errorf("hit %v, status %d", hit, resp.StatusCode)
	}
}

func TestPollBodyLimit(t *testing.T) {
	big := strings.Repeat(" ", maxConfigBody+1) + `{"tunnel":"home"}`
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, big) }))
	defer ts.Close()
	k, _ := wgtypes.GeneratePrivateKey()
	st := &State{Edges: []EdgeState{{URL: ts.URL, Credential: "c", Config: proto.TunnelConfig{Tunnel: "home", EdgePublicKey: k.PublicKey().String()}}}}
	s := &session{r: &Runner{}, st: st, log: quiet, link: &fakeLink{}, upd: newUpdater(filepath.Join(t.TempDir(), "c.json"))}
	e := &edge{s: s, key: k.PublicKey(), cfg: st.Edges[0], control: ts.Client()}
	if err := e.pollOnce(context.Background()); err == nil || !strings.Contains(err.Error(), "poll") {
		t.Errorf("got %v", err)
	}
}

// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/ingressd/ingressd/internal/connector/proto"
	"github.com/ingressd/ingressd/pkg/config"
)

// wgKeys is a tunnel.Keys-like key source with a fixed edge key and the
// configured site key.
type wgKeys struct {
	edge wgtypes.Key
	cfg  *config.Config
}

func (k wgKeys) EdgePublic(string) (string, error)  { return k.edge.PublicKey().String(), nil }
func (k wgKeys) EdgePrivate(string) (string, error) { return k.edge.String(), nil }
func (k wgKeys) SitePublic(t string) (string, error) {
	return k.cfg.Tunnels[t].PublicKey, nil
}

func multiEdgeServer(t *testing.T) (*Server, wgtypes.Key, wgtypes.Key, *config.Config) {
	t.Helper()
	edge, _ := wgtypes.GeneratePrivateKey()
	site, _ := wgtypes.GeneratePrivateKey()
	sib, _ := wgtypes.GeneratePrivateKey()
	cfg := testConfig(51821)
	tun := cfg.Tunnels["cloud"]
	tun.Transit = "100.64.0.4/30"
	tun.PublicKey = site.PublicKey().String()
	tun.Siblings = []config.TunnelSibling{
		{Node: "nod_b", Endpoint: "b.example.test:51822", EdgePublicKey: sib.PublicKey().String(), Transit: "100.64.0.8/30", WSURL: "wss://b.example.test/.ingressd/tunnel/cloud"},
		{Node: "nod_bad", Endpoint: "c.example.test:51822", Transit: "100.64.0.12/30"}, // no key yet: omitted
	}
	cfg.Tunnels["cloud"] = tun
	cfg.Tunnels["lab"] = config.Tunnel{Type: "wireguard", Site: "router", ListenPort: 51830, Transit: "100.64.0.68/30"}
	s := &Server{Store: NewStore(t.TempDir())}
	s.Update(cfg, wgKeys{edge: edge, cfg: cfg})
	return s, edge, site, cfg
}

func TestTunnelConfigSiblings(t *testing.T) {
	s, _, _, cfg := multiEdgeServer(t)
	_, keys, _ := s.snapshot()
	tc, err := TunnelConfig(cfg, keys, "cloud")
	if err != nil {
		t.Fatal(err)
	}
	if tc.Address != "100.64.0.6/30" || tc.EdgeAddress != "100.64.0.5" {
		t.Errorf("own addresses %s %s", tc.Address, tc.EdgeAddress)
	}
	if len(tc.Siblings) != 1 {
		t.Fatalf("siblings %+v", tc.Siblings)
	}
	sb := tc.Siblings[0]
	if sb.Node != "nod_b" || sb.Endpoint != "b.example.test:51822" || sb.Address != "100.64.0.10/30" || sb.EdgeAddress != "100.64.0.9" ||
		sb.WSURL != "wss://b.example.test/.ingressd/tunnel/cloud" || sb.EdgePublicKey != cfg.Tunnels["cloud"].Siblings[0].EdgePublicKey {
		t.Errorf("sibling %+v", sb)
	}
	before := tc.Revision
	cfg.Tunnels["cloud"].Siblings[0].Endpoint = "b2.example.test:51822"
	if tc2, _ := TunnelConfig(cfg, keys, "cloud"); tc2.Revision == before {
		t.Error("revision does not cover siblings")
	}
}

func TestTunnelForPeer(t *testing.T) {
	_, _, _, cfg := multiEdgeServer(t)
	a := netip.MustParseAddr
	if tun, ok := TunnelForPeer(cfg, a("100.64.0.5"), a("100.64.0.6")); !ok || tun != "cloud" {
		t.Errorf("got %q %v", tun, ok)
	}
	for _, c := range [][2]string{
		{"100.64.0.5", "100.64.0.7"},   // not the site address
		{"100.64.0.9", "100.64.0.10"},  // a sibling's transit: not this node's
		{"100.64.0.69", "100.64.0.70"}, // router tunnel
		{"198.51.100.1", "100.64.0.6"}, // public address
	} {
		if tun, ok := TunnelForPeer(cfg, a(c[0]), a(c[1])); ok {
			t.Errorf("%v accepted as %q", c, tun)
		}
	}
}

// TestTunnelControlHandler serves the control port on loopback addresses
// standing in for the transit: the identity comes from the addresses.
func TestTunnelControlHandler(t *testing.T) {
	s, _, _, cfg := multiEdgeServer(t)
	tun := cfg.Tunnels["cloud"]
	tun.Transit = "127.0.0.0/30" // edge 127.0.0.1, site 127.0.0.2
	cfg.Tunnels["cloud"] = tun
	s.Update(cfg, wgKeys{cfg: cfg})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: s.TunnelControlHandler(), ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	get := func(src string) *http.Response {
		d := &net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP(src)}}
		hc := &http.Client{Transport: &http.Transport{DialContext: d.DialContext}, Timeout: 5 * time.Second}
		resp, err := hc.Get("http://" + ln.Addr().String() + proto.PollPath + "?wait=0s")
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}
	resp := get("127.0.0.2")
	var tc proto.TunnelConfig
	if err := json.NewDecoder(resp.Body).Decode(&tc); err != nil || resp.StatusCode != http.StatusOK || tc.Tunnel != "cloud" || len(tc.Siblings) != 1 {
		t.Fatalf("poll from the site address: %s %+v %v", resp.Status, tc, err)
	}
	_ = resp.Body.Close()
	if resp := get("127.0.0.3"); resp.StatusCode != http.StatusForbidden {
		t.Errorf("poll from another address: %s", resp.Status)
	}
	// A report over the tunnel is stored although the connector never
	// enrolled on this node.
	d := &net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP("127.0.0.2")}}
	hc := &http.Client{Transport: &http.Transport{DialContext: d.DialContext}}
	resp, err = hc.Post("http://"+ln.Addr().String()+proto.ReportPath, "application/json", strings.NewReader(`{"mode":"tun","transport":"udp"}`))
	if err != nil || resp.StatusCode != http.StatusNoContent {
		t.Fatalf("report: %v %v", resp, err)
	}
	st, _ := s.Store.Load()
	if c := st.Connectors["cloud"]; c == nil || c.Health == nil || c.Health.Transport != "udp" {
		t.Errorf("report not stored: %+v", c)
	}
}

func TestKeyAuthOnPublicEndpoints(t *testing.T) {
	s, edge, site, _ := multiEdgeServer(t)
	ts := httpServer(t, s)
	poll := func(auth string) int {
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, ts+proto.PollPath+"?wait=0s", nil)
		req.Header.Set("Authorization", auth)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		return resp.StatusCode
	}
	pub := edge.PublicKey()
	h, _ := proto.KeyAuth("cloud", site[:], pub[:], time.Now())
	if c := poll(h); c != http.StatusOK {
		t.Errorf("key auth with the configured site key: %d", c)
	}
	other, _ := wgtypes.GeneratePrivateKey()
	h, _ = proto.KeyAuth("cloud", other[:], pub[:], time.Now())
	if c := poll(h); c != http.StatusUnauthorized {
		t.Errorf("key auth with another key: %d", c)
	}
	h, _ = proto.KeyAuth("lab", site[:], pub[:], time.Now())
	if c := poll(h); c != http.StatusUnauthorized {
		t.Errorf("key auth for a router tunnel: %d", c)
	}
	h, _ = proto.KeyAuth("cloud", site[:], pub[:], time.Now().Add(-time.Hour))
	if c := poll(h); c != http.StatusUnauthorized {
		t.Errorf("stale key auth: %d", c)
	}
}

func TestKeyAuthV2OnPublicEndpoints(t *testing.T) {
	s, edge, site, _ := multiEdgeServer(t)
	ts := httpServer(t, s)
	pub := edge.PublicKey()
	send := func(method, path, body, auth string) int {
		var r io.Reader
		if body != "" {
			r = strings.NewReader(body)
		}
		req, _ := http.NewRequestWithContext(context.Background(), method, ts+path, r)
		req.Header.Set("Authorization", auth)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		return resp.StatusCode
	}
	hdr := func(method, path, body string) string {
		h, err := proto.KeyAuthRequest("cloud", site[:], pub[:], time.Now(), method, path, []byte(body))
		if err != nil {
			t.Fatal(err)
		}
		return h
	}
	// The edge advertises v2.
	tc, err := TunnelConfig(s.cfg, s.keys, "cloud")
	if err != nil || tc.KeyAuth != proto.KeyAuthV2 {
		t.Fatalf("config does not advertise v2: %+v %v", tc, err)
	}

	h := hdr(http.MethodGet, proto.PollPath, "")
	if c := send(http.MethodGet, proto.PollPath+"?wait=0s", "", h); c != http.StatusOK {
		t.Fatalf("v2 poll: %d", c)
	}
	if c := send(http.MethodGet, proto.PollPath+"?wait=0s", "", h); c != http.StatusUnauthorized {
		t.Errorf("replayed v2 header: %d", c)
	}
	// A header made for the WebSocket relay does not authorise a poll.
	if c := send(http.MethodGet, proto.PollPath+"?wait=0s", "", hdr(http.MethodGet, proto.WSPath, "")); c != http.StatusUnauthorized {
		t.Errorf("v2 header for another path: %d", c)
	}
	report := `{"mode":"tun","transport":"udp"}`
	if c := send(http.MethodPost, proto.ReportPath, report, hdr(http.MethodPost, proto.ReportPath, report)); c != http.StatusNoContent {
		t.Errorf("v2 report: %d", c)
	}
	if c := send(http.MethodPost, proto.ReportPath, `{"mode":"tun","transport":"websocket"}`, hdr(http.MethodPost, proto.ReportPath, report)); c != http.StatusUnauthorized {
		t.Errorf("v2 report with another body: %d", c)
	}
	if c := send(http.MethodPost, proto.ReportPath, report, hdr(http.MethodGet, proto.ReportPath, report)); c != http.StatusUnauthorized {
		t.Errorf("v2 header for another method: %d", c)
	}
	st, _ := s.Store.Load()
	if c := st.Connectors["cloud"]; c == nil || c.Health == nil || c.Health.Transport != "udp" {
		t.Errorf("report: %+v", c)
	}
	// v1 headers are still accepted (connectors from before v2).
	h1, _ := proto.KeyAuth("cloud", site[:], pub[:], time.Now())
	if c := send(http.MethodGet, proto.PollPath+"?wait=0s", "", h1); c != http.StatusOK {
		t.Errorf("v1 poll: %d", c)
	}
}

func TestReplayCache(t *testing.T) {
	var c replayCache
	now := time.Now()
	if !c.add("a", now) || c.add("a", now.Add(time.Minute)) {
		t.Fatal("nonce accepted twice")
	}
	if !c.add("a", now.Add(2*proto.KeyAuthSkew+time.Second)) {
		t.Error("nonce remembered after its header expired")
	}
}

func httpServer(t *testing.T, s *Server) string {
	t.Helper()
	mux := http.NewServeMux()
	mux.Handle("/.ingressd/connector/", s.ConnectorHandler())
	mux.Handle(proto.TunnelPathPrefix, s.TunnelHandler())
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return "http://" + ln.Addr().String()
}

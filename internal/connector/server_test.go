// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/ingressd/ingressd/internal/connector/proto"
	"github.com/ingressd/ingressd/pkg/config"
)

type fakeKeys struct{}

func (fakeKeys) EdgePublic(string) (string, error) {
	return "Xk1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaA=", nil
}

func TestConnectorSubnetsNamePublishedAddressesUnderADefaultRoute(t *testing.T) {
	cfg := &config.Config{
		Tunnels: map[string]config.Tunnel{"all": {Subnets: []string{"0.0.0.0/0"}}, "lan": {Subnets: []string{"10.0.1.0/24"}}},
		Apps: map[string]config.App{
			"a": {Tunnel: "all", Origin: "http://203.0.113.7:80"},
			"b": {Tunnel: "lan", Origin: "http://10.0.1.5:80"},
		},
		L4: map[string]config.L4Service{"game": {Target: config.L4Target{Tunnel: "all", Address: "203.0.113.8"}}},
	}
	if got, want := connectorSubnets(cfg, "all"), []string{"0.0.0.0/0", "203.0.113.7/32", "203.0.113.8/32"}; !slices.Equal(got, want) {
		t.Errorf("subnets = %v, want %v", got, want)
	}
	if got, want := connectorSubnets(cfg, "lan"), cfg.TunnelRoutes("lan"); !slices.Equal(got, want) {
		t.Errorf("subnets = %v, want %v", got, want)
	}
}

func testConfig(port int) *config.Config {
	return &config.Config{
		Edge: config.Edge{Admin: config.Admin{Hostname: "edge.example.test"}},
		Tunnels: map[string]config.Tunnel{
			"cloud": {Type: "wireguard", Site: "connector", ListenPort: port, Transit: "10.100.2.0/24",
				Subnets: []string{"10.0.1.0/24"}, Keepalive: 25, FallbackWS: true},
		},
		Apps: map[string]config.App{
			"web": {Origin: "http://10.0.1.5:8080", Tunnel: "cloud"},
			"api": {Origin: "https://10.0.1.6", Tunnel: "cloud"},
		},
	}
}

func newTestServer(t *testing.T, port int) (*Server, *httptest.Server) {
	t.Helper()
	s := &Server{Store: NewStore(t.TempDir())}
	s.Update(testConfig(port), fakeKeys{})
	mux := http.NewServeMux()
	mux.Handle("/.ingressd/connector/", s.ConnectorHandler())
	mux.Handle(proto.TunnelPathPrefix, s.TunnelHandler())
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	return s, ts
}

func enroll(t *testing.T, url, token string) (*http.Response, proto.EnrollResponse) {
	t.Helper()
	k, _ := wgtypes.GeneratePrivateKey()
	body, _ := json.Marshal(proto.EnrollRequest{Token: token, PublicKey: k.PublicKey().String()})
	resp, err := http.Post(url+proto.EnrollPath, "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var er proto.EnrollResponse
	if resp.StatusCode == http.StatusOK {
		if err := json.NewDecoder(resp.Body).Decode(&er); err != nil {
			t.Fatal(err)
		}
	}
	return resp, er
}

func TestEnrollSingleUse(t *testing.T) {
	s, ts := newTestServer(t, 51821)
	reapplied := 0
	s.Reapply = func(context.Context) error { reapplied++; return nil }
	tok, err := s.Store.CreateToken("cloud", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	resp, er := enroll(t, ts.URL, tok)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("enroll: %s", resp.Status)
	}
	c := er.Config
	if c.Tunnel != "cloud" || c.Address != "10.100.2.2/24" || c.EdgeAddress != "10.100.2.1" ||
		c.Endpoint != "edge.example.test:51821" || c.WSURL != "wss://edge.example.test/.ingressd/tunnel/cloud" || c.Revision == "" {
		t.Errorf("unexpected config: %+v", c)
	}
	if want := []string{"10.0.1.5:8080", "10.0.1.6:443"}; !slices.Equal(c.Targets, want) {
		t.Errorf("targets = %v, want %v", c.Targets, want)
	}
	if reapplied != 1 {
		t.Errorf("reapply called %d times", reapplied)
	}
	if pk := s.Store.SitePublicKey("cloud"); pk == "" {
		t.Error("site key not recorded")
	}
	if !s.Store.Authenticate("cloud", er.Credential) || s.Store.Authenticate("cloud", "nope") {
		t.Error("credential check wrong")
	}
	if resp, _ := enroll(t, ts.URL, tok); resp.StatusCode != http.StatusForbidden {
		t.Errorf("reused token: %s, want 403", resp.Status)
	}
	fi, err := os.Stat(s.Store.Path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm()&0o077 != 0 && filepath.Separator == '/' {
		t.Errorf("state file mode %v", fi.Mode())
	}
	b, _ := os.ReadFile(s.Store.Path)
	if strings.Contains(string(b), tok) || strings.Contains(string(b), er.Credential) {
		t.Error("state file contains plaintext secrets")
	}
}

func TestTokenExpires(t *testing.T) {
	st := NewStore(t.TempDir())
	tok, _ := st.CreateToken("cloud", time.Now().Add(-TokenTTL-time.Second))
	if _, _, err := st.Enroll(tok, "k", "", time.Now()); err != ErrBadToken {
		t.Errorf("expired token: err = %v", err)
	}
}

func TestPoll(t *testing.T) {
	s, ts := newTestServer(t, 51821)
	tok, _ := s.Store.CreateToken("cloud", time.Now())
	_, er := enroll(t, ts.URL, tok)
	auth := proto.Bearer("cloud", er.Credential)

	get := func(rev, wait string) *http.Response {
		req, _ := http.NewRequest("GET", ts.URL+proto.PollPath+"?rev="+rev+"&wait="+wait, nil)
		req.Header.Set("Authorization", auth)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}
	if r := get("", "1s"); r.StatusCode != http.StatusOK {
		t.Errorf("poll without rev: %s", r.Status)
	}
	if r := get(er.Config.Revision, "100ms"); r.StatusCode != http.StatusNoContent {
		t.Errorf("poll with current rev: %s", r.Status)
	}
	// A config change wakes a waiting poll.
	go func() {
		time.Sleep(200 * time.Millisecond)
		cfg := testConfig(51821)
		tn := cfg.Tunnels["cloud"]
		tn.Subnets = append(tn.Subnets, "10.0.2.0/24")
		cfg.Tunnels["cloud"] = tn
		s.Update(cfg, fakeKeys{})
	}()
	start := time.Now()
	r := get(er.Config.Revision, "10s")
	var tc proto.TunnelConfig
	_ = json.NewDecoder(r.Body).Decode(&tc)
	if r.StatusCode != http.StatusOK || len(tc.Subnets) != 2 || time.Since(start) > 5*time.Second {
		t.Errorf("poll after change: %s %+v", r.Status, tc)
	}

	req, _ := http.NewRequest("GET", ts.URL+proto.PollPath, nil)
	req.Header.Set("Authorization", proto.Bearer("cloud", "wrong"))
	if r, _ := http.DefaultClient.Do(req); r.StatusCode != http.StatusUnauthorized {
		t.Errorf("bad credential: %s", r.Status)
	}

	h, _ := json.Marshal(proto.Health{Mode: "tun", Transport: "udp", MTU: 1420})
	req, _ = http.NewRequest("POST", ts.URL+proto.ReportPath, bytes.NewReader(h))
	req.Header.Set("Authorization", auth)
	if r, _ := http.DefaultClient.Do(req); r.StatusCode != http.StatusNoContent {
		t.Errorf("report: %s", r.Status)
	}
	st, _ := s.Store.Load()
	if c := st.Connectors["cloud"]; c.Health == nil || c.Health.Transport != "udp" || c.Health.Time.IsZero() {
		t.Errorf("health not stored: %+v", c.Health)
	}
}

func TestWebSocketBridge(t *testing.T) {
	// The "WireGuard listener": echoes datagrams back, prefixed.
	wg, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer wg.Close()
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := wg.ReadFromUDP(buf)
			if err != nil {
				return
			}
			_, _ = wg.WriteToUDP(append([]byte("echo:"), buf[:n]...), from)
		}
	}()
	s, ts := newTestServer(t, wg.LocalAddr().(*net.UDPAddr).Port)
	tok, _ := s.Store.CreateToken("cloud", time.Now())
	_, er := enroll(t, ts.URL, tok)
	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http") + proto.TunnelPathPrefix + "cloud"

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, _, err := websocket.Dial(ctx, wsURL, nil); err == nil {
		t.Error("websocket without credential accepted")
	}
	c, _, err := websocket.Dial(ctx, wsURL, &websocket.DialOptions{HTTPHeader: http.Header{"Authorization": {proto.Bearer("cloud", er.Credential)}}})
	if err != nil {
		t.Fatal(err)
	}
	defer c.CloseNow()
	if err := c.Write(ctx, websocket.MessageBinary, []byte("hello")); err != nil {
		t.Fatal(err)
	}
	_, b, err := c.Read(ctx)
	if err != nil || string(b) != "echo:hello" {
		t.Fatalf("got %q, %v", b, err)
	}
}

func TestHostPort(t *testing.T) {
	for in, want := range map[string]string{
		"http://192.168.0.17:8080": "192.168.0.17:8080",
		"https://nas.lan":          "nas.lan:443",
		"10.0.0.5:22":              "10.0.0.5:22",
		"h2c://10.0.0.5":           "10.0.0.5:80",
		"garbage":                  "",
	} {
		if got := hostPort(in); got != want {
			t.Errorf("hostPort(%q) = %q, want %q", in, got, want)
		}
	}
}

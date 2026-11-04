// SPDX-License-Identifier: Apache-2.0

package l4

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ingressd/ingressd/pkg/config"
)

const testYAML = `
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
l4:
  fivem:
    preset: fivem
    target: { tunnel: home, address: 192.168.0.40 }
    access: login_to_play
    login_to_play: { policy: friends, ttl: 2h, portal_host: play.example.com }
  mc:
    preset: minecraft_java
    target: { tunnel: home, address: 192.168.0.41 }
  bedrock:
    preset: minecraft_bedrock
    target: { tunnel: home, address: 192.168.0.42 }
    access: allowlist
`

func testConfig(t *testing.T) *config.Config {
	t.Helper()
	cfg, err := config.Parse([]byte(testYAML))
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	return cfg
}

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

type fakeNFT struct{ scripts []string }

func (f *fakeNFT) run(_ context.Context, s string) error {
	f.scripts = append(f.scripts, s)
	return nil
}

func newManager(t *testing.T) (*Manager, *clock, *fakeNFT) {
	clk := &clock{time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)}
	nft := &fakeNFT{}
	st := &Store{Path: filepath.Join(t.TempDir(), FileName), Now: clk.now}
	return &Manager{Cfg: testConfig(t), Store: st, NFT: nft.run}, clk, nft
}

func TestAllowRevokeExpire(t *testing.T) {
	m, clk, nft := newManager(t)
	ctx := context.Background()
	if _, err := m.Allow(ctx, "fivem", "198.51.100.7", "sam@example.com", time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Allow(ctx, "bedrock", "198.51.100.8", "", 0); err != nil {
		t.Fatal(err)
	}
	want := "add element ip ingressd_l4 svc_fivem_allow { 198.51.100.7 }\n" +
		"delete element ip ingressd_l4 svc_fivem_allow { 198.51.100.7 }\n" +
		"add element ip ingressd_l4 svc_fivem_allow { 198.51.100.7 timeout 3600s }\n"
	if nft.scripts[0] != want {
		t.Errorf("allow script:\n%s\nwant:\n%s", nft.scripts[0], want)
	}
	if !strings.HasSuffix(nft.scripts[1], "{ 198.51.100.8 }\n") {
		t.Errorf("permanent entry got a timeout: %s", nft.scripts[1])
	}

	// Refreshing replaces the entry instead of duplicating it.
	if _, err := m.Allow(ctx, "fivem", "198.51.100.7", "sam@example.com", 2*time.Hour); err != nil {
		t.Fatal(err)
	}
	es, _ := m.Store.List()
	if len(es) != 2 || es[1].Service != "fivem" || !es[1].Expires.Equal(clk.t.Add(2*time.Hour)) {
		t.Fatalf("entries = %+v", es)
	}

	clk.t = clk.t.Add(3 * time.Hour)
	es, _ = m.Store.List()
	if len(es) != 1 || es[0].Service != "bedrock" {
		t.Fatalf("after expiry entries = %+v", es)
	}

	if err := m.Revoke(ctx, "bedrock", "198.51.100.8"); err != nil {
		t.Fatal(err)
	}
	if es, _ := m.Store.List(); len(es) != 0 {
		t.Fatalf("after revoke entries = %+v", es)
	}
	if err := m.Revoke(ctx, "bedrock", "198.51.100.8"); err == nil {
		t.Error("revoking a missing entry succeeded")
	}
}

func TestAllowRejects(t *testing.T) {
	m, _, _ := newManager(t)
	ctx := context.Background()
	for _, tc := range []struct{ svc, ip, want string }{
		{"nope", "198.51.100.7", "unknown l4 service"},
		{"mc", "198.51.100.7", "has access public"},
		{"fivem", "2001:db8::1", "invalid IPv4"},
		{"fivem", "not-an-ip", "invalid IPv4"},
	} {
		if _, err := m.Allow(ctx, tc.svc, tc.ip, "", 0); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("Allow(%s, %s) = %v, want %q", tc.svc, tc.ip, err, tc.want)
		}
	}
}

func TestSyncScript(t *testing.T) {
	now := time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)
	rendered := "table ip ingressd_l4 {\n\tset svc_fivem_static {\n\t}\n\tset svc_fivem_allow {\n\t\ttype ipv4_addr; flags timeout;\n\t}\n}\n"
	entries := []Entry{
		{Service: "fivem", IP: "198.51.100.7", Expires: now.Add(90 * time.Second)},
		{Service: "fivem", IP: "198.51.100.9"},
		{Service: "fivem", IP: "198.51.100.10", Expires: now.Add(-time.Second)}, // expired
		{Service: "removed", IP: "198.51.100.8"},                                // no set
	}
	got := SyncScript(rendered, entries, now)
	want := "add element ip ingressd_l4 svc_fivem_allow { 198.51.100.7 timeout 90s, 198.51.100.9 }\n"
	if got != want {
		t.Errorf("SyncScript = %q, want %q", got, want)
	}
	if SyncScript("", entries, now) != "" {
		t.Error("sync without sets produced a script")
	}
}

func TestPortal(t *testing.T) {
	m, _, nft := newManager(t)
	var gotPolicy string
	p := &Portal{
		Cfg: m.Cfg, Host: "play.example.com", Manager: m,
		// Test authenticator: signed in when the X-Test-User header is set.
		Authenticate: func(w http.ResponseWriter, r *http.Request, policy string) (string, bool) {
			gotPolicy = policy
			if u := r.Header.Get("X-Test-User"); u != "" {
				return u, true
			}
			http.Error(w, "sign in", http.StatusUnauthorized)
			return "", false
		},
		ClientIP: func(r *http.Request) string { return r.Header.Get("X-Forwarded-For") },
	}
	do := func(path string, hdr map[string]string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodGet, "http://play.example.com"+path, nil)
		for k, v := range hdr {
			r.Header.Set(k, v)
		}
		w := httptest.NewRecorder()
		p.ServeHTTP(w, r)
		return w
	}

	if w := do("/", nil); !strings.Contains(w.Body.String(), `href="/join/fivem"`) {
		t.Errorf("index = %s", w.Body)
	}
	if w := do("/join/mc", nil); w.Code != http.StatusNotFound {
		t.Errorf("non login-to-play service: %d", w.Code)
	}
	if w := do("/join/fivem", map[string]string{"X-Forwarded-For": "198.51.100.7"}); w.Code != http.StatusUnauthorized || gotPolicy != "friends" {
		t.Errorf("unauthenticated: %d, policy %q", w.Code, gotPolicy)
	}
	if len(nft.scripts) != 0 {
		t.Fatal("unauthenticated request changed nftables")
	}
	if w := do("/join/fivem", map[string]string{"X-Forwarded-For": "2001:db8::1", "X-Test-User": "a@example.com"}); w.Code != http.StatusBadRequest {
		t.Errorf("ipv6 client: %d", w.Code)
	}
	w := do("/join/fivem", map[string]string{"X-Forwarded-For": "198.51.100.7", "X-Test-User": "sam@example.com"})
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "198.51.100.7") {
		t.Fatalf("join: %d %s", w.Code, w.Body)
	}
	es, _ := m.Store.List()
	if len(es) != 1 || es[0].Email != "sam@example.com" || es[0].Expires.Sub(es[0].Added) != 2*time.Hour {
		t.Errorf("entries = %+v", es)
	}
	if len(nft.scripts) != 1 || !strings.Contains(nft.scripts[0], "198.51.100.7 timeout 7200s") {
		t.Errorf("nft = %q", nft.scripts)
	}
}

func TestRefuseAuthenticate(t *testing.T) {
	w := httptest.NewRecorder()
	if _, ok := RefuseAuthenticate(w, httptest.NewRequest(http.MethodGet, "/", nil), "p"); ok || w.Code != http.StatusServiceUnavailable {
		t.Errorf("stub: ok=%v code=%d", ok, w.Code)
	}
}

func TestSnippet(t *testing.T) {
	cfg := testConfig(t)
	for svc, wants := range map[string][]string{
		"fivem":   {"UNVERIFIED", "endpoint_add_udp \"0.0.0.0:30120\"", "sv_listingHostOverride \"203.0.113.10:30120\"", "AllowedIPs = 0.0.0.0/0", "ip rule add from 192.168.0.40"},
		"mc":      {"haproxy-protocol = true", "proxy-protocol: true", "10.100.1.1"},
		"bedrock": {"server-port=19132", "Transparent mode"},
	} {
		s, err := Snippet(cfg, svc)
		if err != nil {
			t.Fatal(err)
		}
		for _, w := range wants {
			if !strings.Contains(s, w) {
				t.Errorf("%s snippet missing %q:\n%s", svc, w, s)
			}
		}
	}
	if _, err := Snippet(cfg, "nope"); err == nil {
		t.Error("unknown service accepted")
	}
}

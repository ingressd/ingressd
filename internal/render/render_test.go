// SPDX-License-Identifier: Apache-2.0

package render

import (
	"encoding/json"
	"flag"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ingressd/ingressd/internal/secrets"
	"github.com/ingressd/ingressd/pkg/config"
)

var update = flag.Bool("update", false, "rewrite golden files")

type fakeKeys struct{}

func (fakeKeys) EdgePrivate(t string) (string, error) { return "EDGE-PRIV-" + t, nil }
func (fakeKeys) SitePublic(t string) (string, error)  { return "SITE-PUB-" + t, nil }

const testConfig = `
version: 1
edge:
  public_ipv4: 203.0.113.10
  acme:
    email: me@example.com
    dns_provider: { type: cloudflare, api_token: secret://cf }
certificates:
  wildcards: ["*.example.com"]
tunnels:
  home:
    site: router
    listen_port: 51820
    transit: 10.100.1.0/24
    subnets: [192.168.0.0/24]
    virtual_prefix: 10.201.0.0/24
  office:
    site: connector
    listen_port: 51821
    transit: 10.100.2.0/24
    subnets: [192.168.0.0/24]
    virtual_prefix: 10.202.0.0/24
pools:
  web:
    steering: weighted
    sticky: { cookie: edge_aff, ttl: 30m }
    origins:
      - { name: a, tunnel: home, address: https://192.168.0.17:8443, weight: 3 }
      - { name: b, tunnel: office, address: https://192.168.0.17:8443, weight: 1 }
      - { name: c, tunnel: office, address: https://192.168.0.18:8443, state: disabled }
      - { name: d, tunnel: home, address: https://192.168.0.19:8443, state: draining, priority: 2 }
apps:
  web:
    hosts: [web.example.com]
    pool: web
    headers: { preset: strict, request: { set: { X-Edge: "1" } } }
    proxy: { max_body: 10MB, timeout: 30s }
  lab:
    hosts: ["*.lab.example.com"]
    origin: http://192.168.0.30:80
    tunnel: home
  site:
    hosts: [example.com, www.example.com]
    origin: http://192.168.0.20:3000
    tunnel: home
    redirects: [{ from: www.example.com, to: example.com }]
    cache: { enabled: true, default_ttl: 10m, stale_if_error: 7d, bypass_paths: [/api/] }
    always_online: { enabled: true, banner: true }
`

func renderTest(t *testing.T) *Plan {
	t.Helper()
	cfg, err := config.Parse([]byte(testConfig))
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	p, err := Render(cfg, secrets.NewMemory(map[string]string{"cf": "CF-TOKEN"}), fakeKeys{},
		Options{AdminListen: "unix//run/ingressd/caddy-admin.sock", StorageDir: "/var/lib/ingressd/caddy", StateDir: "/var/lib/ingressd"})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func golden(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if *update {
		os.MkdirAll("testdata", 0o755)
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run go test ./internal/render -update)", err)
	}
	if string(want) != got {
		t.Errorf("%s differs from golden file (run with -update if intended)\n--- got ---\n%s", name, got)
	}
}

func TestGolden(t *testing.T) {
	p := renderTest(t)
	golden(t, "caddy.json", string(p.Caddy)+"\n")
	golden(t, "rules.nft", p.NFT)
	n, _ := json.MarshalIndent(p.Network, "", "  ")
	golden(t, "network.json", string(n)+"\n")
}

func TestVirtual(t *testing.T) {
	tun := config.Tunnel{Subnets: []string{"192.168.0.0/24"}, VirtualPrefix: "10.201.0.0/24"}
	if got := Virtual(tun, netip.MustParseAddr("192.168.0.17")); got.String() != "10.201.0.17" {
		t.Fatalf("Virtual = %s", got)
	}
	if got := Virtual(tun, netip.MustParseAddr("10.9.9.9")); got.String() != "10.9.9.9" {
		t.Fatalf("address outside subnet changed: %s", got)
	}
	if got := Virtual(config.Tunnel{Subnets: []string{"192.168.0.0/24"}}, netip.MustParseAddr("192.168.0.17")); got.String() != "192.168.0.17" {
		t.Fatalf("unremapped tunnel changed address: %s", got)
	}
}

func TestCaddyStructure(t *testing.T) {
	p := renderTest(t)
	s := string(p.Caddy)
	for _, want := range []string{
		`"dial": "10.201.0.17:8443"`, // home origin remapped
		`"dial": "10.202.0.17:8443"`, // office origin remapped
		`"policy": "edge_tiered"`,
		`"origin": "d"`, // draining origins stay for sticky sessions
		`"state": "draining"`,
		`"ttl": "30m0s"`,
		`"api_token": "CF-TOKEN"`,
		`"max_size": 10485760`,
		`"https://example.com{http.request.uri}"`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("caddy config missing %s", want)
		}
	}
	if strings.Contains(s, "192.168.0.18") {
		t.Error("disabled origin was rendered")
	}
	// Exact hosts must precede the wildcard route.
	if strings.Index(s, `"*.lab.example.com"`) < strings.Index(s, `"web.example.com"`) {
		t.Error("wildcard route rendered before exact host route")
	}
}

// Header names and values are literal text even if validation is bypassed:
// a {file.*} or {env.*} placeholder must reach Caddy escaped.
func TestHeaderOpsEscapePlaceholders(t *testing.T) {
	o := headerOps(map[string]string{"X-{env.A}": "{file./etc/shadow}"}, []string{"{env.B}"})
	got := toJSON(o)
	want := `{"delete":["\\{env.B\\}"],"set":{"X-\\{env.A\\}":["\\{file./etc/shadow\\}"]}}`
	if got != want {
		t.Fatalf("headerOps = %s, want %s", got, want)
	}
}

func TestMissingSecret(t *testing.T) {
	cfg, _ := config.Parse([]byte(testConfig))
	_, err := Render(cfg, secrets.NewMemory(nil), fakeKeys{}, Options{})
	if err == nil || !strings.Contains(err.Error(), `secret "cf" is not set`) {
		t.Fatalf("Render = %v", err)
	}
}

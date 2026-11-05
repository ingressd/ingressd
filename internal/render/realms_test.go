// SPDX-License-Identifier: Apache-2.0

package render

import (
	"encoding/json"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/ingressd/ingressd/internal/auth"
	"github.com/ingressd/ingressd/internal/secrets"
	"github.com/ingressd/ingressd/pkg/config"
)

// realmsConfig puts two tenants with the same LAN (192.168.1.0/24), the
// same origin address and the same app names (apart from the namespace) on
// one node.
const realmsConfig = `
version: 1
edge:
  public_ipv4: 203.0.113.10
  acme: { ca: internal }
security: { tunnel_input: restricted }
realms:
  tq7k2m:
    access: { portal_url: https://auth.ingressd.com/a/tq7k2m, session_key: secret://tq7k2m_session, jwt_key: secret://tq7k2m_jwt }
  tb4x9p:
    access: { portal_url: https://auth.ingressd.com/a/tb4x9p/, session_key: secret://tb4x9p_session, jwt_key: secret://tb4x9p_jwt, revoked_sessions: [s-bob] }
tunnels:
  tq7k2m01: { realm: tq7k2m, table: 1201, site: connector, listen_port: 51820, transit: 10.100.1.0/30, subnets: [192.168.1.0/24], virtual_prefix: 10.0.4.0/24 }
  tb4x9p01: { realm: tb4x9p, table: 1202, site: connector, listen_port: 51821, transit: 10.100.2.0/30, subnets: [192.168.1.0/24], virtual_prefix: 10.0.5.0/24 }
groups:
  tq7k2m.family: { realm: tq7k2m, emails: [alice@example.com] }
  tb4x9p.family: { realm: tb4x9p, emails: [bob@example.org] }
service_tokens:
  tq7k2m.ci: { realm: tq7k2m, client_id: ci-client-1, client_secret: secret://tq7k2m_ci }
policies:
  tq7k2m.family: { realm: tq7k2m, action: allow, include: [{ group: tq7k2m.family }] }
  tq7k2m.ci: { realm: tq7k2m, action: service_auth, include: [{ service_token: tq7k2m.ci }] }
  tb4x9p.family: { realm: tb4x9p, action: allow, include: [{ group: tb4x9p.family }] }
apps:
  tq7k2m.nas: { realm: tq7k2m, hosts: [nas.alice.example], tunnel: tq7k2m01, origin: http://192.168.1.10:5000, access: [tq7k2m.family], paths: [{ match: /ci/*, access: [tq7k2m.ci] }], rate_limit: [{ match: /login, requests: 5, per: 1m }] }
  tb4x9p.nas: { realm: tb4x9p, hosts: [nas.bob.example], tunnel: tb4x9p01, origin: http://192.168.1.10:5000, access: [tb4x9p.family], rate_limit: [{ match: /login, requests: 5, per: 1m }] }
`

var realmSecrets = map[string]string{
	"tq7k2m_session": accessSecrets["access_session_key"],
	"tq7k2m_jwt":     accessSecrets["access_jwt_key"],
	"tq7k2m_ci":      "ci-secret",
	"tb4x9p_session": "ZmVkY2JhOTg3NjU0MzIxMGZlZGNiYTk4NzY1NDMyMTA=",
	"tb4x9p_jwt":     "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgorNCYjwxzg8BiUGJ9dxxPi5KgkhCyHy9a48pErN92xuhRANCAARgyZf9BGbMvrjUARVjEZMCXhU7Q6jI97mgaQV8Cl9NPGYcy0UxSc0CEePyWukFa52kZQEYLNLmU8nEcmfotWVw",
}

func renderRealms(t *testing.T) (*config.Config, *Plan) {
	t.Helper()
	cfg, err := config.Parse([]byte(realmsConfig))
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	p, err := Render(cfg, secrets.NewMemory(realmSecrets), fakeKeys{},
		Options{AdminListen: "unix//run/ingressd/caddy-admin.sock", ControlSocket: "/run/ingressd/control.sock"})
	if err != nil {
		t.Fatal(err)
	}
	return cfg, p
}

// walk calls f for every JSON object below v.
func walk(v any, f func(map[string]any)) {
	switch x := v.(type) {
	case map[string]any:
		f(x)
		for _, c := range x {
			walk(c, f)
		}
	case []any:
		for _, c := range x {
			walk(c, f)
		}
	}
}

// hostRoutes returns the top-level Caddy routes by their first host.
func hostRoutes(t *testing.T, p *Plan) map[string]any {
	t.Helper()
	var root map[string]any
	if err := json.Unmarshal(p.Caddy, &root); err != nil {
		t.Fatal(err)
	}
	routes := root["apps"].(map[string]any)["http"].(map[string]any)["servers"].(map[string]any)["edge"].(map[string]any)["routes"].([]any)
	out := map[string]any{}
	for _, r := range routes {
		m, _ := r.(map[string]any)["match"].([]any)
		if len(m) == 0 {
			continue
		}
		if hosts, ok := m[0].(map[string]any)["host"].([]any); ok && len(hosts) > 0 {
			out[hosts[0].(string)] = r
		}
	}
	return out
}

func TestRealmEdgeAuthUsesRealmAccess(t *testing.T) {
	cfg, p := renderRealms(t)
	routes := hostRoutes(t, p)
	want := map[string]struct{ app, realm, portal, session, jwt string }{
		"nas.alice.example": {"tq7k2m.nas", "tq7k2m", "https://auth.ingressd.com/a/tq7k2m", realmSecrets["tq7k2m_session"], realmSecrets["tq7k2m_jwt"]},
		"nas.bob.example":   {"tb4x9p.nas", "tb4x9p", "https://auth.ingressd.com/a/tb4x9p", realmSecrets["tb4x9p_session"], realmSecrets["tb4x9p_jwt"]},
	}
	for host, w := range want {
		var ea map[string]any
		walk(routes[host], func(o map[string]any) {
			if o["handler"] == "edge_auth" {
				ea = o
			}
		})
		if ea == nil {
			t.Fatalf("%s: no edge_auth handler", host)
		}
		if ea["app"] != w.app || ea["realm"] != w.realm || ea["portal_url"] != w.portal || ea["session_key"] != w.session || ea["jwt_key"] != w.jwt {
			t.Errorf("%s: edge_auth app=%v realm=%v portal=%v, keys from the wrong realm or node", host, ea["app"], ea["realm"], ea["portal_url"])
		}
		for name := range ea["policies"].(map[string]any) {
			if cfg.Policies[name].Realm != w.realm {
				t.Errorf("%s: policy %s of another realm rendered", host, name)
			}
		}
	}
	// Service-token verifiers are keyed by the realm's session key.
	keys, err := auth.LoadRealmKeys(cfg, secrets.NewMemory(realmSecrets), "tq7k2m")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(p.Caddy), keys.ServiceTokenVerifier("ci-secret")) {
		t.Error("service token verifier not derived from the realm's key")
	}
	// Rate-limit zones are process-wide in Caddy: their names must differ.
	if !strings.Contains(string(p.Caddy), `"tq7k2m.nas_0"`) || !strings.Contains(string(p.Caddy), `"tb4x9p.nas_0"`) {
		t.Error("rate-limit zones not named per app")
	}
}

func TestRealmMissingKeyFails(t *testing.T) {
	cfg, _ := config.Parse([]byte(realmsConfig))
	sec := map[string]string{}
	for k, v := range realmSecrets {
		if k != "tb4x9p_session" {
			sec[k] = v
		}
	}
	// Never falls back to the node's keys or another realm's.
	sec["access_session_key"] = accessSecrets["access_session_key"]
	sec["access_jwt_key"] = accessSecrets["access_jwt_key"]
	if _, err := Render(cfg, secrets.NewMemory(sec), fakeKeys{}, Options{}); err == nil || !strings.Contains(err.Error(), "tb4x9p") {
		t.Fatalf("Render = %v, want a missing tb4x9p key error", err)
	}
}

// Without an enrolment endpoint a realms node serves its machine endpoints
// (the control plane's machine host mux) on its public IPv4, with an
// internal-CA certificate, since realms refuse the admin hostname.
func TestRealmMachineHostFallback(t *testing.T) {
	_, p := renderRealms(t)
	var dial string
	walk(hostRoutes(t, p)["203.0.113.10"], func(o map[string]any) {
		if o["handler"] == "reverse_proxy" {
			dial = o["upstreams"].([]any)[0].(map[string]any)["dial"].(string)
		}
	})
	if dial != "unix//run/ingressd/control.sock" {
		t.Errorf("public IPv4 not routed to the control plane: %q", dial)
	}
	var internalIP bool
	var root map[string]any
	_ = json.Unmarshal(p.Caddy, &root)
	walk(root, func(o map[string]any) {
		if s, ok := o["subjects"].([]any); ok && len(s) == 1 && s[0] == "203.0.113.10" {
			internalIP = true
		}
	})
	if !internalIP {
		t.Error("no internal-CA policy for the public IPv4")
	}
}

func TestRealmAppCannotClaimMachineHost(t *testing.T) {
	cfg, _ := renderRealms(t)
	if _, err := Render(cfg, secrets.NewMemory(realmSecrets), fakeKeys{}, Options{MachineHost: "NAS.alice.example"}); err == nil {
		t.Fatal("realm app took over the machine host")
	}
	if _, err := Render(cfg, secrets.NewMemory(realmSecrets), fakeKeys{}, Options{MachineHost: "node1.ingressd.net"}); err != nil {
		t.Fatal(err)
	}
}

func TestRealmsNetworkIsolation(t *testing.T) {
	_, p := renderRealms(t)
	n := p.Network
	for _, r := range n.Routes {
		if r.Dst == "192.168.1.0/24" && r.Table == 0 {
			t.Errorf("real LAN subnet in the main table: %+v", r)
		}
	}
	want := []Route{
		{Dst: "10.0.5.0/24", Dev: "ix-tb4x9p01"},
		{Dst: "192.168.1.0/24", Dev: "ix-tb4x9p01", Table: 1202},
		{Dst: "10.0.4.0/24", Dev: "ix-tq7k2m01"},
		{Dst: "192.168.1.0/24", Dev: "ix-tq7k2m01", Table: 1201},
	}
	if len(n.Routes) != len(want) {
		t.Fatalf("routes %+v", n.Routes)
	}
	for i := range want {
		if n.Routes[i] != want[i] {
			t.Errorf("route %d = %+v, want %+v", i, n.Routes[i], want[i])
		}
	}
	wantRules := []Rule{{Priority: 10202, Mark: 1202, Table: 1202}, {Priority: 10201, Mark: 1201, Table: 1201}}
	if len(n.Rules) != 2 || n.Rules[0] != wantRules[0] || n.Rules[1] != wantRules[1] {
		t.Errorf("rules %+v, want %+v", n.Rules, wantRules)
	}
	golden(t, "realms.nft", p.NFT)
	b, _ := json.MarshalIndent(n, "", "  ")
	golden(t, "realms-network.json", string(b)+"\n")
}

var vprefixMarkRe = regexp.MustCompile(`map vprefix_mark \{[^}]*elements = \{ ([^}]*) \}`)

// TestRealmsOriginIsolation is the render half of the two-tenant isolation
// test: both tenants publish 192.168.1.10:5000 behind an app called nas, yet
// each hostname dials its own virtual address, whose fwmark selects its own
// tunnel's table, which alone routes the real subnet to that tunnel.
func TestRealmsOriginIsolation(t *testing.T) {
	cfg, p := renderRealms(t)
	routes := hostRoutes(t, p)

	marks := map[netip.Prefix]int{}
	m := vprefixMarkRe.FindStringSubmatch(p.NFT)
	if m == nil {
		t.Fatalf("no vprefix_mark map in:\n%s", p.NFT)
	}
	for _, el := range strings.Split(m[1], ", ") {
		k, v, _ := strings.Cut(el, " : ")
		mark, _ := strconv.Atoi(v)
		marks[netip.MustParsePrefix(k)] = mark
	}

	dials := map[string]string{}
	for host, app := range map[string]string{"nas.alice.example": "tq7k2m.nas", "nas.bob.example": "tb4x9p.nas"} {
		var dial []string
		walk(routes[host], func(o map[string]any) {
			if o["handler"] == "reverse_proxy" {
				for _, u := range o["upstreams"].([]any) {
					dial = append(dial, u.(map[string]any)["dial"].(string))
				}
			}
		})
		if len(dial) != 1 {
			t.Fatalf("%s: upstreams %v", host, dial)
		}
		dials[host] = dial[0]

		ap, err := netip.ParseAddrPort(dial[0])
		if err != nil {
			t.Fatal(err)
		}
		tunnel := cfg.Apps[app].Tunnel
		mark := 0
		for pfx, mk := range marks {
			if pfx.Contains(ap.Addr()) {
				mark = mk
			}
		}
		if mark == 0 || mark != cfg.TunnelTable(tunnel) {
			t.Errorf("%s dials %s, marked %d; want the table of tunnel %s (%d)", host, dial[0], mark, tunnel, cfg.TunnelTable(tunnel))
		}
		found := false
		for _, r := range p.Network.Routes {
			if r.Table == mark && r.Dst == "192.168.1.0/24" {
				found = r.Dev == config.InterfaceName(tunnel)
			}
		}
		if !found {
			t.Errorf("%s: table %d does not route the LAN to %s", host, mark, config.InterfaceName(tunnel))
		}
	}
	if dials["nas.alice.example"] != "10.0.4.10:5000" || dials["nas.bob.example"] != "10.0.5.10:5000" {
		t.Errorf("dial addresses %v", dials)
	}
}

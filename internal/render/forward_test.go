// SPDX-License-Identifier: Apache-2.0

package render

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/ingressd/ingressd/internal/secrets"
	"github.com/ingressd/ingressd/pkg/config"
)

// forwardConfig is node A of a PoP pair: its tunnel "home" also exists on
// nod_b and nod_c (in that order of preference), and A accepts forwarded
// requests from them too.
const forwardConfig = `
version: 1
edge:
  acme: { ca: internal }
  forward:
    listen_mesh: true
    secret: secret://forward-hop
    siblings:
      home: [nod_b, nod_c]
tunnels:
  home: { site: router, listen_port: 51820, transit: 10.100.1.0/24, subnets: [192.168.0.0/24] }
  lab: { site: router, listen_port: 51821, transit: 10.100.2.0/24 }
mesh:
  address: 10.255.0.1/16
  peers:
    nod_b: { public_key: "` + sdKey + `", endpoint: "198.51.100.6:51900", address: 10.255.0.2/32 }
    nod_c: { public_key: "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=", endpoint: "198.51.100.10:51900", address: 10.255.0.3/32 }
apps:
  nas: { hosts: [nas.example.com], tunnel: home, origin: https://192.168.0.10:5001 }
  lab: { hosts: [lab.example.com], tunnel: lab, origin: http://192.168.9.9:80 }
  public: { hosts: [www.example.com], origin: http://203.0.113.80:80 }
`

const forwardSecret = "0123456789abcdef0123456789abcdef"

func renderForward(t *testing.T, y string) (*Plan, map[string]any) {
	t.Helper()
	cfg, err := config.Parse([]byte(y))
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	st := secrets.NewMemory(map[string]string{config.MeshKeySecret: "MESH-PRIV", "forward-hop": forwardSecret})
	for k, v := range realmSecrets {
		st.Set(k, v)
	}
	p, err := Render(cfg, st, fakeKeys{}, Options{AdminListen: "unix//run/ingressd/caddy-admin.sock", AccessLogSocket: "/run/ingressd/access.sock"})
	if err != nil {
		t.Fatal(err)
	}
	var root map[string]any
	if err := json.Unmarshal(p.Caddy, &root); err != nil {
		t.Fatal(err)
	}
	return p, root["apps"].(map[string]any)["http"].(map[string]any)["servers"].(map[string]any)
}

func proxiesOf(v any) []map[string]any {
	var out []map[string]any
	walk(v, func(o map[string]any) {
		if o["handler"] == "reverse_proxy" {
			out = append(out, o)
		}
	})
	return out
}

func TestForwardGolden(t *testing.T) {
	p, servers := renderForward(t, forwardConfig)
	edge := servers["edge"].(map[string]any)
	byHost := map[string]any{}
	for _, r := range edge["routes"].([]any) {
		if m, _ := r.(map[string]any)["match"].([]any); len(m) > 0 {
			if h, ok := m[0].(map[string]any)["host"].([]any); ok {
				byHost[h[0].(string)] = r
			}
		}
	}
	nas := proxiesOf(byHost["nas.example.com"])
	if len(nas) != 1 {
		t.Fatalf("nas proxies %v", nas)
	}
	out := map[string]any{"nas_proxy": nas[0], "forward_server": servers[ForwardServer]}
	b, _ := json.MarshalIndent(out, "", "  ")
	golden(t, "forward-caddy.json", string(b)+"\n")

	// Apps without siblings, and direct origins, keep the plain proxy.
	for _, h := range []string{"lab.example.com", "www.example.com"} {
		rp := proxiesOf(byHost[h])[0]
		if rp["transport"].(map[string]any)["protocol"] != "http" || len(rp["upstreams"].([]any)) != 1 {
			t.Errorf("%s is forwarded: %v", h, rp)
		}
	}
	// The forward listener serves tunnelled apps only, never forwards
	// again and keeps no access log (the first node logs and meters).
	fwd := servers[ForwardServer].(map[string]any)
	if _, ok := fwd["logs"]; ok {
		t.Error("forward listener has an access log")
	}
	if _, ok := edge["logs"]; !ok {
		t.Error("edge server lost its access log")
	}
	s, _ := json.Marshal(fwd)
	if strings.Contains(string(s), "www.example.com") || strings.Contains(string(s), "203.0.113.80") {
		t.Error("forward listener routes a direct origin")
	}
	for _, rp := range proxiesOf(fwd) {
		if len(rp["upstreams"].([]any)) != 1 || strings.Contains(string(mustJSON(rp)), "51880") {
			t.Errorf("forward listener route forwards again: %v", rp)
		}
	}

	for _, want := range []string{
		`iifname "ix-mesh" ip saddr { 10.255.0.2, 10.255.0.3 } tcp dport 51880 accept`,
	} {
		if !strings.Contains(p.NFT, want) {
			t.Errorf("nft lacks %q:\n%s", want, p.NFT)
		}
	}
}

func mustJSON(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}

func TestForwardWithoutListenerOrSiblings(t *testing.T) {
	y := strings.Replace(forwardConfig, "    listen_mesh: true\n", "", 1)
	p, servers := renderForward(t, y)
	if _, ok := servers[ForwardServer]; ok {
		t.Error("forward listener rendered without listen_mesh")
	}
	if strings.Contains(p.NFT, "51880") {
		t.Errorf("forward port opened without listen_mesh:\n%s", p.NFT)
	}
}

// With realms, the forward listener routes each app only to its own realm's
// tunnel (the app key names it), and the restricted output chain lets the
// unprivileged proxy reach the siblings' forward listeners, nothing else on
// the mesh.
func TestForwardRealms(t *testing.T) {
	y := strings.Replace(realmsConfig, "security: { tunnel_input: restricted }\n", `security: { tunnel_input: restricted }
mesh:
  address: 10.255.0.1/16
  peers:
    nod_b: { public_key: "`+sdKey+`", endpoint: "198.51.100.6:51900", address: 10.255.0.2/32 }
`, 1)
	y = strings.Replace(y, "  acme: { ca: internal }\n", "  acme: { ca: internal }\n  forward: { listen_mesh: true, secret: secret://forward-hop, siblings: { tq7k2m01: [nod_b], tb4x9p01: [nod_b] } }\n", 1)
	p, servers := renderForward(t, y)
	fwd := servers[ForwardServer].(map[string]any)
	dials := map[string]string{}
	for _, r := range fwd["routes"].([]any) {
		m, _ := r.(map[string]any)["match"].([]any)
		if len(m) == 0 {
			continue
		}
		app := m[0].(map[string]any)["vars"].(map[string]any)["edge_forward_app"].([]any)[0].(string)
		rps := proxiesOf(r)
		ups := rps[0]["upstreams"].([]any)
		if len(rps) != 1 || len(ups) != 1 {
			t.Fatalf("%s: %v", app, rps)
		}
		dials[app] = ups[0].(map[string]any)["dial"].(string)
	}
	if dials["tq7k2m.nas"] != "10.0.4.10:5000" || dials["tb4x9p.nas"] != "10.0.5.10:5000" || len(dials) != 2 {
		t.Errorf("forward listener dials %v", dials)
	}
	for _, want := range []string{
		"ip daddr { 10.255.0.2 } tcp dport 51880 accept\n\t\tmeta skuid != 0 meta l4proto tcp ip daddr { 169.254.0.0/16, 10.255.0.0/16 } drop",
		`iifname "ix-mesh" ip saddr { 10.255.0.2 } tcp dport 51880 accept`,
	} {
		if !strings.Contains(p.NFT, want) {
			t.Errorf("nft lacks %q:\n%s", want, p.NFT)
		}
	}
	// edge_auth still guards realm apps on the first node.
	if !strings.Contains(string(mustJSON(servers["edge"])), `"handler":"edge_auth"`) {
		t.Error("edge_auth missing from the edge server")
	}
	if strings.Contains(string(mustJSON(fwd)), "edge_auth") {
		t.Error("forward listener runs edge_auth again")
	}
}

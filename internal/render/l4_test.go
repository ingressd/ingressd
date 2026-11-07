// SPDX-License-Identifier: Apache-2.0

package render

import (
	"strings"
	"testing"

	"github.com/ingressd/ingressd/internal/secrets"
	"github.com/ingressd/ingressd/pkg/config"
)

const l4TestConfig = `
version: 1
edge:
  public_ipv4: 203.0.113.10
  admin: { hostname: edge.example.com }
  acme: { ca: internal }
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
  lab:
    site: router
    listen_port: 51822
    transit: 10.100.3.0/24
    subnets: [192.168.50.0/24]
l4:
  fivem:
    preset: fivem
    target: { tunnel: home, address: 192.168.0.40 }
    access: login_to_play
    allowlist: [198.51.100.0/24]
    login_to_play: { policy: friends, ttl: 6h, portal_host: play.example.com }
    limits: { conn_per_ip: 20, new_conn_rate: 30/s }
  minecraft:
    preset: minecraft_java
    target: { tunnel: office, address: 192.168.0.41 }
  game-x:
    listen: [7777/udp, 7778/tcp]
    target: { tunnel: lab, address: 192.168.50.9, port: 9000 }
    access: allowlist
`

func renderL4Test(t *testing.T) *Plan {
	t.Helper()
	cfg, err := config.Parse([]byte(l4TestConfig))
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	p, err := Render(cfg, secrets.NewMemory(nil), fakeKeys{},
		Options{AdminListen: "unix//run/ingressd/caddy-admin.sock", ControlSocket: "/run/ingressd/control.sock"})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestL4Golden(t *testing.T) {
	p := renderL4Test(t)
	golden(t, "l4.nft", p.NFT)
	golden(t, "l4-caddy.json", string(p.Caddy)+"\n")
}

func TestL4Structure(t *testing.T) {
	p := renderL4Test(t)
	for _, want := range []string{
		// Kernel path: remapped target gets the tunnel's fwmark and is
		// DNATed to the real address; proxy mode masquerades, transparent not.
		"fib daddr type local udp dport 30120 meta mark set 1000",
		"fib daddr type local udp dport 30120 dnat to 192.168.0.40:30120",
		"fib daddr type local tcp dport 7778 dnat to 192.168.50.9:9000",
		`oifname "ix-lab" ip daddr 192.168.50.9 meta l4proto udp ct original proto-dst 7777 ct status dnat masquerade`,
		// Forward chain accepts exactly the DNATed flows.
		`oifname "ix-home" ip daddr 192.168.0.40 tcp dport 30120 ct status dnat accept`,
		// caddy-l4 port is opened in input.
		"tcp dport { 22, 80, 443, 25565 } accept",
		"set svc_fivem_allow {",
		"set svc_game_x_allow {",
		"elements = { 198.51.100.0/24 }",
		"add @svc_fivem_conn { ip saddr ct count over 20 } drop",
		"update @svc_fivem_rate { ip saddr limit rate over 30/second } drop",
	} {
		if !strings.Contains(p.NFT, want) {
			t.Errorf("nft missing %q", want)
		}
	}
	if strings.Contains(p.NFT, `"ix-home" ip daddr 192.168.0.40 meta l4proto tcp ct original proto-dst 30120`) {
		t.Error("transparent service is masqueraded")
	}
	if strings.Contains(p.NFT, "dport 25565 dnat") {
		t.Error("caddy-l4 service is DNATed")
	}
	if !p.Network.IPForward {
		t.Error("ip_forward not enabled")
	}
	s := string(p.Caddy)
	for _, want := range []string{`"layer4"`, `"proxy_protocol": "v2"`, `"10.202.0.41:25565"`, `"tcp/:25565"`, `"play.example.com"`} {
		if !strings.Contains(s, want) {
			t.Errorf("caddy missing %s", want)
		}
	}
}

func TestNoL4(t *testing.T) {
	p := renderTest(t)
	if strings.Contains(p.NFT, "table ip ingressd_l4 {") || strings.Contains(string(p.Caddy), "layer4") || p.Network.IPForward {
		t.Error("L4 state rendered without l4 services")
	}
}

func TestExtraInputTCP(t *testing.T) {
	cfg := &config.Config{}
	cfg.Edge.SSHPort = 22
	got := renderNFT(cfg, []int{8443, 443}, []int{53})
	if !strings.Contains(got, "tcp dport { 22, 80, 443, 8443 } accept") || !strings.Contains(got, "udp dport { 53, 443 } accept") {
		t.Errorf("extra ports not opened once:\n%s", got)
	}
}

func TestL4ListenerFamily(t *testing.T) {
	cfg := &config.Config{L4: map[string]config.L4Service{
		"open":   {ProxyProtocol: "v2", Target: config.L4Target{Tunnel: "t", Address: "10.0.0.1"}, Listen: []string{"25565/tcp"}},
		"closed": {ProxyProtocol: "v2", Target: config.L4Target{Tunnel: "t", Address: "10.0.0.1"}, Listen: []string{"25566/tcp"}, Access: config.L4AccessAllowlist},
		"login":  {ProxyProtocol: "v2", Target: config.L4Target{Tunnel: "t", Address: "10.0.0.1"}, Listen: []string{"25567/tcp"}, Access: config.L4AccessLoginToPlay},
		"capped": {ProxyProtocol: "v2", Target: config.L4Target{Tunnel: "t", Address: "10.0.0.1"}, Listen: []string{"25568/tcp"}, Limits: &config.L4Limits{}},
	}}
	servers := l4CaddyApp(cfg)["servers"].(obj)
	for name, want := range map[string]string{
		"l4_open_25565":   "tcp/:25565",
		"l4_closed_25566": "tcp4/:25566",
		"l4_login_25567":  "tcp4/:25567",
		"l4_capped_25568": "tcp4/:25568",
	} {
		if got := servers[name].(obj)["listen"].([]string)[0]; got != want {
			t.Errorf("%s listens on %s, want %s", name, got, want)
		}
	}
}

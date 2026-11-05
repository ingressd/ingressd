// SPDX-License-Identifier: Apache-2.0

package render

import (
	"strings"
	"testing"

	"github.com/ingressd/ingressd/internal/secrets"
	"github.com/ingressd/ingressd/pkg/config"
)

const sdKey = "eEvqkSJVw/7cGUEcJXmeHiNFDLBGOz8GpScshecvNHU="

const sdConfig = `
version: 1
tunnels:
  home: { site: router, listen_port: 51820, transit: 10.100.1.0/24 }
mesh:
  address: 10.255.0.1/16
  peers:
    nod_nl: { public_key: "` + sdKey + `", endpoint: "198.51.100.6:51900", address: 10.255.0.2/32 }
smartdns:
  enabled: true
  listen: [10.100.1.1, 192.168.1.5]
  exits:
    nl: { node: nod_nl, country: NL }
    gb: { node: self, country: GB, vpn: "secret://proton-gb" }
  services:
    streamtv: { domains: [stream.example], exit: nl }
`

const sdVPN = "[Interface]\nPrivateKey = " + sdKey + "\nAddress = 10.2.0.2/32\nDNS = 10.2.0.1\nMTU = 1380\n[Peer]\nPublicKey = " + sdKey + "\nEndpoint = 203.0.113.9:51820\nAllowedIPs = 0.0.0.0/0\n"

func TestRenderSmartDNS(t *testing.T) {
	cfg, err := config.Parse([]byte(sdConfig))
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	st := secrets.NewMemory(map[string]string{config.MeshKeySecret: "MESH-PRIV", "proton-gb": sdVPN, VPNKeySecret("gb"): "VPN-PRIV"})
	p, err := Render(cfg, st, fakeKeys{}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	n := p.Network
	if len(n.Interfaces) != 3 {
		t.Fatalf("interfaces %+v", n.Interfaces)
	}
	mesh := n.Interfaces[1]
	if mesh.Name != "ix-mesh" || mesh.Address != "10.255.0.1/16" || mesh.ListenPort != 51900 || mesh.PrivateKey != "MESH-PRIV" ||
		len(mesh.Peers) != 1 || mesh.Peers[0].Endpoint != "198.51.100.6:51900" || mesh.Peers[0].AllowedIPs[0] != "10.255.0.2/32" || mesh.Peers[0].Keepalive != 25 {
		t.Errorf("mesh %+v", mesh)
	}
	vpn := n.Interfaces[2]
	if vpn.Name != "ix-x-gb" || vpn.Address != "10.2.0.2/32" || vpn.MTU != 1380 || vpn.PrivateKey != "VPN-PRIV" || vpn.Peers[0].Endpoint != "203.0.113.9:51820" {
		t.Errorf("vpn %+v", vpn)
	}
	if len(n.Routes) != 2 || n.Routes[0].Table != VPNTableBase || n.Routes[0].Dev != "ix-x-gb" {
		t.Errorf("routes %+v", n.Routes)
	}
	if len(n.Rules) != 1 || n.Rules[0] != (Rule{Priority: VPNRulePriorityBase, Mark: VPNTableBase, Table: VPNTableBase}) {
		t.Errorf("rules %+v", n.Rules)
	}
	if mark, ok := VPNMark(cfg, "gb"); !ok || mark != VPNTableBase {
		t.Errorf("mark %d %v", mark, ok)
	}
	for _, want := range []string{
		"udp dport { 443, 51820, 51900 } accept",
		`iifname "ix-mesh" ip saddr { 10.255.0.2 } tcp dport { 51901, 51902 } accept`,
		`iifname "ix-home" ip daddr 10.100.1.1 meta l4proto { tcp, udp } th dport 53 accept`,
		`iifname "ix-home" ip daddr 10.100.1.1 tcp dport { 51080, 51443 } accept`,
		"ip saddr { 10.0.0.0/8, 100.64.0.0/10, 172.16.0.0/12, 192.168.0.0/16 } ip daddr 192.168.1.5 meta l4proto { tcp, udp } th dport 53 accept",
		"ip daddr 10.100.1.1 tcp dport 443 dnat to 10.100.1.1:51443",
		"ip daddr 192.168.1.5 tcp dport 80 dnat to 192.168.1.5:51080",
	} {
		if !strings.Contains(p.NFT, want) {
			t.Errorf("nft lacks %q:\n%s", want, p.NFT)
		}
	}
	if strings.Contains(p.NFT, "203.0.113") {
		t.Error("public address in smartdns rules")
	}

	// Without the mesh key the render fails loudly.
	if _, err := Render(cfg, secrets.NewMemory(nil), fakeKeys{}, Options{}); err == nil {
		t.Error("rendered without the mesh key")
	}
}

// One node hosting several VPN exits: each gets its own interface, routing
// table and fwmark rule, and none of them touches the main table (the
// node's own default route).
func TestRenderSeveralVPNExits(t *testing.T) {
	y := strings.Replace(sdConfig, `    gb: { node: self, country: GB, vpn: "secret://proton-gb" }`,
		`    gb: { node: self, country: GB, vpn: "secret://proton-gb" }
    mullvad-sweden: { node: self, country: SE, vpn: "secret://vpn-mullvad" }`, 1)
	cfg, err := config.Parse([]byte(y))
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	mullvad := "[Interface]\nPrivateKey = " + sdKey + "\nAddress = 10.64.1.2/32, fc00:bbbb::2/128\nDNS = 10.64.0.1\n[Peer]\nPublicKey = " + sdKey +
		"\nEndpoint = 203.0.113.70:51820\nAllowedIPs = 0.0.0.0/0, ::/0\nPersistentKeepalive = 15\n"
	st := secrets.NewMemory(map[string]string{
		config.MeshKeySecret: "MESH-PRIV", "proton-gb": sdVPN, VPNKeySecret("gb"): "VPN-PRIV",
		"vpn-mullvad": mullvad, VPNKeySecret("mullvad-sweden"): "VPN-PRIV-2",
	})
	p, err := Render(cfg, st, fakeKeys{}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	n := p.Network
	if len(n.Interfaces) != 4 {
		t.Fatalf("interfaces %+v", n.Interfaces)
	}
	gb, mv := n.Interfaces[2], n.Interfaces[3] // VPN exits in name order
	mvIf := config.VPNInterfaceName("mullvad-sweden")
	if gb.Name != "ix-x-gb" || gb.Peers[0].Keepalive != 25 {
		t.Errorf("gb %+v", gb)
	}
	if mv.Name != mvIf || len(mvIf) > 15 || mv.Address != "10.64.1.2/32" || mv.PrivateKey != "VPN-PRIV-2" ||
		mv.Peers[0].Keepalive != 15 || strings.Join(mv.Peers[0].AllowedIPs, ",") != "0.0.0.0/0" {
		t.Errorf("mullvad %+v", mv)
	}
	tables := map[int]string{}
	for _, r := range n.Routes {
		if r.Table == 0 {
			t.Errorf("route in the main table: %+v", r)
		}
		if o, ok := tables[r.Table]; ok && o != r.Dev {
			t.Errorf("table %d shared by %s and %s", r.Table, o, r.Dev)
		}
		tables[r.Table] = r.Dev
	}
	if tables[VPNTableBase] != "ix-x-gb" || tables[VPNTableBase+1] != mvIf {
		t.Errorf("tables %v", tables)
	}
	if len(n.Rules) != 2 || n.Rules[0].Mark == n.Rules[1].Mark {
		t.Errorf("rules %+v", n.Rules)
	}
}

// Per-realm Smart DNS: each realm's resolver is reachable only on its own
// tunnel's transit address, and realm VPN exits use their explicit tables.
func TestRenderRealmSmartDNS(t *testing.T) {
	y := strings.NewReplacer(
		"security: { tunnel_input: restricted }\n", "security: { tunnel_input: restricted }\nmesh:\n  address: 10.255.0.1/16\n",
		"jwt_key: secret://tq7k2m_jwt }\n", `jwt_key: secret://tq7k2m_jwt }
    smartdns:
      enabled: true
      exits: { tq7k2m.gb: { node: self, country: GB, vpn: "secret://tq7k2m-gb", table: 1907 } }
      services: { tq7k2m.tv: { domains: [stream.example], exit: tq7k2m.gb } }
`,
		"revoked_sessions: [s-bob] }\n", `revoked_sessions: [s-bob] }
    smartdns:
      enabled: true
      exits: { tb4x9p.gb: { node: self, country: GB, vpn: "secret://tb4x9p-gb", table: 1903 } }
      services: { tb4x9p.tv: { domains: [stream.example], exit: tb4x9p.gb } }
`).Replace(realmsConfig)
	cfg, err := config.Parse([]byte(y))
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	st := secrets.NewMemory(map[string]string{config.MeshKeySecret: "MESH-PRIV", "tq7k2m-gb": sdVPN, "tb4x9p-gb": sdVPN,
		VPNKeySecret("tq7k2m.gb"): "VPN-A", VPNKeySecret("tb4x9p.gb"): "VPN-B"})
	for k, v := range realmSecrets {
		st.Set(k, v)
	}
	p, err := Render(cfg, st, fakeKeys{}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`iifname "ix-tq7k2m01" ip daddr 10.100.1.1 meta l4proto { tcp, udp } th dport 53 accept`,
		`iifname "ix-tb4x9p01" ip daddr 10.100.2.1 meta l4proto { tcp, udp } th dport 53 accept`,
		"ip daddr 10.100.1.1 tcp dport 443 dnat to 10.100.1.1:51443",
		"ip daddr 10.100.2.1 tcp dport 443 dnat to 10.100.2.1:51443",
	} {
		if !strings.Contains(p.NFT, want) {
			t.Errorf("nft lacks %q:\n%s", want, p.NFT)
		}
	}
	for _, bad := range []string{`iifname "ix-tq7k2m01" ip daddr 10.100.2.1`, `iifname "ix-tb4x9p01" ip daddr 10.100.1.1`} {
		if strings.Contains(p.NFT, bad) {
			t.Errorf("nft lets one realm's tunnel reach the other's resolver: %q", bad)
		}
	}
	rules := map[int]Rule{}
	for _, r := range p.Network.Rules {
		rules[r.Table] = r
	}
	if r := rules[1903]; r.Priority != VPNRulePriorityBase+3 || r.Mark != 1903 {
		t.Errorf("tb4x9p.gb rule %+v", r)
	}
	if r := rules[1907]; r.Priority != VPNRulePriorityBase+7 || r.Mark != 1907 {
		t.Errorf("tq7k2m.gb rule %+v", r)
	}
	if m, _ := VPNMark(cfg, "tq7k2m.gb"); m != 1907 {
		t.Errorf("VPNMark = %d", m)
	}
}

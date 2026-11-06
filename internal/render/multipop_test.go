// SPDX-License-Identifier: Apache-2.0

package render

import (
	"strings"
	"testing"

	"github.com/ingressd/ingressd/internal/secrets"
	"github.com/ingressd/ingressd/pkg/config"
)

// A multi-PoP attachment: a /30 from 100.64.0.0/10 (edge .1, site .2),
// siblings that this node never configures.
const multiPopConfig = `
version: 1
tunnels:
  home:
    site: connector
    listen_port: 51823
    transit: 100.64.0.4/30
    fallback_ws: true
    siblings:
      - { node: nod_b, endpoint: "node-b.example.net:51822", edge_public_key: "` + sdKey + `", transit: 100.64.0.8/30 }
  lab: { site: router, listen_port: 51824, transit: 100.64.0.68/30 }
`

func TestRenderMultiPopTransit(t *testing.T) {
	cfg, err := config.Parse([]byte(multiPopConfig))
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	p, err := Render(cfg, secrets.NewMemory(nil), fakeKeys{}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	n := p.Network
	if len(n.Interfaces) != 2 {
		t.Fatalf("interfaces %+v", n.Interfaces)
	}
	home := n.Interfaces[0]
	if home.Name != "ix-home" || home.Address != "100.64.0.5/30" || home.ListenPort != 51823 ||
		len(home.Peers) != 1 || home.Peers[0].AllowedIPs[0] != "100.64.0.6/32" {
		t.Errorf("home %+v", home)
	}
	if lab := n.Interfaces[1]; lab.Address != "100.64.0.69/30" || lab.Peers[0].AllowedIPs[0] != "100.64.0.70/32" {
		t.Errorf("lab %+v", lab)
	}
	for _, want := range []string{
		"udp dport { 443, 51823, 51824 } accept",
		`iifname "ix-home" ip saddr 100.64.0.6 ip daddr 100.64.0.5 tcp dport 51819 accept`,
	} {
		if !strings.Contains(p.NFT, want) {
			t.Errorf("nft lacks %q:\n%s", want, p.NFT)
		}
	}
	if strings.Contains(p.NFT, "100.64.0.8") || strings.Contains(p.NFT, "100.64.0.9") {
		t.Error("sibling transit leaked into this node's firewall")
	}
	if strings.Contains(p.NFT, `iifname "ix-lab" ip saddr`) {
		t.Error("router tunnel got the connector control rule")
	}
}

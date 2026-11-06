// SPDX-License-Identifier: Apache-2.0

package render

import (
	"strings"
	"testing"

	"github.com/ingressd/ingressd/internal/secrets"
	"github.com/ingressd/ingressd/pkg/config"
)

const sdKey = "eEvqkSJVw/7cGUEcJXmeHiNFDLBGOz8GpScshecvNHU="

// A node exit for the connector site home; away is a connector site that
// may not use it and udm a router site.
const sdConfig = `
version: 1
tunnels:
  home: { site: connector, listen_port: 51820, transit: 10.100.1.0/30, smartdns: '{"site":"home"}' }
  away: { site: connector, listen_port: 51821, transit: 10.100.2.0/30 }
  udm: { site: router, listen_port: 51822, transit: 10.100.3.0/30 }
mesh:
  address: 10.255.0.1/16
  peers:
    nod_nl: { public_key: "` + sdKey + `", endpoint: "198.51.100.6:51900", address: 10.255.0.2/32 }
smartdns:
  exit: { country: NL, sites: [home] }
`

func TestRenderSmartDNSNodeExit(t *testing.T) {
	cfg, err := config.Parse([]byte(sdConfig))
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	p, err := Render(cfg, secrets.NewMemory(map[string]string{config.MeshKeySecret: "MESH-PRIV"}), fakeKeys{}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	for _, ifc := range p.Network.Interfaces {
		if strings.HasPrefix(ifc.Name, "ix-x-") {
			t.Errorf("node rendered a VPN interface %s", ifc.Name)
		}
	}
	if len(p.Network.Rules) != 0 {
		t.Errorf("node exit added policy rules %+v", p.Network.Rules)
	}
	for _, want := range []string{
		`iifname "ix-home" ip saddr 10.100.1.2 ip daddr 10.100.1.1 tcp dport { 51901, 51902 } accept`,
		`iifname "ix-mesh" ip saddr { 10.255.0.2 } tcp dport 51901 accept`,
		"add table ip ingressd_smartdns\ndelete table ip ingressd_smartdns\n",
	} {
		if !strings.Contains(p.NFT, want) {
			t.Errorf("nft lacks %q:\n%s", want, p.NFT)
		}
	}
	for _, bad := range []string{`"ix-away" ip saddr 10.100.2.2 ip daddr 10.100.2.1 tcp dport { 51901`, "th dport 53", "51443", "dnat to"} {
		if strings.Contains(p.NFT, bad) {
			t.Errorf("nft contains %q", bad)
		}
	}
}

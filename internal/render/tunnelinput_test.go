// SPDX-License-Identifier: Apache-2.0

package render

import (
	"strings"
	"testing"

	"github.com/ingressd/ingressd/pkg/config"
)

func TestTunnelInputRestrictedGolden(t *testing.T) {
	cfg, err := config.Parse([]byte(testConfig + "security: { tunnel_input: restricted, edge_output_deny: [10.10.0.0/16, \"fd12:3456::/48\"] }\n"))
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	golden(t, "rules-restricted.nft", renderNFT(cfg, nil, nil))

	// Smart DNS on a transit address stays reachable from its own tunnel
	// only; LAN listen addresses and mesh rules come after the tunnel drop.
	sd, err := config.Parse([]byte(sdConfig + "security: { tunnel_input: restricted }\n"))
	if err != nil {
		t.Fatal(err)
	}
	if err := sd.Validate(); err != nil {
		t.Fatal(err)
	}
	s := renderNFT(sd, nil, nil)
	golden(t, "smartdns-restricted.nft", s)
	drop := strings.Index(s, `iifname { "ix-home" } drop`)
	if transit := strings.Index(s, `iifname "ix-home" ip daddr 10.100.1.1 meta l4proto { tcp, udp } th dport 53 accept`); transit < 0 || transit > drop {
		t.Error("transit resolver rule missing or after the tunnel drop")
	}
	if lan := strings.Index(s, `ip daddr 192.168.1.5 meta l4proto`); lan < drop {
		t.Error("LAN listen rule before the tunnel drop")
	}
	if !strings.Contains(s, "meta skuid != 0 meta l4proto tcp ip daddr { 169.254.0.0/16, 10.255.0.0/16 } drop") ||
		!strings.Contains(s, "meta skuid != 0 meta l4proto tcp ip6 daddr { fd00:ec2::254/128 } drop") {
		t.Error("output denylist misses metadata or the mesh")
	}
}

func TestTunnelInputOpenUnchanged(t *testing.T) {
	cfg, err := config.Parse([]byte(testConfig + "security: { tunnel_input: open }\n"))
	if err != nil {
		t.Fatal(err)
	}
	if got := renderNFT(cfg, nil, nil); got != renderTest(t).NFT {
		t.Error("tunnel_input: open renders differently from the default")
	}
}

func TestExplicitTunnelTables(t *testing.T) {
	cfg, err := config.Parse([]byte(strings.Replace(testConfig, "    virtual_prefix: 10.202.0.0/24", "    virtual_prefix: 10.202.0.0/24\n    table: 1700", 1)))
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	n, err := renderNetwork(cfg, fakeKeys{})
	if err != nil {
		t.Fatal(err)
	}
	want := []Rule{{Priority: 10000, Mark: 1000, Table: 1000}, {Priority: 10700, Mark: 1700, Table: 1700}}
	if len(n.Rules) != 2 || n.Rules[0] != want[0] || n.Rules[1] != want[1] {
		t.Errorf("rules %+v, want %+v", n.Rules, want)
	}
	if !strings.Contains(renderNFT(cfg, nil, nil), "10.202.0.0/24 : 1700") {
		t.Error("explicit table not used as the fwmark")
	}
	if VPNRulePriorityBase <= TunnelRulePriority(config.TunnelTableMax) || VPNTableBase != config.TunnelTableMax+1 {
		t.Error("tunnel tables or rules overlap the VPN exits' range")
	}
}

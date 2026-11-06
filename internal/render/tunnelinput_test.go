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

	// The node exit API stays reachable from its own site only, before the
	// tunnel drop; mesh rules come after it.
	sd, err := config.Parse([]byte(sdConfig + "security: { tunnel_input: restricted }\n"))
	if err != nil {
		t.Fatal(err)
	}
	if err := sd.Validate(); err != nil {
		t.Fatal(err)
	}
	s := renderNFT(sd, nil, nil)
	golden(t, "smartdns-restricted.nft", s)
	drop := strings.Index(s, `iifname { "ix-away", "ix-home", "ix-udm" } drop`)
	if exit := strings.Index(s, `iifname "ix-home" ip saddr 10.100.1.2 ip daddr 10.100.1.1 tcp dport { 51901, 51902 } accept`); exit < 0 || exit > drop {
		t.Error("exit API rule missing or after the tunnel drop")
	}
	if mesh := strings.Index(s, `iifname "ix-mesh"`); mesh < drop {
		t.Error("mesh rule before the tunnel drop")
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
}

func TestSSHAllow(t *testing.T) {
	cfg, err := config.Parse([]byte(testConfig + "security: { tunnel_input: restricted, ssh_allow: [203.0.113.7/32, \"2001:db8::/48\"] }\n"))
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	nft := renderNFT(cfg, []int{22}, nil)
	for _, want := range []string{
		"ip saddr { 203.0.113.7/32 } tcp dport 22 accept\n",
		"ip6 saddr { 2001:db8::/48 } tcp dport 22 accept\n",
	} {
		if !strings.Contains(nft, want) {
			t.Errorf("missing %q in:\n%s", want, nft)
		}
	}
	if strings.Contains(nft, "tcp dport { 22") || strings.Contains(nft, " 22, ") {
		t.Errorf("SSH still open to everyone:\n%s", nft)
	}
	if drop, ssh := strings.Index(nft, "iifname {"), strings.Index(nft, "ip saddr { 203"); drop < 0 || ssh < drop {
		t.Errorf("the allowlist must follow the tunnel drop:\n%s", nft)
	}

	// One family listed: the other has no SSH at all.
	cfg.Security.SSHAllow = []string{"203.0.113.7/32"}
	if nft := renderNFT(cfg, nil, nil); strings.Contains(nft, "ip6 saddr") {
		t.Errorf("IPv6 rule without an IPv6 network:\n%s", nft)
	}

	cfg.Security.SSHAllow = nil
	if nft := renderNFT(cfg, nil, nil); !strings.Contains(nft, "tcp dport { 22, ") {
		t.Errorf("no allowlist must leave SSH open:\n%s", nft)
	}
}

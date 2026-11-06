// SPDX-License-Identifier: Apache-2.0

package client

import (
	"strings"
	"testing"

	"github.com/ingressd/ingressd/internal/connector/proto"
)

func TestParseTransparent(t *testing.T) {
	got, err := parseTransparent([]string{"tcp/192.168.0.17:25565", "udp/192.168.0.18:30120"})
	if err != nil || len(got) != 2 || got[0].addr.Port() != 25565 || got[1].proto != 17 {
		t.Fatalf("got %+v, %v", got, err)
	}
	for _, bad := range []string{"192.168.0.17:1", "icmp/192.168.0.17:1", "tcp/[::1]:1", "tcp/host:1"} {
		if _, err := parseTransparent([]string{bad}); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	got, err = parseTransparent([]string{"bad", "udp/192.168.0.18:30120"})
	if err == nil || len(got) != 1 || got[0].proto != 17 {
		t.Errorf("mixed list: %+v, %v", got, err)
	}
}

func TestNFTScript(t *testing.T) {
	st := &State{Masquerade: true, Edges: []EdgeState{
		{Config: proto.TunnelConfig{Address: "10.100.1.2/24"}},
		{Config: proto.TunnelConfig{Address: "100.64.0.10/30"}},
	}}
	s := nftScript("ingressd0", st, 1280)
	for _, want := range []string{
		"add table ip ingressd_connector\ndelete table ip ingressd_connector\n",
		`oifname "ingressd0" tcp flags syn tcp option maxseg size > 1240 tcp option maxseg size set 1240`,
		`ip saddr { 10.100.1.0/30, 100.64.0.8/30 } oifname != "ingressd0" masquerade`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("script lacks %q:\n%s", want, s)
		}
	}
	if s := nftScript("ingressd0", &State{}, 1420); strings.Contains(s, "masquerade") {
		t.Error("masquerade without --masquerade")
	}
}

func TestNFTTunnelFilter(t *testing.T) {
	st := &State{reach: reachOf("0.0.0.0/0", "::/0"), Edges: []EdgeState{{Config: proto.TunnelConfig{
		Subnets:     []string{"192.168.1.0/24", "192.168.1.5/32", "10.0.0.9/32", "fd00::/64"},
		Transparent: []string{"tcp/172.16.0.4:25565"},
	}}}}
	s := nftScript("ingressd0", st, 1420)
	set := "ip daddr != { 192.168.1.0/24, 10.0.0.9/32, 172.16.0.4/32 }"
	for _, want := range []string{
		`iifname "ingressd0" ` + set + " drop",
		`iifname "ingressd0" ip protocol != icmp ct state new ` + set + " drop",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("script lacks %q:\n%s", want, s)
		}
	}
	if strings.Index(s, "drop") > strings.Index(s, "maxseg") {
		t.Errorf("filter after the MSS rules:\n%s", s)
	}

	// A site with nothing to reach forwards nothing.
	s = nftScript("ingressd0", &State{}, 1420)
	if !strings.Contains(s, "\t\tiifname \"ingressd0\" drop\n") || !strings.Contains(s, `ip protocol != icmp ct state new drop`) {
		t.Errorf("empty site:\n%s", s)
	}

	// A subnet of everything leaves nothing to filter.
	st.Edges[0].Config.Subnets = []string{"0.0.0.0/0"}
	if s = nftScript("ingressd0", st, 1420); strings.Contains(s, "drop") {
		t.Errorf("default route:\n%s", s)
	}

	// The local allowlist decides, whatever the edge asks for.
	st.reach = reachOf("192.168.1.0/24")
	s = nftScript("ingressd0", st, 1420)
	if !strings.Contains(s, "ip daddr != { 192.168.1.0/24 } drop") {
		t.Errorf("edge asks for everything:\n%s", s)
	}
	st.Edges[0].Config.Subnets = []string{"192.168.0.0/16"}
	if s = nftScript("ingressd0", st, 1420); !strings.Contains(s, "ip daddr != { 192.168.1.0/24 } drop") {
		t.Errorf("edge asks for a wider network:\n%s", s)
	}
	st.reach = nil
	if s = nftScript("ingressd0", st, 1420); !strings.Contains(s, "\t\tiifname \"ingressd0\" drop\n") {
		t.Errorf("no list in effect:\n%s", s)
	}

	if s = nftRules("ingressd0", &State{Masquerade: true, Edges: []EdgeState{{Config: proto.TunnelConfig{Address: "100.64.0.6/30"}}}}, 1420, false); strings.Contains(s, "drop") || !strings.Contains(s, "masquerade") {
		t.Errorf("without the filter:\n%s", s)
	}
}

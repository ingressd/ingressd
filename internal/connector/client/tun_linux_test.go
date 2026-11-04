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
		`ip saddr { 10.100.1.0/24, 100.64.0.8/30 } oifname != "ingressd0" masquerade`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("script lacks %q:\n%s", want, s)
		}
	}
	if s := nftScript("ingressd0", &State{}, 1420); strings.Contains(s, "masquerade") {
		t.Error("masquerade without --masquerade")
	}
}

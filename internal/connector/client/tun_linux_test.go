// SPDX-License-Identifier: Apache-2.0

package client

import (
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

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

// netnsWithTunnel runs the test on a new network namespace holding the tunnel
// interface and a LAN, forwarding between them.
func netnsWithTunnel(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	// Left locked: the thread ends with the test, and its namespace with it.
	runtime.LockOSThread()
	if err := unix.Unshare(unix.CLONE_NEWNET); err != nil {
		t.Skip(err)
	}
	for name, addr := range map[string]string{"ingressd0": "100.64.0.6/30", "lan0": "192.168.1.1/24"} {
		lk := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: name}}
		if err := netlink.LinkAdd(lk); err != nil {
			t.Skip(err)
		}
		a, _ := netlink.ParseAddr(addr)
		if err := netlink.AddrAdd(lk, a); err != nil {
			t.Fatal(err)
		}
		if err := netlink.LinkSetUp(lk); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1"), 0o644); err != nil { //nolint:gosec // procfs entry, mode unused
		t.Fatal(err)
	}
}

// fromTunnel looks up the route of a packet arriving on the tunnel.
func fromTunnel(dst string) (*netlink.Route, bool) {
	rs, err := netlink.RouteGetWithOptions(net.ParseIP(dst), &netlink.RouteGetOptions{Iif: "ingressd0", SrcAddr: net.ParseIP("100.64.0.5")})
	if err != nil || len(rs) == 0 {
		return nil, false
	}
	return &rs[0], true
}

func TestForwardingWithoutTheFilter(t *testing.T) {
	netnsWithTunnel(t)
	stub := func(body string) string {
		dir := t.TempDir()
		if body != "" {
			if err := os.WriteFile(filepath.Join(dir, "nft"), []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil { //nolint:gosec // the stub must be executable
				t.Fatal(err)
			}
		}
		return dir
	}
	noNFT, brokenNFT, filterRefused, workingNFT := stub(""), stub("exit 1"), stub(`grep -q drop && exit 1; exit 0`), stub("cat >/dev/null")
	damaged := &localReach{problem: "allowlist file is missing"}
	partly := reachOf("192.168.1.0/24")
	partly.problem = "ignoring invalid allowlist entries: x"
	for _, tc := range []struct {
		name     string
		path     string
		reach    *localReach
		forwards bool
		off      bool
	}{
		{"healthy list, no nft", noNFT, reachOf("192.168.1.0/24"), true, true},
		{"healthy list, nft fails", brokenNFT, reachOf("192.168.1.0/24"), true, true},
		{"damaged list, no nft", noNFT, damaged, false, true},
		{"partly damaged list, no nft", noNFT, partly, false, true},
		{"empty list, no nft", noNFT, reachOf(), false, true},
		{"no list, nft fails", brokenNFT, damaged, false, true},
		{"empty list, filter refused", filterRefused, reachOf(), false, true},
		{"healthy list again", noNFT, reachOf("192.168.1.0/24"), true, true},
		{"damaged list, working nft", workingNFT, damaged, true, false}, // the filter drops it
	} {
		// No subtests: they would run on another thread, outside the namespace.
		path := tc.path + ":/usr/bin:/bin"
		if tc.path == noNFT {
			path = tc.path
		}
		t.Setenv("PATH", path)
		tc.reach.unfiltered.Store(false)
		applyNFT("ingressd0", &State{reach: tc.reach}, 1420, quiet)
		if got := tc.reach.unfiltered.Load(); got != tc.off {
			t.Errorf("%s: filter off = %v, want %v", tc.name, got, tc.off)
		}
		if _, got := fromTunnel("192.168.1.10"); got != tc.forwards {
			t.Errorf("%s: forwards = %v, want %v", tc.name, got, tc.forwards)
		}
		// The control channel's replies and the edge's ping end here.
		if r, ok := fromTunnel("100.64.0.6"); !ok || r.Type != unix.RTN_LOCAL {
			t.Errorf("%s: transit address: %+v, %v", tc.name, r, ok)
		}
		// This host's own traffic does not go through the rule.
		if rs, err := netlink.RouteGet(net.ParseIP("192.168.1.10")); err != nil || len(rs) == 0 {
			t.Errorf("%s: host route: %v, %v", tc.name, rs, err)
		}
	}
	if err := holdForwarding("ingressd0", false); err != nil {
		t.Fatal(err)
	}
	if _, ok := fromTunnel("192.168.1.10"); !ok {
		t.Error("forwarding still held")
	}
}

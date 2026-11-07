// SPDX-License-Identifier: Apache-2.0

package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/ingressd/ingressd/internal/connector/proto"
)

// reachOf is an allowlist in effect holding nets.
func reachOf(nets ...string) *localReach {
	r := &localReach{}
	for _, n := range nets {
		r.nets = append(r.nets, netip.MustParsePrefix(n))
	}
	return r
}

func strs(ps []netip.Prefix) []string {
	out := []string{}
	for _, p := range ps {
		out = append(out, p.String())
	}
	return out
}

func siteState(t *testing.T, tc proto.TunnelConfig) (*State, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "connector.json")
	st := &State{Mode: ModeNetstack, Edges: []EdgeState{{Config: tc}}}
	if err := st.Save(path); err != nil {
		t.Fatal(err)
	}
	return st, path
}

func TestFirstStartPinsCurrentNetworks(t *testing.T) {
	st, path := siteState(t, proto.TunnelConfig{
		Subnets:     []string{"198.51.100.0/24", "198.51.100.5/32", "192.0.2.9/32"},
		Transparent: []string{"tcp/192.0.2.4:25565"},
	})
	st.reach = openReach(path, st, quiet)
	want := []string{"198.51.100.0/24", "192.0.2.4/32", "192.0.2.9/32"}
	if got := strs(st.forwardPrefixes()); !slices.Equal(got, want) {
		t.Errorf("forwards %v, want %v", got, want)
	}
	if got := st.refused(); len(got) != 0 {
		t.Errorf("refused %v", got)
	}
	if fi, err := os.Stat(AllowlistPath(path)); err != nil {
		t.Fatal(err)
	} else if fi.Mode().Perm()&0o077 != 0 && os.PathSeparator == '/' {
		t.Errorf("mode %v", fi.Mode())
	}
	a, _, err := readAllowlist(path)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"10.0.0.0/8", "172.16.0.0/12", "192.0.2.4/32", "192.0.2.9/32", "192.168.0.0/16", "198.51.100.0/24", "fc00::/7"}; !slices.Equal(a.Networks, want) {
		t.Errorf("pinned %v, want %v", a.Networks, want)
	}

	// The list survives a restart, and later configs do not extend it.
	saved, err := LoadState(path)
	if err != nil || !saved.AllowlistPinned {
		t.Fatalf("saved %+v, %v", saved, err)
	}
	saved.Edges[0].Config.Subnets = append(saved.Edges[0].Config.Subnets, "203.0.113.0/24")
	saved.reach = openReach(path, saved, quiet)
	if got := strs(saved.forwardPrefixes()); !slices.Equal(got, want) {
		t.Errorf("after restart %v, want %v", got, want)
	}
	if got := saved.refused(); !slices.Equal(got, []string{"203.0.113.0/24"}) {
		t.Errorf("refused %v", got)
	}
}

func TestFirstStartUnderADefaultRouteKeepsTheOrigins(t *testing.T) {
	st, path := siteState(t, proto.TunnelConfig{
		Subnets: []string{"0.0.0.0/0", "198.51.100.9/32"},
		Targets: []string{"203.0.113.7:443", "203.0.113.8:80", "192.168.1.5:80", "169.254.169.254:80", "127.0.0.1:80", "origin.example:80"},
	})
	st.reach = openReach(path, st, quiet)
	a, _, err := readAllowlist(path)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "198.51.100.9/32", "203.0.113.7/32", "203.0.113.8/32", "fc00::/7"}
	if !slices.Equal(a.Networks, want) {
		t.Errorf("pinned %v, want %v", a.Networks, want)
	}
	reachable := func(s string) bool {
		_, ok := (&netstackTUN{allowed: st.allowedSubnets()}).target(tcpID(netip.MustParseAddr(s)))
		return ok
	}
	if !reachable("203.0.113.7") || !reachable("198.51.100.9") {
		t.Errorf("origins lost: %v", st.allowedSubnets())
	}
	if reachable("203.0.113.9") {
		t.Errorf("forwards more than the origins: %v", st.allowedSubnets())
	}
	if got := st.reachTargets(); !slices.Contains(got, "203.0.113.7:443") {
		t.Errorf("targets %v", got)
	}
	if got := st.refused(); !slices.Equal(got, []string{"0.0.0.0/0"}) {
		t.Errorf("refused %v", got)
	}
}

func TestPinLeavesOutTargetsTheSiteDoesNotRoute(t *testing.T) {
	st, _ := siteState(t, proto.TunnelConfig{Subnets: []string{"198.51.100.0/24"}, Targets: []string{"198.51.100.4:80", "203.0.113.7:443"}})
	if got := pinnedAllowlist(st).Networks; slices.Contains(got, "203.0.113.7/32") || slices.Contains(got, "198.51.100.4/32") {
		t.Errorf("pinned %v", got)
	}
}

func TestHealthCarriesTheFilterState(t *testing.T) {
	st := &State{reach: reachOf("192.168.1.0/24")}
	var h proto.Health
	st.reportReach(&h)
	if h.LANFilterOff {
		t.Error("filter off by default")
	}
	st.reach.setUnfiltered(true)
	st.reportReach(&h)
	b, err := json.Marshal(Status{Health: h})
	if err != nil || !h.LANFilterOff || !bytes.Contains(b, []byte(`"lan_filter_off":true`)) {
		t.Errorf("%s %v", b, err)
	}
	(&State{}).reportReach(&h) // no list in effect
}

func TestDefaultListCoversPrivateNetworks(t *testing.T) {
	k, _ := wgtypes.GeneratePrivateKey()
	pub := k.PublicKey()
	first := proto.TunnelConfig{Tunnel: "home", EdgePublicKey: pub.String(), Endpoint: "a:1", Address: "100.64.0.6/30", Revision: "r1", Subnets: []string{"198.51.100.0/24"}}
	st, path := siteState(t, first)
	st.reach = openReach(path, st, quiet)
	restarts := 0
	s := &session{
		r: &Runner{StatePath: path}, st: st, log: quiet, restartEdge: map[string]bool{}, refresh: make(chan struct{}, 1),
		restart: func(error) { restarts++ },
	}
	e := &edge{s: s, key: pub, cfg: st.Edges[0]}
	listed, err := os.ReadFile(AllowlistPath(path))
	if err != nil {
		t.Fatal(err)
	}
	reachable := func(a string) bool {
		_, ok := (&netstackTUN{allowed: st.allowedSubnets()}).target(tcpID(netip.MustParseAddr(a)))
		return ok
	}

	// A new private origin works, a new public network does not.
	next := first
	next.Revision = "r2"
	next.Subnets = []string{"198.51.100.0/24", "192.168.7.20/32", "203.0.113.0/24"}
	next.Transparent = []string{"tcp/10.4.0.9:25565", "tcp/192.0.2.9:25565"}
	if err := s.applyEdgeConfig(e, next); err != nil {
		t.Fatal(err)
	}
	if restarts != 1 {
		t.Errorf("%d link restarts", restarts)
	}
	st.reach = openReach(path, st, quiet)
	if got, want := strs(st.forwardPrefixes()), []string{"198.51.100.0/24", "10.4.0.9/32", "192.168.7.20/32"}; !slices.Equal(got, want) {
		t.Errorf("forwards %v, want %v", got, want)
	}
	if got, want := st.refused(), []string{"203.0.113.0/24", "192.0.2.9/32"}; !slices.Equal(got, want) {
		t.Errorf("refused %v, want %v", got, want)
	}
	if got, want := st.allowedTransparent(), []string{"tcp/10.4.0.9:25565"}; !slices.Equal(got, want) {
		t.Errorf("transparent %v, want %v", got, want)
	}
	for a, want := range map[string]bool{"192.168.7.20": true, "198.51.100.5": true, "203.0.113.5": false} {
		if got := reachable(a); got != want {
			t.Errorf("%s: %v", a, got)
		}
	}

	// Every network from the edge is held to the same list.
	next.Revision = "r3"
	next.Subnets, next.Transparent = []string{"0.0.0.0/0"}, nil
	if err := s.applyEdgeConfig(e, next); err != nil {
		t.Fatal(err)
	}
	st.reach = openReach(path, st, quiet)
	if got, want := strs(st.forwardPrefixes()), []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "198.51.100.0/24"}; !slices.Equal(got, want) {
		t.Errorf("forwards %v, want %v", got, want)
	}
	if got := st.refused(); !slices.Equal(got, []string{"0.0.0.0/0"}) {
		t.Errorf("refused %v", got)
	}
	for a, want := range map[string]bool{
		"10.9.9.9": true, "198.51.100.5": true,
		"203.0.113.5": false, "192.0.2.5": false, "8.8.8.8": false, "127.0.0.1": false, "169.254.169.254": false,
	} {
		if got := reachable(a); got != want {
			t.Errorf("%s: %v", a, got)
		}
	}

	if after, err := os.ReadFile(AllowlistPath(path)); err != nil || !bytes.Equal(after, listed) {
		t.Errorf("the list changed: %s, %v", after, err)
	}
}

func TestForwardingIsTheIntersection(t *testing.T) {
	for _, tc := range []struct {
		name          string
		allow, subnet []string
		want, refused []string
	}{
		{"same", []string{"198.51.100.0/24"}, []string{"198.51.100.0/24"}, []string{"198.51.100.0/24"}, nil},
		{"edge narrower", []string{"198.51.100.0/24"}, []string{"198.51.100.128/25"}, []string{"198.51.100.128/25"}, nil},
		{"edge wider", []string{"198.51.100.0/24"}, []string{"198.51.0.0/16"}, []string{"198.51.100.0/24"}, []string{"198.51.0.0/16"}},
		{"edge every network", []string{"198.51.100.0/24"}, []string{"0.0.0.0/0"}, []string{"198.51.100.0/24"}, []string{"0.0.0.0/0"}},
		{"split", []string{"10.0.1.0/24", "10.0.2.0/24"}, []string{"10.0.0.0/16"}, []string{"10.0.1.0/24", "10.0.2.0/24"}, []string{"10.0.0.0/16"}},
		{"disjoint", []string{"198.51.100.0/24"}, []string{"10.0.0.0/8"}, []string{}, []string{"10.0.0.0/8"}},
		{"nothing allowed", nil, []string{"198.51.100.0/24"}, []string{}, []string{"198.51.100.0/24"}},
		{"other family", []string{"198.51.100.0/24"}, []string{"fd00::/64"}, []string{}, []string{"fd00::/64"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st := &State{reach: reachOf(tc.allow...), Edges: []EdgeState{{Config: proto.TunnelConfig{Subnets: tc.subnet}}}}
			if got := strs(st.forwardPrefixes()); !slices.Equal(got, tc.want) {
				t.Errorf("forwards %v, want %v", got, tc.want)
			}
			if got := strs(st.allowedSubnets()); !slices.Equal(got, tc.want) {
				t.Errorf("subnets %v, want %v", got, tc.want)
			}
			if got := st.refused(); !slices.Equal(got, tc.refused) {
				t.Errorf("refused %v, want %v", got, tc.refused)
			}
		})
	}
	// Without a list in effect nothing is reachable.
	st := &State{Edges: []EdgeState{{Config: proto.TunnelConfig{Subnets: []string{"198.51.100.0/24"}}}}}
	if got := st.forwardPrefixes(); len(got) != 0 {
		t.Errorf("no list: %v", got)
	}
}

func TestNetstackUsesTheIntersection(t *testing.T) {
	k, _ := wgtypes.GeneratePrivateKey()
	st := &State{reach: reachOf("198.51.100.0/24"), Edges: []EdgeState{{Config: proto.TunnelConfig{Address: "100.64.0.6/30", Subnets: []string{"198.51.0.0/16"}}}}}
	l, err := openNetstack(st, k, quiet)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	ns := &netstackTUN{allowed: st.allowedSubnets()}
	for a, want := range map[string]bool{"198.51.100.5": true, "198.51.7.5": false, "203.0.113.5": false, "192.0.2.5": false} {
		if _, ok := ns.target(tcpID(netip.MustParseAddr(a))); ok != want {
			t.Errorf("%s: %v", a, ok)
		}
	}
}

func TestAnyNetworkNeedsTheOverride(t *testing.T) {
	st, path := siteState(t, proto.TunnelConfig{Subnets: []string{"0.0.0.0/0", "198.51.100.0/24"}})
	for _, n := range []string{"0.0.0.0/0", "::/0", "1.2.3.4/0"} {
		if _, err := parseNetwork(n, false); !errors.Is(err, errAnyNetwork) {
			t.Errorf("%s: %v", n, err)
		}
		if _, err := AllowAdd(path, []string{n}, false); !errors.Is(err, errAnyNetwork) {
			t.Errorf("add %s: %v", n, err)
		}
	}
	for _, n := range []string{"nope", "::ffff:10.0.0.0/104", "198.51.100.0/33"} {
		if _, err := parseNetwork(n, true); err == nil {
			t.Errorf("%s accepted", n)
		}
	}

	// A first start never pins a /0, and shows it as refused.
	st.reach = openReach(path, st, quiet)
	if got, want := strs(st.forwardPrefixes()), []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "198.51.100.0/24"}; !slices.Equal(got, want) {
		t.Errorf("forwards %v, want %v", got, want)
	}
	if got := st.refused(); !slices.Equal(got, []string{"0.0.0.0/0"}) {
		t.Errorf("refused %v", got)
	}
	if a, _, err := readAllowlist(path); err != nil || a.AnyNetwork || slices.Contains(a.Networks, "0.0.0.0/0") {
		t.Errorf("pinned %+v, %v", a, err)
	}

	a, err := AllowAdd(path, []string{"0.0.0.0/0"}, true)
	if err != nil || !a.AnyNetwork {
		t.Fatalf("%+v, %v", a, err)
	}
	st.reach = openReach(path, st, quiet)
	if got := strs(st.forwardPrefixes()); !slices.Equal(got, []string{"0.0.0.0/0"}) {
		t.Errorf("with the override %v", got)
	}
	if a, err = AllowRemove(path, []string{"0.0.0.0/0"}); err != nil || a.AnyNetwork {
		t.Errorf("%+v, %v", a, err)
	}

	// An entry the override does not cover is left out, the rest kept.
	b, _ := json.Marshal(Allowlist{Networks: []string{"0.0.0.0/0", "10.0.0.0/8", "nope"}})
	if err := os.WriteFile(AllowlistPath(path), b, 0o600); err != nil {
		t.Fatal(err)
	}
	r := openReach(path, st, quiet)
	if got := strs(r.nets); !slices.Equal(got, []string{"10.0.0.0/8"}) || !strings.Contains(r.problem, "0.0.0.0/0") {
		t.Errorf("%v, %q", got, r.problem)
	}
}

func TestDamagedAllowlistForwardsNothing(t *testing.T) {
	k, _ := wgtypes.GeneratePrivateKey()
	tc := proto.TunnelConfig{Address: "100.64.0.6/30", Subnets: []string{"198.51.100.0/24"}}
	for name, damage := range map[string]func(path string) error{
		"corrupt": func(p string) error { return os.WriteFile(p, []byte("{not json"), 0o600) },
		"wrong":   func(p string) error { return os.WriteFile(p, []byte(`{"networks":"all"}`), 0o600) },
		"missing": os.Remove,
	} {
		t.Run(name, func(t *testing.T) {
			st, path := siteState(t, tc)
			st.reach = openReach(path, st, quiet)
			if err := damage(AllowlistPath(path)); err != nil {
				t.Fatal(err)
			}
			st, err := LoadState(path)
			if err != nil {
				t.Fatalf("state: %v", err)
			}
			st.reach = openReach(path, st, quiet)
			if st.reach.problem == "" || len(st.forwardPrefixes()) != 0 {
				t.Errorf("%q, forwards %v", st.reach.problem, st.forwardPrefixes())
			}
			if got := DescribeReach(path, st); got.Problem == "" || len(got.Refused) != 1 {
				t.Errorf("%+v", got)
			}
			// The link still comes up, and a wider config changes nothing.
			l, err := openNetstack(st, k, quiet)
			if err != nil {
				t.Fatal(err)
			}
			_ = l.Close()
			st.Edges[0].Config.Subnets = append(st.Edges[0].Config.Subnets, "192.168.1.0/24")
			st.reach = openReach(path, st, quiet)
			if len(st.forwardPrefixes()) != 0 {
				t.Error("pinned again")
			}
			// The operator repairs it locally.
			if _, err := AllowAdd(path, []string{"198.51.100.0/24"}, false); err != nil {
				t.Fatal(err)
			}
			st.reach = openReach(path, st, quiet)
			if st.reach.problem != "" || len(st.forwardPrefixes()) != 1 {
				t.Errorf("repaired: %q, %v", st.reach.problem, st.forwardPrefixes())
			}
		})
	}
}

func TestUnsavableAllowlistStillRuns(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("needs directory permissions that apply to this user")
	}
	st, path := siteState(t, proto.TunnelConfig{Subnets: []string{"198.51.100.0/24"}})
	dir := filepath.Dir(path)
	if err := os.Chmod(dir, 0o500); err != nil { //nolint:gosec // the test needs an unwritable directory
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) }) //nolint:gosec // restores the directory for cleanup
	st.reach = openReach(path, st, quiet)
	if got := strs(st.forwardPrefixes()); !slices.Equal(got, []string{"198.51.100.0/24"}) {
		t.Errorf("forwards %v", got)
	}
}

func TestAllowAddBeforeFirstStartKeepsThePin(t *testing.T) {
	_, path := siteState(t, proto.TunnelConfig{Subnets: []string{"198.51.100.0/24"}})
	a, err := AllowAdd(path, []string{"192.0.2.5", "203.0.113.200/25"}, false)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"10.0.0.0/8", "172.16.0.0/12", "192.0.2.5/32", "192.168.0.0/16", "198.51.100.0/24", "203.0.113.128/25", "fc00::/7"}
	if !slices.Equal(a.Networks, want) {
		t.Errorf("got %v, want %v", a.Networks, want)
	}
	if _, err := AllowRemove(path, []string{"203.0.113.0/24"}); err == nil {
		t.Error("removed a network not in the list")
	}
	want = slices.DeleteFunc(want, func(s string) bool { return s == "203.0.113.128/25" })
	if a, err = AllowRemove(path, []string{"203.0.113.128/25"}); err != nil || !slices.Equal(a.Networks, want) {
		t.Errorf("%+v, %v, want %v", a, err, want)
	}
	st, _ := LoadState(path)
	if got := DescribeReach(path, st); got.Pending || got.Problem != "" || !slices.Equal(got.Allowed, want) {
		t.Errorf("%+v", got)
	}
}

func TestAllowRemoveBeforeFirstStartLasts(t *testing.T) {
	st, path := siteState(t, proto.TunnelConfig{Subnets: []string{"198.51.100.0/24", "172.16.5.0/24"}})
	want := []string{"10.0.0.0/8", "192.168.0.0/16", "198.51.100.0/24", "fc00::/7"}
	a, err := AllowRemove(path, []string{"172.16.0.0/12"})
	if err != nil || !slices.Equal(a.Networks, want) {
		t.Fatalf("%+v, %v, want %v", a, err, want)
	}
	st.reach = openReach(path, st, quiet)
	if got := strs(st.forwardPrefixes()); !slices.Equal(got, []string{"198.51.100.0/24"}) {
		t.Errorf("forwards %v", got)
	}
	if got := st.refused(); !slices.Equal(got, []string{"172.16.5.0/24"}) {
		t.Errorf("refused %v", got)
	}
}

func TestDescribeBeforeFirstStart(t *testing.T) {
	st, path := siteState(t, proto.TunnelConfig{Subnets: []string{"198.51.100.0/24"}})
	if got := DescribeReach(path, st); !got.Pending || !slices.Equal(got.Allowed, []string{"fc00::/7", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "198.51.100.0/24"}) {
		t.Errorf("%+v", got)
	}
	if _, err := os.Stat(AllowlistPath(path)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("describe wrote the file: %v", err)
	}
}

func TestTransparentRepliesWithAllowlist(t *testing.T) {
	k, _ := wgtypes.GeneratePrivateKey()
	st := &State{reach: reachOf("192.168.0.0/24"), Edges: []EdgeState{{Config: proto.TunnelConfig{
		Address: "100.64.0.6/30", Transparent: []string{"tcp/192.168.0.17:25565", "tcp/192.0.2.9:22"},
	}}}}
	s := &session{st: st, mode: ModeTUN, owner: k}
	e := &edge{s: s, key: k, cfg: st.Edges[0]}

	// The owner takes replies to any client, while the LAN stays limited.
	if got := strs(s.allowedIPs(e)); !slices.Equal(got, []string{"100.64.0.4/30", "0.0.0.0/0"}) {
		t.Errorf("allowed IPs %v", got)
	}
	if got := st.allowedTransparent(); !slices.Equal(got, []string{"tcp/192.168.0.17:25565"}) {
		t.Errorf("transparent %v", got)
	}
	if got := strs(st.forwardPrefixes()); !slices.Equal(got, []string{"192.168.0.17/32"}) {
		t.Errorf("forwards %v", got)
	}
	if got := st.refused(); !slices.Equal(got, []string{"192.0.2.9/32"}) {
		t.Errorf("refused %v", got)
	}

	// With no source allowed there are no replies to take.
	st.reach = reachOf("172.16.0.0/12")
	if got := strs(s.allowedIPs(e)); !slices.Equal(got, []string{"100.64.0.4/30"}) {
		t.Errorf("allowed IPs %v", got)
	}
}

func TestTransitOverlappingARouteIsRefused(t *testing.T) {
	k, _ := wgtypes.GeneratePrivateKey()
	pub := k.PublicKey()
	good := proto.TunnelConfig{Tunnel: "home", EdgePublicKey: pub.String(), Endpoint: "a:1", Address: "192.168.0.5/30", Revision: "r1"}
	st, path := siteState(t, good)
	st.reach = reachOf()
	st.routes = func() []netip.Prefix { return []netip.Prefix{netip.MustParsePrefix("192.168.0.0/24")} }
	s := &session{r: &Runner{StatePath: path}, st: st, log: quiet, restartEdge: map[string]bool{}, refresh: make(chan struct{}, 1)}
	e := &edge{s: s, key: pub, cfg: st.Edges[0]}

	// A config already in place keeps working.
	next := good
	next.Revision = "r2"
	if err := s.applyEdgeConfig(e, next); err != nil {
		t.Fatal(err)
	}
	next.Revision, next.Address = "r3", "192.168.0.9/30"
	if err := s.applyEdgeConfig(e, next); err == nil || !strings.Contains(err.Error(), "192.168.0.0/24") {
		t.Fatalf("got %v", err)
	}
	if st.Edges[0].Config.Address != good.Address {
		t.Errorf("address %s", st.Edges[0].Config.Address)
	}
	next.Address = "100.64.0.6/30"
	if err := s.applyEdgeConfig(e, next); err != nil {
		t.Error(err)
	}

	// A sibling is treated the same way.
	k2, _ := wgtypes.GeneratePrivateKey()
	k3, _ := wgtypes.GeneratePrivateKey()
	st.Edges[0].Config.Siblings = []proto.Sibling{
		{EdgePublicKey: k2.PublicKey().String(), Endpoint: "b:1", Address: "192.168.0.13/30"},
		{EdgePublicKey: k3.PublicKey().String(), Endpoint: "c:1", Address: "100.64.0.10/30"},
	}
	mergeSiblings(st, map[string]bool{}, st.Edges[0].LastSeen)
	if st.Edge(k2.PublicKey().String()) != nil || st.Edge(k3.PublicKey().String()) == nil {
		t.Errorf("edges %+v", st.Edges)
	}

	// Netstack has no host routes to take over.
	st.routes = nil
	if _, clash := st.transitClash("192.168.0.9/30"); clash {
		t.Error("clash without routes")
	}
}

func TestAllowlistChangeIsNoticed(t *testing.T) {
	st, path := siteState(t, proto.TunnelConfig{Subnets: []string{"198.51.100.0/24"}})
	st.reach = openReach(path, st, quiet)
	s := &session{r: &Runner{StatePath: path}, st: st}
	if s.allowlistChanged() {
		t.Error("changed at start")
	}
	if _, err := AllowAdd(path, []string{"203.0.113.0/24"}, false); err != nil {
		t.Fatal(err)
	}
	if !s.allowlistChanged() {
		t.Error("change missed")
	}
	st.reach = openReach(path, st, quiet)
	if s.allowlistChanged() {
		t.Error("changed after reload")
	}
	if err := os.Remove(AllowlistPath(path)); err != nil {
		t.Fatal(err)
	}
	if !s.allowlistChanged() {
		t.Error("removal missed")
	}
}

func TestRefusedNetworkIsLoggedOnce(t *testing.T) {
	var out bytes.Buffer
	r := &Runner{Log: slog.New(slog.NewTextHandler(&out, nil))}
	for range 3 {
		r.warnOnce("refused 10.0.0.0/8", "refusing", "network", "10.0.0.0/8")
	}
	r.warnOnce("refused 10.1.0.0/16", "refusing", "network", "10.1.0.0/16")
	if got := strings.Count(out.String(), "refusing"); got != 2 {
		t.Errorf("%d lines:\n%s", got, out.String())
	}
}

func enrollEdge(t *testing.T, subnets []string, calls *int) *httptest.Server {
	t.Helper()
	k, _ := wgtypes.GeneratePrivateKey()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		*calls++
		_ = json.NewEncoder(w).Encode(proto.EnrollResponse{Credential: "c", Config: proto.TunnelConfig{
			Tunnel: "home", EdgePublicKey: k.PublicKey().String(), Endpoint: "a:1", Address: "100.64.0.6/30", Subnets: subnets,
		}})
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestEnrollSetsTheAllowlist(t *testing.T) {
	calls := 0
	srv := enrollEdge(t, []string{"198.51.100.0/24"}, &calls)
	opts := func() EnrollOptions {
		return EnrollOptions{EdgeURL: srv.URL, Token: "t", Insecure: true, Mode: ModeNetstack}
	}

	path := filepath.Join(t.TempDir(), "connector.json")
	st, err := Enroll(context.Background(), path, opts())
	if err != nil {
		t.Fatal(err)
	}
	a, _, err := readAllowlist(path)
	want := []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "198.51.100.0/24", "fc00::/7"}
	if err != nil || !st.AllowlistPinned || !slices.Equal(a.Networks, want) || a.Source != allowFromPin {
		t.Errorf("%+v, %v", a, err)
	}

	path = filepath.Join(t.TempDir(), "connector.json")
	o := opts()
	o.Allow = []string{"10.0.0.0/24"}
	st, err = Enroll(context.Background(), path, o)
	if err != nil {
		t.Fatal(err)
	}
	if a, _, err = readAllowlist(path); err != nil || !slices.Equal(a.Networks, []string{"10.0.0.0/24"}) || a.Source != allowFromEnroll {
		t.Errorf("%+v, %v", a, err)
	}
	st.Edges[0].Config.Subnets = append(st.Edges[0].Config.Subnets, "192.168.1.0/24")
	st.reach = openReach(path, st, quiet)
	if got := st.forwardPrefixes(); len(got) != 0 {
		t.Errorf("forwards %v", got)
	}
	if got := st.refused(); !slices.Equal(got, []string{"192.168.1.0/24", "198.51.100.0/24"}) {
		t.Errorf("refused %v", got)
	}

	// Refused before the one-time token is spent.
	before := calls
	o = opts()
	o.Allow = []string{"0.0.0.0/0"}
	if _, err := Enroll(context.Background(), filepath.Join(t.TempDir(), "connector.json"), o); !errors.Is(err, errAnyNetwork) {
		t.Errorf("got %v", err)
	}
	if calls != before {
		t.Error("token spent")
	}
	path = filepath.Join(t.TempDir(), "connector.json")
	o.AllowAnyNetwork = true
	if _, err := Enroll(context.Background(), path, o); err != nil {
		t.Fatal(err)
	}
	if a, _, _ := readAllowlist(path); !a.AnyNetwork {
		t.Errorf("%+v", a)
	}
}

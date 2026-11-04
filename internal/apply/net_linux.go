// SPDX-License-Identifier: Apache-2.0

//go:build linux

package apply

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/ingressd/ingressd/internal/render"
)

// routeProto tags routes ingressd installs, so stale ones can be found and
// removed without touching anything else.
const routeProto = netlink.RouteProtocol(190)

const ifPrefix = "ix-"

// legacyIfPrefix named the WireGuard interfaces before the rename (he-home,
// he-mesh, ...). They are removed before the new ones come up, because they
// hold the same listen ports.
const legacyIfPrefix = "he-" // legacy homeedge name, remove after 2027-01

// Net reconciles WireGuard interfaces, addresses, routes and policy rules
// with n. Only ix-* (and legacy he-*) interfaces, routes tagged routeProto and rules in
// ingressd's priority range are ever modified.
func Net(_ context.Context, n render.Network) error {
	wg, err := wgctrl.New()
	if err != nil {
		return err
	}
	defer wg.Close()

	if err := removeLegacyInterfaces(); err != nil {
		return err
	}
	want := map[string]bool{}
	for _, ifc := range n.Interfaces {
		want[ifc.Name] = true
		if err := ensureInterface(wg, ifc); err != nil {
			return fmt.Errorf("%s: %w", ifc.Name, err)
		}
	}

	links, err := netlink.LinkList()
	if err != nil {
		return err
	}
	for _, l := range links {
		name := l.Attrs().Name
		if strings.HasPrefix(name, ifPrefix) && l.Type() == "wireguard" && !want[name] {
			if err := netlink.LinkDel(l); err != nil {
				return fmt.Errorf("remove %s: %w", name, err)
			}
		}
	}

	if err := reconcileRoutes(n.Routes); err != nil {
		return err
	}
	if err := reconcileRules(n.Rules); err != nil {
		return err
	}
	if n.IPForward {
		if err := sysctl("net/ipv4/ip_forward", "1"); err != nil {
			return err
		}
	}
	return setRPFilter(n)
}

func removeLegacyInterfaces() error {
	links, err := netlink.LinkList()
	if err != nil {
		return err
	}
	for _, l := range links {
		if name := l.Attrs().Name; strings.HasPrefix(name, legacyIfPrefix) && l.Type() == "wireguard" {
			if err := netlink.LinkDel(l); err != nil {
				return fmt.Errorf("remove %s: %w", name, err)
			}
		}
	}
	return nil
}

func ensureInterface(wg *wgctrl.Client, ifc render.Interface) error {
	link, err := netlink.LinkByName(ifc.Name)
	if err != nil {
		var nf netlink.LinkNotFoundError
		if !errors.As(err, &nf) {
			return err
		}
		la := netlink.NewLinkAttrs()
		la.Name = ifc.Name
		if err := netlink.LinkAdd(&netlink.GenericLink{LinkAttrs: la, LinkType: "wireguard"}); err != nil {
			return fmt.Errorf("create (is the wireguard kernel module available?): %w", err)
		}
		if link, err = netlink.LinkByName(ifc.Name); err != nil {
			return err
		}
	}

	priv, err := wgtypes.ParseKey(ifc.PrivateKey)
	if err != nil {
		return err
	}
	cfg := wgtypes.Config{PrivateKey: &priv, ListenPort: &ifc.ListenPort}

	// Update peers in place rather than replacing them, so a reconfigure
	// keeps each peer's learned endpoint and the tunnel stays up.
	wanted := map[wgtypes.Key]bool{}
	for _, p := range ifc.Peers {
		pk, err := wgtypes.ParseKey(p.PublicKey)
		if err != nil {
			return err
		}
		wanted[pk] = true
		var allowed []net.IPNet
		for _, a := range p.AllowedIPs {
			_, n, err := net.ParseCIDR(a)
			if err != nil {
				return err
			}
			allowed = append(allowed, *n)
		}
		pc := wgtypes.PeerConfig{PublicKey: pk, ReplaceAllowedIPs: true, AllowedIPs: allowed}
		if err := meshPeerExtras(&pc, p); err != nil {
			return err
		}
		cfg.Peers = append(cfg.Peers, pc)
	}
	if dev, err := wg.Device(ifc.Name); err == nil {
		for _, p := range dev.Peers {
			if !wanted[p.PublicKey] {
				cfg.Peers = append(cfg.Peers, wgtypes.PeerConfig{PublicKey: p.PublicKey, Remove: true})
			}
		}
	}
	if err := wg.ConfigureDevice(ifc.Name, cfg); err != nil {
		return err
	}

	addr, err := netlink.ParseAddr(ifc.Address)
	if err != nil {
		return err
	}
	addrs, err := netlink.AddrList(link, netlink.FAMILY_V4)
	if err != nil {
		return err
	}
	have := false
	for _, a := range addrs {
		if a.IPNet.String() == addr.IPNet.String() {
			have = true
			continue
		}
		if err := netlink.AddrDel(link, &a); err != nil {
			return err
		}
	}
	if !have {
		if err := netlink.AddrAdd(link, addr); err != nil {
			return err
		}
	}
	if err := netlink.LinkSetMTU(link, ifc.MTU); err != nil {
		return err
	}
	return netlink.LinkSetUp(link)
}

func routeKey(dst string, table int) string { return fmt.Sprintf("%s@%d", dst, table) }

func reconcileRoutes(routes []render.Route) error {
	want := map[string]bool{}
	for _, r := range routes {
		link, err := netlink.LinkByName(r.Dev)
		if err != nil {
			return fmt.Errorf("route %s: %w", r.Dst, err)
		}
		_, dst, err := net.ParseCIDR(r.Dst)
		if err != nil {
			return err
		}
		table := r.Table
		if table == 0 {
			table = unix.RT_TABLE_MAIN
		}
		want[routeKey(dst.String(), table)] = true
		nr := &netlink.Route{LinkIndex: link.Attrs().Index, Dst: dst, Table: table, Scope: netlink.SCOPE_LINK, Protocol: routeProto}
		if err := netlink.RouteReplace(nr); err != nil {
			return fmt.Errorf("route %s dev %s table %d: %w", r.Dst, r.Dev, table, err)
		}
	}
	all, err := netlink.RouteListFiltered(netlink.FAMILY_V4, &netlink.Route{Table: unix.RT_TABLE_UNSPEC}, netlink.RT_FILTER_TABLE)
	if err != nil {
		return err
	}
	for _, r := range all {
		if r.Protocol != routeProto || r.Dst == nil || want[routeKey(r.Dst.String(), r.Table)] {
			continue
		}
		if err := netlink.RouteDel(&r); err != nil {
			return fmt.Errorf("remove route %s: %w", r.Dst, err)
		}
	}
	return nil
}

func reconcileRules(rules []render.Rule) error {
	existing, err := netlink.RuleList(netlink.FAMILY_V4)
	if err != nil {
		return err
	}
	want := map[int]render.Rule{}
	for _, r := range rules {
		want[r.Priority] = r
	}
	have := map[int]bool{}
	for _, r := range existing {
		if r.Priority < render.RulePriorityBase || r.Priority > render.RulePriorityMax {
			continue
		}
		if w, ok := want[r.Priority]; ok && int(r.Mark) == w.Mark && r.Table == w.Table && !have[r.Priority] {
			have[r.Priority] = true
			continue
		}
		if err := netlink.RuleDel(&r); err != nil {
			return fmt.Errorf("remove rule %d: %w", r.Priority, err)
		}
	}
	for _, r := range rules {
		if have[r.Priority] {
			continue
		}
		nr := netlink.NewRule()
		nr.Family = netlink.FAMILY_V4
		nr.Priority = r.Priority
		nr.Mark = uint32(r.Mark)
		nr.Table = r.Table
		if err := netlink.RuleAdd(nr); err != nil {
			return fmt.Errorf("add rule %d: %w", r.Priority, err)
		}
	}
	return nil
}

// setRPFilter sets reverse-path filtering on tunnel interfaces: loose (2)
// normally, off (0) for remapped tunnels whose reply sources are not in the
// main table. The effective value is max(all, iface), so "all" must be 0
// for the remapped case; other interfaces keep their own setting.
func setRPFilter(n render.Network) error {
	off := map[string]bool{}
	for _, name := range n.NoRPFilter {
		off[name] = true
	}
	if len(off) > 0 {
		if err := sysctl("net/ipv4/conf/all/rp_filter", "0"); err != nil {
			return err
		}
	}
	for _, ifc := range n.Interfaces {
		v := "2"
		if off[ifc.Name] {
			v = "0"
		}
		if err := sysctl("net/ipv4/conf/"+ifc.Name+"/rp_filter", v); err != nil {
			return err
		}
	}
	return nil
}

func sysctl(key, value string) error {
	path := "/proc/sys/" + key
	// The interface's sysctl directory can appear a moment after creation.
	var err error
	for range 10 {
		if err = os.WriteFile(path, []byte(value), 0o644); err == nil {
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return fmt.Errorf("sysctl %s: %w", key, err)
}

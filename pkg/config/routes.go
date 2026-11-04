// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"
	"net/netip"
	"net/url"
	"slices"
)

// TunnelAddresses returns the distinct IPv4 addresses that published things
// (app origins, pool members, L4 targets) reach through a tunnel. Hostname
// origins are skipped: the edge resolves those itself.
func (c *Config) TunnelAddresses(tunnel string) []netip.Addr {
	seen := map[netip.Addr]bool{}
	add := func(host string) {
		if a, err := netip.ParseAddr(host); err == nil && a.Is4() {
			seen[a] = true
		}
	}
	addURL := func(raw string) {
		if u, err := url.Parse(raw); err == nil {
			add(u.Hostname())
		}
	}
	for _, a := range c.Apps {
		if a.Pool == "" && a.Origin != "" && a.Tunnel == tunnel {
			addURL(a.Origin)
		}
	}
	for _, p := range c.Pools {
		for _, o := range p.Origins {
			if o.Tunnel == tunnel {
				addURL(o.Address)
			}
		}
	}
	for _, s := range c.L4 {
		if s.Target.Tunnel == tunnel {
			add(s.Target.Address)
		}
	}
	addrs := make([]netip.Addr, 0, len(seen))
	for a := range seen {
		addrs = append(addrs, a)
	}
	slices.SortFunc(addrs, func(a, b netip.Addr) int { return a.Compare(b) })
	return addrs
}

// TunnelRoutes returns the destination prefixes the edge sends down a
// tunnel: its configured subnets, plus a /32 for every published address
// they don't already cover. Routes follow what is published, so subnets are
// optional (like a cloudflared tunnel, you only name the apps); setting them
// makes whole networks reachable, e.g. for remapped tunnels.
func (c *Config) TunnelRoutes(tunnel string) []string {
	t := c.Tunnels[tunnel]
	routes := slices.Clone(t.Subnets)
	var nets []netip.Prefix
	for _, s := range t.Subnets {
		if p, err := netip.ParsePrefix(s); err == nil {
			nets = append(nets, p)
		}
	}
	for _, a := range c.TunnelAddresses(tunnel) {
		if !slices.ContainsFunc(nets, func(p netip.Prefix) bool { return p.Contains(a) }) {
			routes = append(routes, netip.PrefixFrom(a, 32).String())
		}
	}
	return routes
}

// validateTunnelRoutes checks the derived per-address routes: they must not
// collide with ranges the edge owns, and an address may only be routed down
// one tunnel (otherwise the edge can't tell which site it means).
func (c *Config) validateTunnelRoutes(v *validator) {
	var owned []claim
	for _, name := range sortedKeys(c.Tunnels) {
		t := c.Tunnels[name]
		if p, err := netip.ParsePrefix(t.Transit); err == nil {
			owned = append(owned, claim{"tunnels." + name + ".transit", p.Masked()})
		}
		if p, err := netip.ParsePrefix(t.VirtualPrefix); err == nil {
			owned = append(owned, claim{"tunnels." + name + ".virtual_prefix", p.Masked()})
		}
	}

	type route struct {
		tunnel string
		p      netip.Prefix
	}
	var all []route
	for _, name := range sortedKeys(c.Tunnels) {
		for _, r := range c.TunnelRoutes(name) {
			if p, err := netip.ParsePrefix(r); err == nil {
				all = append(all, route{name, p.Masked()})
			}
		}
	}

	for _, r := range all {
		if r.p.Bits() != 32 {
			continue // configured subnets are checked in validateTunnels
		}
		a := r.p.Addr()
		path := "tunnels." + r.tunnel
		if a.IsLoopback() || a.IsUnspecified() || a.IsMulticast() || a.IsLinkLocalUnicast() {
			v.add(path, "published address %s cannot be routed through a tunnel", a)
		}
		if c.Edge.PublicIPv4 != "" && a.String() == c.Edge.PublicIPv4 {
			v.add(path, "published address %s is the edge's own public IP", a)
		}
		for _, o := range owned {
			if o.p.Contains(a) {
				v.add(path, "published address %s is inside %s (%s), which the edge uses itself", a, o.path, o.p)
			}
		}
	}

	reported := map[string]bool{}
	for i, a := range all {
		for _, b := range all[i+1:] {
			if a.tunnel == b.tunnel || !a.p.Overlaps(b.p) {
				continue
			}
			ta, tb := c.Tunnels[a.tunnel], c.Tunnels[b.tunnel]
			if ta.VirtualPrefix != "" && tb.VirtualPrefix != "" {
				continue // both remapped: validateTunnels handles their subnets
			}
			if a.p.Bits() != 32 && b.p.Bits() != 32 {
				continue // subnet vs subnet: reported by validateTunnels
			}
			key := fmt.Sprintf("%s|%s|%s", a.tunnel, b.tunnel, a.p)
			if reported[key] {
				continue
			}
			reported[key] = true
			v.add("tunnels."+b.tunnel, "%s is reached through both tunnel %q (%s) and tunnel %q (%s); give the sites' LANs a virtual_prefix to tell them apart",
				firstAddr(a.p, b.p), a.tunnel, a.p, b.tunnel, b.p)
		}
	}
}

// firstAddr names the more specific of two overlapping prefixes.
func firstAddr(a, b netip.Prefix) string {
	if a.Bits() >= b.Bits() {
		return a.Addr().String()
	}
	return b.Addr().String()
}

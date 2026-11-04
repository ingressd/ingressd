// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strconv"
)

// validEndpoint reports whether s is host:port with a usable host and port.
func validEndpoint(s string) bool {
	host, port, err := net.SplitHostPort(s)
	if err != nil || host == "" {
		return false
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return false
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return true
	}
	return validHostname(host, false)
}

// validateSiblings checks tunnels.<t>.siblings.
// A sibling's transit belongs to another node, so it must not overlap any
// range this node owns (transits and virtual prefixes) nor another sibling
// of the same tunnel.
func (c *Config) validateSiblings(v *validator) {
	var own []claim
	for _, name := range sortedKeys(c.Tunnels) {
		t := c.Tunnels[name]
		for _, s := range []string{t.Transit, t.VirtualPrefix} {
			if p, err := netip.ParsePrefix(s); err == nil {
				own = append(own, claim{"tunnels." + name, p.Masked()})
			}
		}
	}
	for _, name := range sortedKeys(c.Tunnels) {
		t := c.Tunnels[name]
		p := "tunnels." + name
		var seen []claim
		nodes := map[string]bool{}
		keys := map[string]bool{}
		for i, s := range t.Siblings {
			sp := fmt.Sprintf("%s.siblings[%d]", p, i)
			if s.Node != "" {
				if nodes[s.Node] {
					v.add(sp+".node", "node %q is listed twice", s.Node)
				}
				nodes[s.Node] = true
			}
			if !validEndpoint(s.Endpoint) {
				v.add(sp+".endpoint", "must be host:port, got %q", s.Endpoint)
			}
			if !validWGKey(s.EdgePublicKey) {
				v.add(sp+".edge_public_key", "must be a WireGuard public key (base64 of 32 bytes)")
			} else if keys[s.EdgePublicKey] {
				v.add(sp+".edge_public_key", "is listed twice")
			}
			keys[s.EdgePublicKey] = true
			if s.WSURL != "" {
				if u, err := url.Parse(s.WSURL); err != nil || (u.Scheme != "wss" && u.Scheme != "ws") || u.Hostname() == "" {
					v.add(sp+".ws_url", "must be a wss:// URL, got %q", s.WSURL)
				}
			}
			tp, ok := v.prefix(sp+".transit", s.Transit)
			if !ok {
				continue
			}
			if tp.Bits() > 30 {
				v.add(sp+".transit", "must be /30 or larger to hold the edge and site addresses")
			}
			for _, o := range own {
				if o.p.Overlaps(tp) {
					v.add(sp+".transit", "%s overlaps %s (%s) on this node", tp, o.path, o.p)
				}
			}
			for _, o := range seen {
				if o.p.Overlaps(tp) {
					v.add(sp+".transit", "%s overlaps %s (%s)", tp, o.path, o.p)
				}
			}
			seen = append(seen, claim{sp, tp})
		}
	}
}

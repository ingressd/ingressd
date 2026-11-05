// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"
	"net/netip"
	"slices"
)

// ForwardPort is the forward listener's TCP port on the mesh address.
const ForwardPort = 51880

// MaxForwardSiblings caps edge.forward.siblings.<tunnel>.
const MaxForwardSiblings = 4

// Forward is PoP forwarding (edge.forward): an app whose tunnel is down on
// this node is served through a sibling node holding the same site's
// tunnel, over the mesh.
type Forward struct {
	// ListenMesh serves the forward listener on the mesh address
	// (ForwardPort), for siblings forwarding to this node.
	ListenMesh bool `yaml:"listen_mesh"`
	// Secret (secret://name, the same on every node of the mesh) signs
	// forwarded requests.
	Secret string `yaml:"secret"`
	// Siblings lists, per local tunnel, the mesh peers (node ids) that
	// hold the same site, in order of preference.
	Siblings map[string][]string `yaml:"siblings,omitempty"`
}

// ForwardSiblings returns the forward listeners (mesh address:ForwardPort)
// an app falls back to: the siblings of its origins' tunnels, in origin
// order then preference, without repeats.
func (c *Config) ForwardSiblings(app string) []string {
	f := c.Edge.Forward
	if f == nil || c.Mesh == nil {
		return nil
	}
	var out []string
	for _, t := range c.appTunnels(app) {
		for _, id := range f.Siblings[t] {
			a, ok := c.Mesh.Peers[id].PeerAddr()
			if !ok {
				continue
			}
			d := netip.AddrPortFrom(a, ForwardPort).String()
			if !slices.Contains(out, d) {
				out = append(out, d)
			}
		}
	}
	return out
}

// ForwardTarget reports whether the forward listener serves app: it has at
// least one origin through a tunnel.
func (c *Config) ForwardTarget(app string) bool { return len(c.appTunnels(app)) > 0 }

// appTunnels returns the tunnels of an app's origins in origin order.
func (c *Config) appTunnels(app string) []string {
	a, ok := c.Apps[app]
	if !ok {
		return nil
	}
	var out []string
	add := func(t string) {
		if t != "" && !slices.Contains(out, t) {
			out = append(out, t)
		}
	}
	if a.Pool == "" {
		add(a.Tunnel)
		return out
	}
	for _, o := range c.Pools[a.Pool].Origins {
		if o.State != OriginDisabled {
			add(o.Tunnel)
		}
	}
	return out
}

func (c *Config) validateForward(v *validator) {
	f := c.Edge.Forward
	if f == nil {
		return
	}
	const p = "edge.forward"
	if _, ok := c.Mesh.MeshPrefix(); !ok {
		v.add(p, "needs the mesh section (forwarded requests travel over the node mesh)")
	}
	if !secretRefRe.MatchString(f.Secret) {
		v.add(p+".secret", "must be a secret reference secret://name, got %q", f.Secret)
	}
	if !f.ListenMesh && len(f.Siblings) == 0 {
		v.add(p, "set listen_mesh, siblings or both")
	}
	for _, t := range sortedKeys(f.Siblings) {
		sp := p + ".siblings." + t
		if _, ok := c.Tunnels[t]; !ok {
			v.add(sp, "unknown tunnel %q", t)
		}
		ids := f.Siblings[t]
		switch {
		case len(ids) == 0:
			v.add(sp, "at least one sibling is required")
		case len(ids) > MaxForwardSiblings:
			v.add(sp, "at most %d siblings, got %d", MaxForwardSiblings, len(ids))
		}
		for i, id := range ids {
			ip := fmt.Sprintf("%s[%d]", sp, i)
			switch {
			case slices.Index(ids, id) < i:
				v.add(ip, "duplicate sibling %q", id)
			case c.Mesh == nil:
			default:
				if _, ok := c.Mesh.Peers[id]; !ok {
					v.add(ip, "unknown mesh peer %q (siblings are reached over the mesh)", id)
				}
			}
		}
	}
}

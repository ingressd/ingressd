// SPDX-License-Identifier: Apache-2.0

package config

import (
	"encoding/base64"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"strconv"
)

// Mesh and Smart DNS runtime constants shared by the node and the panel.
const (
	// MeshInterface is the WireGuard interface joining the org's nodes.
	MeshInterface = "ix-mesh"
	// MeshKeySecret holds this node's mesh private key (generated if missing).
	MeshKeySecret = "wg-mesh-node"
	// DefaultMeshPort is the mesh WireGuard listen port (UDP).
	DefaultMeshPort = 51900
	// MeshAPIPort serves the mesh HTTP API (ping, exit resolve) on the mesh
	// address only; MeshRelayPort accepts relayed streams from peers.
	MeshAPIPort   = 51901
	MeshRelayPort = 51902
	// ExitSelf in smartdns.exits.<name>.node means this node egresses.
	ExitSelf = "self"
)

// meshPeerIDRe accepts panel node ids (nod_…) and plain names.
var meshPeerIDRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,62}$`)

func (c *Config) applyMeshDefaults() {
	if c.Mesh != nil && c.Mesh.ListenPort == 0 {
		c.Mesh.ListenPort = DefaultMeshPort
	}
}

// MeshPrefix returns the mesh address with its prefix (e.g. 10.255.0.1/16).
func (m *Mesh) MeshPrefix() (netip.Prefix, bool) {
	if m == nil {
		return netip.Prefix{}, false
	}
	p, err := netip.ParsePrefix(m.Address)
	if err != nil || !p.Addr().Is4() {
		return netip.Prefix{}, false
	}
	return p, true
}

// PeerAddr returns a peer's mesh address ("10.255.0.2" or "10.255.0.2/32").
func (p MeshPeer) PeerAddr() (netip.Addr, bool) {
	s := p.Address
	if pr, err := netip.ParsePrefix(s); err == nil {
		if pr.Bits() != 32 || !pr.Addr().Is4() {
			return netip.Addr{}, false
		}
		return pr.Addr(), true
	}
	a, err := netip.ParseAddr(s)
	if err != nil || !a.Is4() {
		return netip.Addr{}, false
	}
	return a, true
}

// validWGKey reports whether s is a base64 WireGuard key (32 bytes).
func validWGKey(s string) bool {
	b, err := base64.StdEncoding.DecodeString(s)
	return err == nil && len(b) == 32
}

func (c *Config) validateMesh(v *validator) {
	m := c.Mesh
	if m == nil {
		return
	}
	if _, ok := c.Tunnels["mesh"]; ok {
		v.add("tunnels.mesh", "the name mesh is reserved (interface %s belongs to the node mesh)", MeshInterface)
	}
	self, ok := m.MeshPrefix()
	if !ok {
		v.add("mesh.address", "must be an IPv4 address with prefix length, e.g. 10.255.0.1/16; got %q", m.Address)
	} else {
		switch {
		case !self.Addr().IsPrivate() && !cgnat.Contains(self.Addr()):
			v.add("mesh.address", "must be a private address (RFC 1918 or 100.64.0.0/10), got %s", self.Addr())
		case self.Bits() > 30 || self.Bits() < 8:
			v.add("mesh.address", "prefix length must be /8 to /30, got /%d", self.Bits())
		case self.Addr() == self.Masked().Addr():
			v.add("mesh.address", "%s is the network address of %s", self.Addr(), self.Masked())
		}
		for _, cl := range c.ownedPrefixes() {
			if cl.p.Overlaps(self.Masked()) {
				v.add("mesh.address", "mesh network %s overlaps %s (%s)", self.Masked(), cl.path, cl.p)
			}
		}
	}
	if m.ListenPort < 1 || m.ListenPort > 65535 {
		v.add("mesh.listen_port", "must be 1-65535, got %d", m.ListenPort)
	}
	for _, name := range sortedKeys(c.Tunnels) {
		if c.Tunnels[name].ListenPort == m.ListenPort {
			v.add("mesh.listen_port", "port %d is already used by tunnel %q", m.ListenPort, name)
		}
	}

	addrs := map[netip.Addr]string{}
	keys := map[string]string{}
	for _, id := range sortedKeys(m.Peers) {
		peer := m.Peers[id]
		p := "mesh.peers." + id
		if !meshPeerIDRe.MatchString(id) || id == ExitSelf {
			v.add(p, "peer id must match %s and not be %q", meshPeerIDRe, ExitSelf)
		}
		if !validWGKey(peer.PublicKey) {
			v.add(p+".public_key", "must be a base64 WireGuard public key")
		} else if other, dup := keys[peer.PublicKey]; dup {
			v.add(p+".public_key", "same key as peer %q", other)
		} else {
			keys[peer.PublicKey] = id
		}
		if peer.Endpoint != "" {
			host, port, err := net.SplitHostPort(peer.Endpoint)
			n, perr := strconv.Atoi(port)
			if err != nil || host == "" || perr != nil || n < 1 || n > 65535 {
				v.add(p+".endpoint", "must be host:port, got %q", peer.Endpoint)
			}
		}
		a, ok := peer.PeerAddr()
		if !ok {
			v.add(p+".address", "must be an IPv4 address (/32), got %q", peer.Address)
			continue
		}
		if self.IsValid() {
			if !self.Masked().Contains(a) {
				v.add(p+".address", "%s is outside the mesh network %s", a, self.Masked())
			}
			if a == self.Addr() {
				v.add(p+".address", "%s is this node's own mesh address", a)
			}
		}
		if other, dup := addrs[a]; dup {
			v.add(p+".address", "%s is already used by peer %q", a, other)
		}
		addrs[a] = id
	}
}

// ownedPrefixes lists networks the edge routes or owns: tunnel transits,
// subnets, virtual prefixes and published routes.
func (c *Config) ownedPrefixes() []claim {
	var out []claim
	for _, name := range sortedKeys(c.Tunnels) {
		t := c.Tunnels[name]
		p := "tunnels." + name
		if tp, err := netip.ParsePrefix(t.Transit); err == nil {
			out = append(out, claim{p + ".transit", tp.Masked()})
		}
		if vp, err := netip.ParsePrefix(t.VirtualPrefix); err == nil {
			out = append(out, claim{p + ".virtual_prefix", vp.Masked()})
		}
		for i, r := range c.TunnelRoutes(name) {
			if rp, err := netip.ParsePrefix(r); err == nil {
				out = append(out, claim{fmt.Sprintf("%s route[%d]", p, i), rp.Masked()})
			}
		}
	}
	return out
}

var cgnat = netip.MustParsePrefix("100.64.0.0/10")

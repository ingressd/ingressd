// SPDX-License-Identifier: Apache-2.0

package render

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/ingressd/ingressd/pkg/config"
)

// MeshMTU is the mesh interface MTU.
const MeshMTU = DefaultMTU

// renderMeshNetwork adds the node mesh interface (ix-mesh) and its peers.
func renderMeshNetwork(cfg *config.Config, res Resolver, n *Network) error {
	m := cfg.Mesh
	if m == nil {
		return nil
	}
	priv, err := res.Resolve("secret://" + config.MeshKeySecret)
	if err != nil {
		return fmt.Errorf("mesh: %w", err)
	}
	ifc := Interface{Name: config.MeshInterface, Address: m.Address, ListenPort: m.ListenPort, MTU: MeshMTU, PrivateKey: priv, Peers: []Peer{}}
	for _, id := range sortedKeys(m.Peers) {
		p := m.Peers[id]
		a, _ := p.PeerAddr()
		ifc.Peers = append(ifc.Peers, Peer{
			PublicKey:  p.PublicKey,
			AllowedIPs: []string{netip.PrefixFrom(a, 32).String()},
			Endpoint:   p.Endpoint,
			Keepalive:  25,
		})
	}
	n.Interfaces = append(n.Interfaces, ifc)
	return nil
}

func meshInputUDP(cfg *config.Config) []int {
	if cfg.Mesh == nil {
		return nil
	}
	return []int{cfg.Mesh.ListenPort}
}

// meshInputRules admits the mesh API (peer probes) from mesh peers on the
// mesh interface only.
func meshInputRules(cfg *config.Config) string {
	m := cfg.Mesh
	if m == nil || len(m.Peers) == 0 {
		return ""
	}
	var peers []string
	for _, id := range sortedKeys(m.Peers) {
		if a, ok := m.Peers[id].PeerAddr(); ok {
			peers = append(peers, a.String())
		}
	}
	if len(peers) == 0 {
		return ""
	}
	return fmt.Sprintf("\t\tiifname %q ip saddr { %s } tcp dport %d accept\n",
		config.MeshInterface, strings.Join(peers, ", "), config.MeshAPIPort)
}

// exitInputRules admits the node exit API from each allowed connector site,
// pinned to the tunnel interface, the site's transit address and the edge's.
func exitInputRules(cfg *config.Config) string {
	var b strings.Builder
	for _, name := range cfg.SmartDNSExitSites() {
		edge, ok1 := cfg.TransitEdgeAddr(name)
		site, ok2 := cfg.TransitSiteAddr(name)
		if !ok1 || !ok2 {
			continue
		}
		fmt.Fprintf(&b, "\t\tiifname %q ip saddr %s ip daddr %s tcp dport { %d, %d } accept\n",
			config.InterfaceName(name), site, edge, config.SmartDNSExitAPIPort, config.SmartDNSExitRelayPort)
	}
	return b.String()
}

// dropOldSmartDNSTables removes the table older nodes used to redirect the
// edge-side Smart DNS relay ports.
const dropOldSmartDNSTables = "add table ip ingressd_smartdns\ndelete table ip ingressd_smartdns\n"

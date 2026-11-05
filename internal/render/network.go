// SPDX-License-Identifier: Apache-2.0

package render

import (
	"fmt"
	"net/netip"

	"github.com/ingressd/ingressd/pkg/config"
)

func renderNetwork(cfg *config.Config, keys Keys) (Network, error) {
	n := Network{Interfaces: []Interface{}, Routes: []Route{}, Rules: []Rule{}, IPForward: l4NeedsForwarding(cfg)}
	for _, name := range sortedKeys(cfg.Tunnels) {
		t := cfg.Tunnels[name]
		ifname := config.InterfaceName(name)
		transit, err := netip.ParsePrefix(t.Transit)
		if err != nil {
			return n, fmt.Errorf("tunnel %s: %w", name, err)
		}
		priv, err := keys.EdgePrivate(name)
		if err != nil {
			return n, fmt.Errorf("tunnel %s: %w", name, err)
		}
		pub, err := keys.SitePublic(name)
		if err != nil {
			return n, fmt.Errorf("tunnel %s: %w", name, err)
		}

		// Remapped tunnels route their whole (translated) subnet; others route
		// their subnets, if any, plus each published address on the tunnel.
		routes := cfg.TunnelRoutes(name)
		if t.VirtualPrefix != "" {
			routes = t.Subnets
		}
		allowed := append([]string{netip.PrefixFrom(SiteAddr(transit), 32).String()}, routes...)
		n.Interfaces = append(n.Interfaces, Interface{
			Name:       ifname,
			Address:    netip.PrefixFrom(EdgeAddr(transit), transit.Bits()).String(),
			ListenPort: t.ListenPort,
			MTU:        DefaultMTU,
			PrivateKey: priv,
			Peers:      []Peer{{PublicKey: pub, AllowedIPs: allowed}},
		})

		if t.VirtualPrefix == "" {
			for _, r := range routes {
				n.Routes = append(n.Routes, Route{Dst: r, Dev: ifname})
			}
			continue
		}
		// Remapped tunnel: sockets connect to the virtual prefix (main
		// table); after DNAT the fwmark picks a table holding the real subnet.
		id := cfg.TunnelTable(name)
		n.Routes = append(n.Routes,
			Route{Dst: t.VirtualPrefix, Dev: ifname},
			Route{Dst: t.Subnets[0], Dev: ifname, Table: id},
		)
		n.Rules = append(n.Rules, Rule{Priority: TunnelRulePriority(id), Mark: id, Table: id})
		n.NoRPFilter = append(n.NoRPFilter, ifname)
	}
	n.Shapes = renderShapes(cfg)
	return n, nil
}

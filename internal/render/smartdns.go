// SPDX-License-Identifier: Apache-2.0

package render

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"github.com/ingressd/ingressd/internal/smartdns/wgconf"
	"github.com/ingressd/ingressd/pkg/config"
)

// Smart DNS exits with a VPN get their own routing table and fwmark,
// starting at VPNTableBase, selected by rules at VPNRulePriorityBase+i.
// Sockets egressing through the VPN set SO_MARK to the table number and bind
// to the interface, so they can never leave by the main route.
const (
	VPNTableBase        = 1900
	VPNRulePriorityBase = RulePriorityBase + 900
	// MeshMTU leaves room for WireGuard over WireGuard (a VPN exit relays
	// mesh traffic over its own tunnel).
	MeshMTU = DefaultMTU
)

// VPNKeySecret and VPNPSKSecret hold the keys taken from an exit's VPN
// .conf (see smartdns.Prepare), so they are redacted from plan diffs.
func VPNKeySecret(exit string) string { return "wg-vpn-" + exit }
func VPNPSKSecret(exit string) string { return "wg-vpn-" + exit + "-psk" }

// VPNMark returns the fwmark (= routing table) for a VPN exit on this node.
func VPNMark(cfg *config.Config, exit string) (int, bool) {
	i := slices.Index(cfg.VPNExits(), exit)
	if i < 0 {
		return 0, false
	}
	return VPNTableBase + i, true
}

// renderSmartDNSNetwork adds the mesh interface and VPN exit interfaces.
func renderSmartDNSNetwork(cfg *config.Config, res Resolver, n *Network) error {
	if m := cfg.Mesh; m != nil {
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
	}

	for i, name := range cfg.VPNExits() {
		e := cfg.SmartDNS.Exits[name]
		text, err := res.Resolve(e.VPN)
		if err != nil {
			return fmt.Errorf("smartdns.exits.%s.vpn: %w", name, err)
		}
		wc, err := wgconf.Parse(text)
		if err != nil {
			return fmt.Errorf("smartdns.exits.%s.vpn: %w", name, err)
		}
		priv, err := res.Resolve("secret://" + VPNKeySecret(name))
		if err != nil {
			return fmt.Errorf("smartdns.exits.%s.vpn: %w", name, err)
		}
		// Every destination goes through the tunnel, whatever the file's
		// AllowedIPs say: only Smart DNS sockets (SO_MARK + SO_BINDTODEVICE)
		// ever use this interface, never the node's own traffic. IPv6
		// addresses, DNS and wg-quick keys of the file are not applied.
		peer := Peer{PublicKey: wc.Peer.PublicKey, AllowedIPs: []string{"0.0.0.0/0"}, Endpoint: wc.Peer.Endpoint, Keepalive: wc.Peer.EffectiveKeepalive()}
		if wc.Peer.PresharedKey != "" {
			if peer.PresharedKey, err = res.Resolve("secret://" + VPNPSKSecret(name)); err != nil {
				return fmt.Errorf("smartdns.exits.%s.vpn: %w", name, err)
			}
		}
		ifname := config.VPNInterfaceName(name)
		mtu := DefaultMTU
		if wc.MTU > 0 {
			mtu = wc.MTU
		}
		n.Interfaces = append(n.Interfaces, Interface{Name: ifname, Address: wc.Address.String(), MTU: mtu, PrivateKey: priv, Peers: []Peer{peer}})
		table := VPNTableBase + i
		// Two /1 routes instead of a default route (as wg-quick does).
		n.Routes = append(n.Routes,
			Route{Dst: "0.0.0.0/1", Dev: ifname, Table: table},
			Route{Dst: "128.0.0.0/1", Dev: ifname, Table: table},
		)
		n.Rules = append(n.Rules, Rule{Priority: VPNRulePriorityBase + i, Mark: table, Table: table})
		n.NoRPFilter = append(n.NoRPFilter, ifname)
	}
	return nil
}

// smartDNSInputUDP lists extra UDP ports the managed firewall opens.
func smartDNSInputUDP(cfg *config.Config) []int {
	if cfg.Mesh == nil {
		return nil
	}
	return []int{cfg.Mesh.ListenPort}
}

var privateSources = "10.0.0.0/8, 100.64.0.0/10, 172.16.0.0/12, 192.168.0.0/16"

// smartDNSInputRules returns input-chain rules for the managed firewall:
// mesh services only from mesh peers on ix-mesh, and the resolver/relay only
// from tunnels (or private sources for explicit LAN listen addresses).
func smartDNSInputRules(cfg *config.Config) string {
	var b strings.Builder
	if m := cfg.Mesh; m != nil && len(m.Peers) > 0 {
		var peers []string
		for _, id := range sortedKeys(m.Peers) {
			if a, ok := m.Peers[id].PeerAddr(); ok {
				peers = append(peers, a.String())
			}
		}
		fmt.Fprintf(&b, "\t\tiifname %q ip saddr { %s } tcp dport { %d, %d } accept\n",
			config.MeshInterface, strings.Join(peers, ", "), config.MeshAPIPort, config.MeshRelayPort)
	}
	transitIf := map[netip.Addr]string{}
	for _, name := range sortedKeys(cfg.Tunnels) {
		if a, ok := cfg.TransitEdgeAddr(name); ok {
			transitIf[a] = config.InterfaceName(name)
		}
	}
	for _, a := range cfg.SmartDNSListen() {
		match := fmt.Sprintf("ip saddr { %s } ip daddr %s", privateSources, a)
		if ifname, ok := transitIf[a]; ok {
			match = fmt.Sprintf("iifname %q ip daddr %s", ifname, a)
		}
		fmt.Fprintf(&b, "\t\t%s meta l4proto { tcp, udp } th dport 53 accept\n", match)
		fmt.Fprintf(&b, "\t\t%s tcp dport { %d, %d } accept\n", match, config.SmartDNSRelayHTTPPort, config.SmartDNSRelayTLSPort)
	}
	return b.String()
}

// renderSmartDNSNFT redirects :443 and :80 on the listen addresses to the
// relay's ports (the edge proxy owns the wildcard :443/:80 sockets).
func renderSmartDNSNFT(cfg *config.Config) string {
	var b strings.Builder
	b.WriteString("add table ip ingressd_smartdns\ndelete table ip ingressd_smartdns\n")
	listen := cfg.SmartDNSListen()
	if len(listen) == 0 {
		return b.String()
	}
	b.WriteString("\ntable ip ingressd_smartdns {\n\tchain prerouting {\n\t\ttype nat hook prerouting priority -100; policy accept;\n")
	for _, a := range listen {
		fmt.Fprintf(&b, "\t\tip daddr %s tcp dport 443 dnat to %s:%d\n", a, a, config.SmartDNSRelayTLSPort)
		fmt.Fprintf(&b, "\t\tip daddr %s tcp dport 80 dnat to %s:%d\n", a, a, config.SmartDNSRelayHTTPPort)
	}
	b.WriteString("\t}\n}\n")
	return b.String()
}

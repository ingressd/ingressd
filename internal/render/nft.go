// SPDX-License-Identifier: Apache-2.0

package render

import (
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/ingressd/ingressd/pkg/config"
)

// dropLegacyTables removes the tables of a pre-rename install (same rules
// under the old names), so an upgraded node never runs both sets.
const dropLegacyTables = "add table inet homeedge # legacy homeedge name, remove after 2027-01\n" + // legacy homeedge name, remove after 2027-01
	"delete table inet homeedge # legacy homeedge name, remove after 2027-01\n" + // legacy homeedge name, remove after 2027-01
	"add table ip homeedge_nat # legacy homeedge name, remove after 2027-01\n" + // legacy homeedge name, remove after 2027-01
	"delete table ip homeedge_nat # legacy homeedge name, remove after 2027-01\n" + // legacy homeedge name, remove after 2027-01
	"add table ip homeedge_l4 # legacy homeedge name, remove after 2027-01\n" + // legacy homeedge name, remove after 2027-01
	"delete table ip homeedge_l4 # legacy homeedge name, remove after 2027-01\n" + // legacy homeedge name, remove after 2027-01
	"add table ip homeedge_smartdns # legacy homeedge name, remove after 2027-01\n" + // legacy homeedge name, remove after 2027-01
	"delete table ip homeedge_smartdns # legacy homeedge name, remove after 2027-01\n" // legacy homeedge name, remove after 2027-01

// renderNFT returns an nft script that atomically replaces ingressd's
// tables. "add" before "delete" makes the delete safe when a table is absent,
// and nft -f applies the whole script as one transaction.
func renderNFT(cfg *config.Config, extraTCP, extraUDP []int) string {
	var b strings.Builder
	b.WriteString(dropLegacyTables)
	b.WriteString("add table inet ingressd\ndelete table inet ingressd\n")
	b.WriteString("add table ip ingressd_nat\ndelete table ip ingressd_nat\n")
	b.WriteString("add table ip ingressd_l4\ndelete table ip ingressd_l4\n")

	if cfg.Edge.FirewallManaged() {
		tcp := append([]int{cfg.Edge.SSHPort, 80, 443}, l4InputTCP(cfg)...)
		tcp = append(tcp, extraTCP...)
		udp := append([]int{443}, smartDNSInputUDP(cfg)...)
		udp = append(udp, extraUDP...)
		for _, t := range cfg.Tunnels {
			udp = append(udp, t.ListenPort)
		}
		var tunnelRules, output string
		rules := smartDNSInputRules(cfg) + connectorInputRules(cfg)
		if cfg.TunnelInputRestricted() {
			tunnelRules = restrictedTunnelInput(cfg)
			rules = smartDNSRules(cfg, false, true)
			output = restrictedOutput(cfg)
		}
		fmt.Fprintf(&b, `
table inet ingressd {
	chain input {
		type filter hook input priority filter; policy drop;
		ct state established,related accept
		ct state invalid drop
		iifname "lo" accept
%s		meta l4proto { icmp, ipv6-icmp } accept
		tcp dport { %s } accept
		udp dport { %s } accept
%s	}

	chain forward {
		type filter hook forward priority filter; policy drop;
		ct state established,related accept
%s	}
%s}
`, tunnelRules, portSet(tcp), portSet(udp), rules, l4ForwardRules(cfg), output)
	}

	var marks, nets []string
	for _, name := range sortedKeys(cfg.Tunnels) {
		t := cfg.Tunnels[name]
		if t.VirtualPrefix == "" {
			continue
		}
		marks = append(marks, fmt.Sprintf("%s : %d", t.VirtualPrefix, cfg.TunnelTable(name)))
		nets = append(nets, fmt.Sprintf("%s : %s", t.VirtualPrefix, t.Subnets[0]))
	}
	if len(marks) > 0 {
		fmt.Fprintf(&b, `
table ip ingressd_nat {
	map vprefix_mark {
		type ipv4_addr : mark
		flags interval
		elements = { %s }
	}

	chain output_route {
		type route hook output priority mangle; policy accept;
		meta mark set ip daddr map @vprefix_mark
	}

	chain output_nat {
		type nat hook output priority -100; policy accept;
		dnat ip prefix to ip daddr map { %s }
	}
}
`, strings.Join(marks, ", "), strings.Join(nets, ", "))
	}
	b.WriteString(renderL4NFT(cfg))
	b.WriteString(renderSmartDNSNFT(cfg))
	return b.String()
}

// restrictedTunnelInput (security.tunnel_input: restricted) admits from each
// tunnel only its connector control port and its Smart DNS address, both
// pinned to the tunnel's own interface and transit addresses, and drops
// everything else arriving on a tunnel interface before the public ports
// are opened: a site must not reach the proxy, SSH or the admin hostname
// through its tunnel (another tenant's apps by Host header, with a source
// address that may satisfy "LAN" IP rules).
func restrictedTunnelInput(cfg *config.Config) string {
	if len(cfg.Tunnels) == 0 {
		return ""
	}
	var ifs []string
	for _, name := range sortedKeys(cfg.Tunnels) {
		ifs = append(ifs, strconv.Quote(config.InterfaceName(name)))
	}
	return connectorInputRules(cfg) + smartDNSRules(cfg, true, false) +
		fmt.Sprintf("\t\tiifname { %s } drop\n", strings.Join(ifs, ", "))
}

// restrictedOutput keeps the proxy from being used to reach cloud metadata
// or the mesh (SSRF through an origin address), plus the networks in
// security.edge_output_deny. It matches unprivileged sockets only: the edge
// runs as its own user, while the control plane (root) uses the mesh
// itself. TCP only, so host daemons that query link-local NTP or DNS
// services keep working.
func restrictedOutput(cfg *config.Config) string {
	v4 := []string{"169.254.0.0/16"}
	v6 := []string{"fd00:ec2::254/128"} // AWS IMDS over IPv6
	if p, ok := cfg.Mesh.MeshPrefix(); ok {
		v4 = append(v4, p.Masked().String())
	}
	for _, s := range cfg.Security.EdgeOutputDeny {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			continue
		}
		if p.Addr().Is4() {
			v4 = append(v4, p.Masked().String())
		} else {
			v6 = append(v6, p.Masked().String())
		}
	}
	return fmt.Sprintf(`
	chain output {
		type filter hook output priority filter; policy accept;
		meta skuid != 0 meta l4proto tcp ip daddr { %s } drop
		meta skuid != 0 meta l4proto tcp ip6 daddr { %s } drop
	}
`, strings.Join(v4, ", "), strings.Join(v6, ", "))
}

func portSet(ports []int) string {
	slices.Sort(ports)
	ports = slices.Compact(ports)
	s := make([]string, len(ports))
	for i, p := range ports {
		s[i] = strconv.Itoa(p)
	}
	return strings.Join(s, ", ")
}

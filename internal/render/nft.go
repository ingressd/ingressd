// SPDX-License-Identifier: Apache-2.0

package render

import (
	"fmt"
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
		fmt.Fprintf(&b, `
table inet ingressd {
	chain input {
		type filter hook input priority filter; policy drop;
		ct state established,related accept
		ct state invalid drop
		iifname "lo" accept
		meta l4proto { icmp, ipv6-icmp } accept
		tcp dport { %s } accept
		udp dport { %s } accept
%s	}

	chain forward {
		type filter hook forward priority filter; policy drop;
		ct state established,related accept
%s	}
}
`, portSet(tcp), portSet(udp), smartDNSInputRules(cfg)+connectorInputRules(cfg), l4ForwardRules(cfg))
	}

	var marks, nets []string
	for i, name := range sortedKeys(cfg.Tunnels) {
		t := cfg.Tunnels[name]
		if t.VirtualPrefix == "" {
			continue
		}
		marks = append(marks, fmt.Sprintf("%s : %d", t.VirtualPrefix, TableBase+i))
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

func portSet(ports []int) string {
	slices.Sort(ports)
	ports = slices.Compact(ports)
	s := make([]string, len(ports))
	for i, p := range ports {
		s[i] = strconv.Itoa(p)
	}
	return strings.Join(s, ", ")
}

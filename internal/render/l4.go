// SPDX-License-Identifier: Apache-2.0

package render

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/ingressd/ingressd/pkg/config"
)

// L4 services (PLAN §11) are forwarded either in the kernel by
// `table ip ingressd_l4` (DNAT, plus masquerade in proxy mode) or, for TCP
// services that need a PROXY protocol header, by caddy-l4 listening on the
// public port. Both engines share the access checks in the table's filter
// chain, which runs in prerouting before DNAT:
//
//   - svc_<name>_static: static allowlist CIDRs from config.yaml.
//   - svc_<name>_allow: runtime entries with per-element timeouts, filled by
//     internal/l4 (CLI and login-to-play). Applies recreate the table, so
//     internal/l4 re-adds the entries after each nftables apply.
//   - svc_<name>_conn / _rate: per-source meters for limits.
//
// Only new connections are checked: removing or expiring an allowlist entry
// stops new connections, established ones keep running until idle.
//
// Traffic reaches neither the access log nor the per-host usage, so the table
// also counts it per service, for both engines:
//
//   - svc_<name>_in / _out / _conns: named counters, read by internal/l4 for
//     usage. An apply recreates the table, which restarts them.
//   - svc_<name>_live: recent new connections, polled for the live preview.

// L4Table is the nftables table holding L4 forwarding and allowlists.
const L4Table = "ingressd_l4"

// L4AllowSet is the runtime allowlist set (flags timeout) of a service.
func L4AllowSet(service string) string { return l4ID(service) + "_allow" }

// L4CounterIn counts bytes from players to a service.
func L4CounterIn(service string) string { return l4ID(service) + "_in" }

// L4CounterOut counts bytes from a service to players.
func L4CounterOut(service string) string { return l4ID(service) + "_out" }

// L4CounterConns counts a service's new connections (in packets).
func L4CounterConns(service string) string { return l4ID(service) + "_conns" }

// L4LiveSet holds a service's recent new connections, keyed by client
// address, protocol and source port.
func L4LiveSet(service string) string { return l4ID(service) + "_live" }

func l4ID(service string) string { return "svc_" + strings.ReplaceAll(service, "-", "_") }

// l4Mark is the fwmark that routes to a remapped tunnel's real subnet (see
// renderNetwork), or 0 for tunnels without a virtual prefix.
func l4Mark(cfg *config.Config, tunnel string) int {
	if cfg.Tunnels[tunnel].VirtualPrefix == "" {
		return 0
	}
	return cfg.TunnelTable(tunnel)
}

// l4NeedsForwarding reports whether any service is forwarded by the kernel,
// which needs net.ipv4.ip_forward.
func l4NeedsForwarding(cfg *config.Config) bool {
	for _, s := range cfg.L4 {
		if s.Engine() == config.L4EngineNFT {
			return true
		}
	}
	return false
}

// l4InputTCP lists the public ports caddy-l4 listens on, which the managed
// input chain must open. Kernel-forwarded ports never reach input.
func l4InputTCP(cfg *config.Config) []int {
	var ports []int
	for _, s := range cfg.L4 {
		if s.Engine() != config.L4EngineCaddy {
			continue
		}
		for _, p := range s.Ports() {
			ports = append(ports, p.Port)
		}
	}
	return ports
}

// l4ForwardRules returns accept rules for the managed `inet ingressd`
// forward chain (policy drop): DNATed connections to each service target.
func l4ForwardRules(cfg *config.Config) string {
	var b strings.Builder
	for _, name := range sortedKeys(cfg.L4) {
		s := cfg.L4[name]
		if s.Engine() != config.L4EngineNFT {
			continue
		}
		for _, p := range s.Ports() {
			fmt.Fprintf(&b, "\t\toifname %q ip daddr %s %s dport %d ct status dnat accept\n",
				config.InterfaceName(s.Target.Tunnel), s.Target.Address, p.Proto, s.TargetPort(p.Port))
		}
	}
	return b.String()
}

// renderL4NFT returns `table ip ingressd_l4`, or "" without L4 services.
func renderL4NFT(cfg *config.Config) string {
	if len(cfg.L4) == 0 {
		return ""
	}
	var counters, sets, filter, svcChains, mark, dnat, snat []string
	var countChains, countForward, countInput, countOutput []string
	for _, name := range sortedKeys(cfg.L4) {
		s := cfg.L4[name]
		id := l4ID(name)
		for _, c := range []string{L4CounterIn(name), L4CounterOut(name), L4CounterConns(name)} {
			counters = append(counters, fmt.Sprintf("\tcounter %s {\n\t}\n", c))
		}
		sets = append(sets, fmt.Sprintf("\tset %s {\n\t\ttype ipv4_addr . inet_proto . inet_service; size 1024; flags dynamic,timeout; timeout 30s;\n\t}\n", L4LiveSet(name)))
		countChains = append(countChains, fmt.Sprintf(`	chain count_%[1]s {
		ct direction original counter name %[2]q
		ct direction reply counter name %[3]q
		ct state new counter name %[4]q
		ct state new add @%[5]s { ip saddr . meta l4proto . th sport }
	}
`, id, L4CounterIn(name), L4CounterOut(name), L4CounterConns(name), L4LiveSet(name)))
		for _, p := range s.Ports() {
			if s.Engine() == config.L4EngineNFT {
				countForward = append(countForward, fmt.Sprintf("ct status dnat meta l4proto %s ct original proto-dst %d jump count_%s", p.Proto, p.Port, id))
			} else {
				countInput = append(countInput, fmt.Sprintf("%s dport %d jump count_%s", p.Proto, p.Port, id))
				countOutput = append(countOutput, fmt.Sprintf("%s sport %d counter name %q", p.Proto, p.Port, L4CounterOut(name)))
			}
		}
		var checks []string
		if s.Restricted() {
			var elems []string
			for _, a := range s.Allowlist {
				if pf, err := config.ParseL4Source(a); err == nil {
					elems = append(elems, pf.String())
				}
			}
			static := "\t\ttype ipv4_addr; flags interval;\n"
			if len(elems) > 0 {
				static += "\t\telements = { " + strings.Join(elems, ", ") + " }\n"
			}
			sets = append(sets,
				fmt.Sprintf("\tset %s_static {\n%s\t}\n", id, static),
				fmt.Sprintf("\tset %s {\n\t\ttype ipv4_addr; flags timeout;\n\t}\n", L4AllowSet(name)))
			checks = append(checks, fmt.Sprintf("ip saddr != @%s_static ip saddr != @%s drop", id, L4AllowSet(name)))
		}
		if l := s.Limits; l != nil && l.ConnPerIP > 0 {
			sets = append(sets, fmt.Sprintf("\tset %s_conn {\n\t\ttype ipv4_addr; size 65535; flags dynamic;\n\t}\n", id))
			checks = append(checks, fmt.Sprintf("add @%s_conn { ip saddr ct count over %d } drop", id, l.ConnPerIP))
		}
		if l := s.Limits; l != nil && l.NewConnRate != "" {
			if n, unit, err := config.ParseRate(l.NewConnRate); err == nil {
				sets = append(sets, fmt.Sprintf("\tset %s_rate {\n\t\ttype ipv4_addr; size 65535; flags dynamic,timeout; timeout 1m;\n\t}\n", id))
				checks = append(checks, fmt.Sprintf("update @%s_rate { ip saddr limit rate over %d/%s } drop", id, n, unit))
			}
		}
		if len(checks) > 0 {
			var keys []string
			for _, p := range s.Ports() {
				keys = append(keys, fmt.Sprintf("%s . %d : jump %s", p.Proto, p.Port, id))
			}
			filter = append(filter, keys...)
			svcChains = append(svcChains, fmt.Sprintf("\tchain %s {\n\t\t%s\n\t}\n", id, strings.Join(checks, "\n\t\t")))
		}

		if s.Engine() != config.L4EngineNFT {
			continue
		}
		m := l4Mark(cfg, s.Target.Tunnel)
		for _, p := range s.Ports() {
			match := fmt.Sprintf("fib daddr type local %s dport %d", p.Proto, p.Port)
			if m != 0 {
				mark = append(mark, fmt.Sprintf("%s meta mark set %d", match, m))
			}
			dnat = append(dnat, fmt.Sprintf("%s dnat to %s:%d", match, s.Target.Address, s.TargetPort(p.Port)))
			// Match the original (public) port: a proxy and a transparent
			// service may share a target address and port.
			if s.Mode == config.L4ModeProxy {
				snat = append(snat, fmt.Sprintf("oifname %q ip daddr %s meta l4proto %s ct original proto-dst %d ct status dnat masquerade",
					config.InterfaceName(s.Target.Tunnel), s.Target.Address, p.Proto, p.Port))
			}
		}
	}

	var b strings.Builder
	fmt.Fprintf(&b, "\ntable ip %s {\n", L4Table)
	for _, c := range counters {
		b.WriteString(c + "\n")
	}
	for _, s := range sets {
		b.WriteString(s + "\n")
	}
	for _, c := range countChains {
		b.WriteString(c + "\n")
	}
	// Before the managed filter chains, so a service's traffic is counted
	// whatever they do with it. Rejected connections were dropped in
	// prerouting and never get here.
	if len(countForward) > 0 {
		fmt.Fprintf(&b, `	chain count_forward {
		type filter hook forward priority -10; policy accept;
		%s
	}

`, strings.Join(countForward, "\n\t\t"))
	}
	if len(countInput) > 0 {
		fmt.Fprintf(&b, `	chain count_input {
		type filter hook input priority -10; policy accept;
		iifname "ix-*" return
		%s
	}

	chain count_output {
		type filter hook output priority -10; policy accept;
		oifname "ix-*" return
		%s
	}

`, strings.Join(countInput, "\n\t\t"), strings.Join(countOutput, "\n\t\t"))
	}
	// Traffic from the tunnels (replies, site-initiated flows) is never
	// subject to the public-facing rules.
	if len(filter) > 0 {
		fmt.Fprintf(&b, `	chain filter {
		type filter hook prerouting priority -160; policy accept;
		iifname "ix-*" return
		ct state != new return
		fib daddr type != local return
		meta l4proto . th dport vmap { %s }
	}

`, strings.Join(filter, ", "))
		for _, c := range svcChains {
			b.WriteString(c + "\n")
		}
	}
	// Remapped tunnels: the real subnet is only routable with the tunnel's
	// fwmark. Marks are per packet, so they are set before DNAT on every
	// packet of the connection (daddr is still the edge's here).
	if len(mark) > 0 {
		fmt.Fprintf(&b, `	chain route_mark {
		type filter hook prerouting priority mangle; policy accept;
		iifname "ix-*" return
		%s
	}

`, strings.Join(mark, "\n\t\t"))
	}
	if len(dnat) > 0 {
		fmt.Fprintf(&b, `	chain prerouting {
		type nat hook prerouting priority dstnat; policy accept;
		iifname "ix-*" return
		%s
	}
`, strings.Join(dnat, "\n\t\t"))
	}
	// Proxy mode: the site host sees (and replies to) the edge's transit
	// address. Transparent mode keeps the client address, so the site must
	// route replies back through the tunnel.
	if len(snat) > 0 {
		fmt.Fprintf(&b, `
	chain postrouting {
		type nat hook postrouting priority srcnat; policy accept;
		%s
	}
`, strings.Join(snat, "\n\t\t"))
	}
	b.WriteString("}\n")
	return b.String()
}

// l4CaddyApp renders the caddy-l4 `layer4` app for services that need a
// PROXY protocol header, or nil if there are none. Caddy dials the target
// from the edge, so remapped tunnels use the virtual address.
func l4CaddyApp(cfg *config.Config) obj {
	servers := obj{}
	for _, name := range sortedKeys(cfg.L4) {
		s := cfg.L4[name]
		if s.Engine() != config.L4EngineCaddy {
			continue
		}
		addr := s.Target.Address
		if a, err := netip.ParseAddr(addr); err == nil {
			addr = Virtual(cfg.Tunnels[s.Target.Tunnel], a).String()
		}
		// Access checks and limits live in `table ip`, so services using them
		// listen on IPv4.
		network := "tcp"
		if s.Restricted() || s.Limits != nil {
			network = "tcp4"
		}
		for _, p := range s.Ports() {
			servers[fmt.Sprintf("l4_%s_%d", strings.ReplaceAll(name, "-", "_"), p.Port)] = obj{
				"listen": []string{fmt.Sprintf("%s/:%d", network, p.Port)},
				"routes": []obj{{
					"handle": []obj{{
						"handler":        "proxy",
						"proxy_protocol": s.ProxyProtocol,
						"upstreams":      []obj{{"dial": []string{fmt.Sprintf("%s:%d", addr, s.TargetPort(p.Port))}}},
					}},
				}},
			}
		}
	}
	if len(servers) == 0 {
		return nil
	}
	return obj{"servers": servers}
}

// SPDX-License-Identifier: Apache-2.0

package l4

import (
	"cmp"
	"fmt"
	"net/netip"
	"strings"

	"github.com/ingressd/ingressd/internal/render"
	"github.com/ingressd/ingressd/pkg/config"
)

// Snippet returns setup notes for a service: game-server settings for its
// preset and, for transparent mode, the site-side return routing.
//
// Game-server setting names are written from memory of the projects' docs
// and are marked UNVERIFIED where they have not been checked against the
// current upstream documentation (see docs/spikes/04-fivem.md).
func Snippet(cfg *config.Config, name string) (string, error) {
	s, ok := cfg.L4[name]
	if !ok {
		return "", fmt.Errorf("unknown l4 service %q", name)
	}
	t := cfg.Tunnels[s.Target.Tunnel]
	transit, _ := netip.ParsePrefix(t.Transit)
	edgeTransit := render.EdgeAddr(transit)
	public := cmp.Or(cfg.Edge.PublicIPv4, cfg.Edge.Admin.Hostname, "<edge public address>")
	ports := s.Ports()
	first := 0
	if len(ports) > 0 {
		first = ports[0].Port
	}

	var b strings.Builder
	fmt.Fprintf(&b, "# l4 service %q: preset %s, mode %s, engine %s\n", name, s.Preset, s.Mode, s.Engine())
	fmt.Fprintf(&b, "# Players connect to %s (%s); traffic goes to %s:%d via tunnel %q.\n",
		public, strings.Join(s.Listen, ", "), s.Target.Address, s.TargetPort(first), s.Target.Tunnel)
	switch {
	case s.Mode == config.L4ModeTransparent:
		b.WriteString("# Transparent mode: the server sees real player IPs.\n")
	case s.Engine() == config.L4EngineCaddy:
		fmt.Fprintf(&b, "# Proxy mode with PROXY protocol %s: connections come from the edge (%s);\n# the real player IP is in the PROXY header, which the server MUST be configured to accept.\n", s.ProxyProtocol, edgeTransit)
	default:
		fmt.Fprintf(&b, "# Proxy mode: the server sees every player as %s (the edge's tunnel address).\n", edgeTransit)
	}
	b.WriteString("\n")

	switch s.Preset {
	case config.PresetFiveM:
		fmt.Fprintf(&b, `## server.cfg (FiveM) — UNVERIFIED: check every convar against the current Cfx.re docs
endpoint_add_tcp "0.0.0.0:%[1]d"
endpoint_add_udp "0.0.0.0:%[1]d"
# Advertise the edge, not your home address, in the server list:
set sv_listingIpOverride "%[2]s"
set sv_listingHostOverride "%[2]s:%[3]d"
set sv_forceIndirectListing true
`, s.TargetPort(first), public, first)
		if s.Mode == config.L4ModeProxy {
			fmt.Fprintf(&b, "# Proxy mode only: treat the edge as a trusted proxy.\nset sv_proxyIPRanges \"%s/32\"\n", edgeTransit)
		}
		b.WriteString("# Publish txAdmin (port 40120) as an HTTP app behind Access, never as an l4 port.\n")
	case config.PresetMinecraftJava:
		if s.Engine() == config.L4EngineCaddy {
			b.WriteString(`## Accept the PROXY protocol header — UNVERIFIED: check against current docs
# Velocity (velocity.toml, [advanced]):
haproxy-protocol = true
# Paper/Purpur without a proxy (config/paper-global.yml):
#   proxies:
#     proxy-protocol: true
# BungeeCord/Waterfall (config.yml, under listeners:):
#   proxy_protocol: true
# Vanilla servers cannot read PROXY headers: set proxy_protocol: none instead.
`)
		} else {
			b.WriteString("## No PROXY protocol: vanilla Minecraft works as is.\n")
		}
	case config.PresetMinecraftBedrock:
		fmt.Fprintf(&b, "## server.properties (Bedrock Dedicated Server)\nserver-port=%d\n", s.TargetPort(first))
	default:
		b.WriteString("## Custom service: no game-specific settings.\n")
	}

	if s.Mode == config.L4ModeTransparent {
		fmt.Fprintf(&b, `
## Site: return routing for transparent mode
Replies from %[1]s to players must go back through the tunnel, not out of
your normal internet connection:
1. In the site's WireGuard config for tunnel %[2]q set
     AllowedIPs = 0.0.0.0/0
   but do NOT route the whole site through it: on UniFi, import the config
   as a VPN Client and do not enable it as the default route.
2. Add a policy-based route: source %[1]s (the game host or its VLAN)
   -> interface: the %[2]q VPN client. UniFi: Settings -> Routing ->
   Policy-Based Routes -> Create, Device/Network = the game host,
   Interface = the VPN client, Kill switch off. (UNVERIFIED against current
   UniFi OS; see docs/spikes/02-udm-wireguard.md.)
   Linux router equivalent:
     ip rule add from %[1]s lookup 100
     ip route add default dev wg0 table 100
3. Firewall: allow VPN -> LAN only to %[1]s on %[3]s.
`, s.Target.Address, s.Target.Tunnel, strings.Join(targetPorts(s), ", "))
	} else {
		fmt.Fprintf(&b, "\n## Site firewall\nAllow VPN -> LAN from %s to %s on %s.\n",
			transit.Masked(), s.Target.Address, strings.Join(targetPorts(s), ", "))
	}
	return b.String(), nil
}

func targetPorts(s config.L4Service) []string {
	var out []string
	for _, p := range s.Ports() {
		out = append(out, fmt.Sprintf("%d/%s", s.TargetPort(p.Port), p.Proto))
	}
	return out
}

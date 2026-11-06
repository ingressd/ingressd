// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"
)

// L4 presets, modes, access types and engines (PLAN §11).
const (
	PresetFiveM            = "fivem"
	PresetMinecraftJava    = "minecraft_java"
	PresetMinecraftBedrock = "minecraft_bedrock"
	PresetCustom           = "custom"

	L4ModeProxy       = "proxy"
	L4ModeTransparent = "transparent"

	L4AccessPublic      = "public"
	L4AccessAllowlist   = "allowlist"
	L4AccessLoginToPlay = "login_to_play"

	// L4EngineNFT forwards in the kernel (DNAT); L4EngineCaddy proxies in
	// userspace with caddy-l4, needed for PROXY protocol injection.
	L4EngineNFT   = "nftables"
	L4EngineCaddy = "caddy-l4"

	DefaultLoginToPlayTTL = 12 * time.Hour
)

// L4Service forwards raw TCP/UDP ports (game servers) to a site host.
type L4Service struct {
	// Preset fills listen ports, target port and mode when they are unset.
	Preset string   `yaml:"preset"`
	Listen []string `yaml:"listen"` // "30120/tcp", "30120/udp"
	Target L4Target `yaml:"target"`
	Mode   string   `yaml:"mode"`
	// ProxyProtocol is v1, v2 or none (TCP only). v1/v2 move the service to
	// the caddy-l4 engine.
	ProxyProtocol string       `yaml:"proxy_protocol"`
	Access        string       `yaml:"access"`
	Allowlist     []string     `yaml:"allowlist"` // static CIDRs or IPs
	LoginToPlay   *LoginToPlay `yaml:"login_to_play"`
	Limits        *L4Limits    `yaml:"limits"`
}

// L4Target is the site host the service forwards to. Address is a real LAN
// IP; for remapped tunnels the renderer translates it.
type L4Target struct {
	Tunnel  string `yaml:"tunnel"`
	Address string `yaml:"address"`
	// Port is the destination port for every listen port; 0 keeps each
	// listen port unchanged.
	Port int `yaml:"port"`
}

// LoginToPlay lets players add their own IP to the service's allowlist by
// signing in on PortalHost under Policy; entries expire after TTL. With
// access.portal_url set, PortalHost may be empty: players sign in on the
// external portal, which relays the allowlist entry to the node.
type LoginToPlay struct {
	Policy     string   `yaml:"policy"`
	TTL        Duration `yaml:"ttl"`
	PortalHost string   `yaml:"portal_host"`
}

type L4Limits struct {
	// ConnPerIP caps concurrent connections (conntrack entries) per source.
	ConnPerIP int `yaml:"conn_per_ip"`
	// NewConnRate caps new connections per source, e.g. "30/s" or "100/m".
	NewConnRate string `yaml:"new_conn_rate"`
}

// L4Port is one parsed listen entry.
type L4Port struct {
	Port  int
	Proto string // tcp or udp
}

func (p L4Port) String() string { return fmt.Sprintf("%d/%s", p.Port, p.Proto) }

// ParseL4Port parses "30120/tcp".
func ParseL4Port(s string) (L4Port, error) {
	port, proto, ok := strings.Cut(strings.TrimSpace(s), "/")
	if !ok || (proto != "tcp" && proto != "udp") {
		return L4Port{}, fmt.Errorf("must be <port>/tcp or <port>/udp, got %q", s)
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return L4Port{}, fmt.Errorf("invalid port in %q", s)
	}
	return L4Port{Port: n, Proto: proto}, nil
}

// Ports returns the parsed listen ports, skipping invalid entries (which
// Validate reports).
func (s L4Service) Ports() []L4Port {
	var out []L4Port
	for _, l := range s.Listen {
		if p, err := ParseL4Port(l); err == nil {
			out = append(out, p)
		}
	}
	return out
}

// TargetPort is the destination port for a listen port.
func (s L4Service) TargetPort(listen int) int {
	if s.Target.Port != 0 {
		return s.Target.Port
	}
	return listen
}

// Engine is the data plane that forwards this service.
func (s L4Service) Engine() string {
	if s.ProxyProtocol == "v1" || s.ProxyProtocol == "v2" {
		return L4EngineCaddy
	}
	return L4EngineNFT
}

// Restricted reports whether only allowlisted sources may connect.
func (s L4Service) Restricted() bool {
	return s.Access == L4AccessAllowlist || s.Access == L4AccessLoginToPlay
}

// ParseRate parses a rate like "30/s", "100/m" or "1000/h" into a count and
// an nftables unit (second, minute, hour).
func ParseRate(s string) (int, string, error) {
	n, unit, ok := strings.Cut(strings.TrimSpace(s), "/")
	count, err := strconv.Atoi(n)
	if !ok || err != nil || count < 1 {
		return 0, "", fmt.Errorf("invalid rate %q (use e.g. 30/s)", s)
	}
	switch unit {
	case "s", "sec", "second":
		return count, "second", nil
	case "m", "min", "minute":
		return count, "minute", nil
	case "h", "hour":
		return count, "hour", nil
	}
	return 0, "", fmt.Errorf("invalid rate unit in %q (use /s, /m or /h)", s)
}

type l4Preset struct {
	listen []string
	port   int
	mode   string
	pp     string
}

var l4Presets = map[string]l4Preset{
	PresetFiveM:            {listen: []string{"30120/tcp", "30120/udp"}, port: 30120, mode: L4ModeTransparent},
	PresetMinecraftJava:    {listen: []string{"25565/tcp"}, port: 25565, mode: L4ModeProxy, pp: "v2"},
	PresetMinecraftBedrock: {listen: []string{"19132/udp"}, port: 19132, mode: L4ModeTransparent},
	PresetCustom:           {mode: L4ModeProxy},
}

func (c *Config) applyL4Defaults() {
	for name, s := range c.L4 {
		if s.Preset == "" {
			s.Preset = PresetCustom
		}
		if p, ok := l4Presets[s.Preset]; ok {
			if len(s.Listen) == 0 {
				s.Listen = slices.Clone(p.listen)
			}
			if s.Target.Port == 0 {
				s.Target.Port = p.port
			}
			if s.Mode == "" {
				s.Mode = p.mode
			}
			// The preset's PROXY protocol only makes sense in proxy mode.
			if s.ProxyProtocol == "" && s.Mode == L4ModeProxy {
				s.ProxyProtocol = p.pp
			}
		}
		if s.ProxyProtocol == "" {
			s.ProxyProtocol = "none"
		}
		if s.Access == "" {
			s.Access = L4AccessPublic
		}
		if lp := s.LoginToPlay; lp != nil && lp.TTL == 0 {
			lp.TTL = Duration(DefaultLoginToPlayTTL)
		}
		c.L4[name] = s
	}
}

func (c *Config) validateL4(v *validator) {
	// Ports the edge itself listens on.
	used := map[L4Port]string{
		{c.Edge.SSHPort, "tcp"}: "edge.ssh_port",
		{80, "tcp"}:             "HTTP",
		{443, "tcp"}:            "HTTPS",
		{443, "udp"}:            "HTTP/3",
	}
	for _, name := range sortedKeys(c.Tunnels) {
		used[L4Port{c.Tunnels[name].ListenPort, "udp"}] = "tunnel " + strconv.Quote(name)
	}
	hosts := map[string]bool{}
	for _, a := range c.Apps {
		for _, h := range a.Hosts {
			hosts[h] = true
		}
	}

	for _, name := range sortedKeys(c.L4) {
		s := c.L4[name]
		p := "l4." + name
		if !nameRe.MatchString(name) {
			v.add(p, "name must match %s", nameRe)
		}
		if _, ok := l4Presets[s.Preset]; !ok {
			v.add(p+".preset", "must be fivem, minecraft_java, minecraft_bedrock or custom; got %q", s.Preset)
		}
		if len(s.Listen) == 0 {
			v.add(p+".listen", "at least one port is required (e.g. 30120/tcp)")
		}
		seen := map[L4Port]bool{}
		for i, l := range s.Listen {
			lp := fmt.Sprintf("%s.listen[%d]", p, i)
			port, err := ParseL4Port(l)
			if err != nil {
				v.add(lp, "%v", err)
				continue
			}
			if seen[port] {
				v.add(lp, "duplicate port %s", port)
				continue
			}
			seen[port] = true
			if other, dup := used[port]; dup {
				v.add(lp, "port %s is already used by %s", port, other)
			} else {
				used[port] = "l4 service " + strconv.Quote(name)
			}
		}

		c.validateL4Target(v, p+".target", s.Target)

		switch s.Mode {
		case L4ModeProxy, L4ModeTransparent:
		default:
			v.add(p+".mode", "must be proxy or transparent; got %q", s.Mode)
		}
		switch s.ProxyProtocol {
		case "none":
		case "v1", "v2":
			if s.Mode == L4ModeTransparent {
				v.add(p+".proxy_protocol", "requires mode proxy (transparent mode keeps the real client IP already)")
			}
			for _, port := range s.Ports() {
				if port.Proto != "tcp" {
					v.add(p+".proxy_protocol", "only applies to TCP; move %s to a separate service", port)
				}
			}
		default:
			v.add(p+".proxy_protocol", "must be none, v1 or v2; got %q", s.ProxyProtocol)
		}

		switch s.Access {
		case L4AccessPublic, L4AccessAllowlist, L4AccessLoginToPlay:
		default:
			v.add(p+".access", "must be public, allowlist or login_to_play; got %q", s.Access)
		}
		if len(s.Allowlist) > 0 && !s.Restricted() {
			v.add(p+".allowlist", "only applies with access allowlist or login_to_play")
		}
		for i, a := range s.Allowlist {
			if _, err := ParseL4Source(a); err != nil {
				v.add(fmt.Sprintf("%s.allowlist[%d]", p, i), "%v", err)
			}
		}
		switch lp := s.LoginToPlay; {
		case s.Access == L4AccessLoginToPlay && lp == nil:
			v.add(p+".login_to_play", "is required with access login_to_play")
		case s.Access != L4AccessLoginToPlay && lp != nil:
			v.add(p+".login_to_play", "only applies with access login_to_play")
		case lp != nil:
			if lp.Policy == "" {
				v.add(p+".login_to_play.policy", "is required")
			}
			if lp.TTL <= 0 {
				v.add(p+".login_to_play.ttl", "must be positive")
			}
			switch h := lp.PortalHost; {
			case h == "" && c.Access != nil && c.Access.PortalURL != "":
				// Played through the external portal (access.portal_url).
			case h == "":
				v.add(p+".login_to_play.portal_host", "is required (or set access.portal_url)")
			case !servableHostname(h, false):
				v.add(p+".login_to_play.portal_host", "invalid hostname %q", h)
			case hosts[h]:
				v.add(p+".login_to_play.portal_host", "%q is already served by an app", h)
			case h == c.Edge.Admin.Hostname:
				v.add(p+".login_to_play.portal_host", "%q is the admin hostname", h)
			}
		}

		if l := s.Limits; l != nil {
			if l.ConnPerIP < 0 {
				v.add(p+".limits.conn_per_ip", "must not be negative")
			}
			if l.NewConnRate != "" {
				if _, _, err := ParseRate(l.NewConnRate); err != nil {
					v.add(p+".limits.new_conn_rate", "%v", err)
				}
			}
		}
	}
}

func (c *Config) validateL4Target(v *validator, p string, t L4Target) {
	if t.Port < 0 || t.Port > 65535 {
		v.add(p+".port", "must be 1-65535, got %d", t.Port)
	}
	tun, ok := c.Tunnels[t.Tunnel]
	switch {
	case t.Tunnel == "":
		v.add(p+".tunnel", "is required")
	case !ok:
		v.add(p+".tunnel", "unknown tunnel %q", t.Tunnel)
	}
	addr, err := netip.ParseAddr(t.Address)
	if err != nil || !addr.Is4() {
		v.add(p+".address", "must be an IPv4 address, got %q", t.Address)
		return
	}
	if ok && !tunnelCovers(tun, addr) {
		v.add(p+".address", "%s is not inside the subnets of tunnel %q, which is remapped (virtual_prefix)", addr, t.Tunnel)
	}
}

// ParseL4Source parses an allowlist entry: an IPv4 address or CIDR.
func ParseL4Source(s string) (netip.Prefix, error) {
	if !strings.Contains(s, "/") {
		a, err := netip.ParseAddr(s)
		if err != nil || !a.Is4() {
			return netip.Prefix{}, fmt.Errorf("invalid IPv4 address or CIDR %q", s)
		}
		return netip.PrefixFrom(a, 32), nil
	}
	pf, err := netip.ParsePrefix(s)
	if err != nil || !pf.Addr().Is4() {
		return netip.Prefix{}, fmt.Errorf("invalid IPv4 address or CIDR %q", s)
	}
	if pf != pf.Masked() {
		return netip.Prefix{}, fmt.Errorf("%q has host bits set (did you mean %s?)", s, pf.Masked())
	}
	return pf, nil
}

// LoginToPlayHosts returns the distinct portal hosts of login-to-play
// services, sorted.
func (c *Config) LoginToPlayHosts() []string {
	var hosts []string
	for _, s := range c.L4 {
		if s.Access == L4AccessLoginToPlay && s.LoginToPlay != nil && s.LoginToPlay.PortalHost != "" {
			hosts = append(hosts, s.LoginToPlay.PortalHost)
		}
	}
	slices.Sort(hosts)
	return slices.Compact(hosts)
}

// L4Services maps service names to their configuration.
type L4Services = map[string]L4Service

// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"
	"hash/fnv"
	"net"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

const (
	// SmartDNSRelayTLSPort and SmartDNSRelayHTTPPort are where the relay
	// listens on each listen address; nftables redirects :443 and :80 there,
	// so the relay never competes with the edge proxy for those ports.
	SmartDNSRelayTLSPort  = 51443
	SmartDNSRelayHTTPPort = 51080
	// MaxVPNExitNameLen is the longest exit name used verbatim in its VPN
	// interface name (VPNInterfaceName); longer names are hashed.
	MaxVPNExitNameLen = 10
	// MaxSmartDNSServiceExits caps a service's exit list.
	MaxSmartDNSServiceExits = 4
	// DefaultSmartDNSFailbackAfter and MaxSmartDNSFailbackAfter bound
	// smartdns.failback_after.
	DefaultSmartDNSFailbackAfter = 5 * time.Minute
	MaxSmartDNSFailbackAfter     = time.Hour
)

// DefaultSmartDNSUpstream resolves names that no service routes.
var DefaultSmartDNSUpstream = []string{"1.1.1.1", "9.9.9.9"}

var (
	exitCountryRe = regexp.MustCompile(`^[A-Z]{2}$`)
	secretRefRe   = regexp.MustCompile(`^secret://[a-z0-9][a-z0-9_-]{0,63}$`)
)

// VPNInterfaceName is the WireGuard interface an exit's VPN uses:
// "ix-x-<exit>" when that fits Linux's 15-byte limit, otherwise the first
// four characters of the name and a hash of the whole name
// ("ix-x-prot-3fa9c1" style, always 15 bytes), so panel exit names of any
// length (one node can host several VPN exits) get stable, distinct
// interfaces.
func VPNInterfaceName(exit string) string {
	if len(exit) <= MaxVPNExitNameLen {
		return "ix-x-" + exit
	}
	h := fnv.New32a()
	_, _ = h.Write([]byte(exit)) // hash.Hash.Write never returns an error
	return fmt.Sprintf("ix-x-%s-%05x", strings.TrimRight(exit[:4], "-"), h.Sum32()&0xfffff)
}

// IsEnabled reports whether a service is enabled (default true).
func (s SmartDNSService) IsEnabled() bool { return s.Enabled == nil || *s.Enabled }

// ExitList returns the service's exits in order of preference, accepting
// the single exit form when the config was not normalised by loading.
func (s SmartDNSService) ExitList() []string {
	if len(s.Exits) == 0 && s.Exit != "" {
		return []string{s.Exit}
	}
	return s.Exits
}

// FailbackDuration is FailbackAfter with its default applied.
func (s *SmartDNS) FailbackDuration() time.Duration {
	if s == nil || s.FailbackAfter == nil {
		return DefaultSmartDNSFailbackAfter
	}
	return time.Duration(*s.FailbackAfter)
}

// IsSelf reports whether this node egresses for the exit.
func (e SmartDNSExit) IsSelf() bool { return e.Node == ExitSelf }

func (c *Config) applySmartDNSDefaults() {
	c.applyMeshDefaults()
	s := c.SmartDNS
	if s == nil {
		return
	}
	if len(s.Upstream) == 0 {
		s.Upstream = slices.Clone(DefaultSmartDNSUpstream)
	}
	for name, svc := range s.Services {
		for i, d := range svc.Domains {
			svc.Domains[i] = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(d)), ".")
		}
		// Both set is left as is for validation to reject.
		if svc.Exit != "" && len(svc.Exits) == 0 {
			svc.Exits, svc.Exit = []string{svc.Exit}, ""
		}
		s.Services[name] = svc
	}
	for name, e := range s.Exits {
		e.Country = strings.ToUpper(e.Country)
		s.Exits[name] = e
	}
}

// SmartDNSListen returns the addresses the resolver and relay bind: the
// configured ones, or by default every tunnel's edge transit address.
func (c *Config) SmartDNSListen() []netip.Addr {
	if c.SmartDNS == nil || !c.SmartDNS.Enabled {
		return nil
	}
	var out []netip.Addr
	if len(c.SmartDNS.Listen) > 0 {
		for _, s := range c.SmartDNS.Listen {
			if a, err := netip.ParseAddr(s); err == nil {
				out = append(out, a)
			}
		}
	} else {
		for _, name := range sortedKeys(c.Tunnels) {
			if a, ok := c.TransitEdgeAddr(name); ok {
				out = append(out, a)
			}
		}
	}
	slices.SortFunc(out, func(a, b netip.Addr) int { return a.Compare(b) })
	return slices.Compact(out)
}

// TransitEdgeAddr is the edge's own address in a tunnel's transit network
// (the first host).
func (c *Config) TransitEdgeAddr(tunnel string) (netip.Addr, bool) {
	t, ok := c.Tunnels[tunnel]
	if !ok {
		return netip.Addr{}, false
	}
	p, err := netip.ParsePrefix(t.Transit)
	if err != nil || !p.Addr().Is4() {
		return netip.Addr{}, false
	}
	return p.Masked().Addr().Next(), true
}

// VPNExits returns the names of exits this node egresses for through a VPN,
// sorted (their index picks the routing table, see VPNTable).
func (c *Config) VPNExits() []string {
	if c.SmartDNS == nil {
		return nil
	}
	var out []string
	for _, name := range sortedKeys(c.SmartDNS.Exits) {
		if e := c.SmartDNS.Exits[name]; e.IsSelf() && e.VPN != "" {
			out = append(out, name)
		}
	}
	return out
}

func (c *Config) validateSmartDNS(v *validator) {
	s := c.SmartDNS
	if s == nil {
		return
	}
	transits := map[netip.Addr]bool{}
	for _, name := range sortedKeys(c.Tunnels) {
		if a, ok := c.TransitEdgeAddr(name); ok {
			transits[a] = true
		}
	}
	meshAddr := netip.Addr{}
	if p, ok := c.Mesh.MeshPrefix(); ok {
		meshAddr = p.Addr()
	}
	seen := map[netip.Addr]bool{}
	for i, l := range s.Listen {
		p := fmt.Sprintf("smartdns.listen[%d]", i)
		a, err := netip.ParseAddr(l)
		switch {
		case err != nil || !a.Is4():
			v.add(p, "must be an IPv4 address, got %q", l)
			continue
		case seen[a]:
			v.add(p, "duplicate address %s", a)
		case a == meshAddr:
			v.add(p, "%s is the mesh address; the resolver must listen on tunnel transit or LAN addresses", a)
		case transits[a]:
		case a.IsPrivate() || cgnat.Contains(a):
			// An explicitly allowed private (LAN) address.
		default:
			v.add(p, "%s is neither a tunnel transit address nor a private address; the resolver must never listen on public interfaces", a)
		}
		seen[a] = true
	}
	for i, u := range s.Upstream {
		if !validUpstream(u) {
			v.add(fmt.Sprintf("smartdns.upstream[%d]", i), "must be an IP address or IP:port, got %q", u)
		}
	}

	for _, name := range sortedKeys(s.Exits) {
		e := s.Exits[name]
		p := "smartdns.exits." + name
		if !nameRe.MatchString(name) {
			v.add(p, "name must match %s", nameRe)
		}
		switch {
		case e.Node == "":
			v.add(p+".node", "is required (self or a mesh peer id)")
		case e.IsSelf():
		case c.Mesh == nil:
			v.add(p+".node", "exit on node %q needs the mesh section", e.Node)
		default:
			if _, ok := c.Mesh.Peers[e.Node]; !ok {
				v.add(p+".node", "unknown mesh peer %q (expected self or one of mesh.peers)", e.Node)
			}
		}
		if !exitCountryRe.MatchString(e.Country) {
			v.add(p+".country", "must be an ISO 3166-1 alpha-2 country code, got %q", e.Country)
		}
		if e.VPN != "" {
			if !secretRefRe.MatchString(e.VPN) {
				v.add(p+".vpn", "must be a secret reference secret://name, got %q", e.VPN)
			}
			if e.IsSelf() {
				ifname := VPNInterfaceName(name)
				for _, t := range sortedKeys(c.Tunnels) {
					if InterfaceName(t) == ifname {
						v.add(p, "interface %q is already used by tunnel %q", ifname, t)
					}
				}
				for _, other := range sortedKeys(s.Exits) {
					if o := s.Exits[other]; other < name && o.IsSelf() && o.VPN != "" && VPNInterfaceName(other) == ifname {
						v.add(p, "interface %q is already used by exit %q; rename one of them", ifname, other)
					}
				}
			}
		}
	}

	owners := map[string]string{}
	for _, name := range sortedKeys(s.Services) {
		svc := s.Services[name]
		p := "smartdns.services." + name
		if !nameRe.MatchString(name) {
			v.add(p, "name must match %s", nameRe)
		}
		c.validateServiceExits(v, p, svc)
		if len(svc.Domains) == 0 {
			v.add(p+".domains", "at least one domain is required")
		}
		for i, d := range svc.Domains {
			dp := fmt.Sprintf("%s.domains[%d]", p, i)
			if !validHostname(d, false) {
				v.add(dp, "invalid domain %q (use the bare suffix, e.g. example.com)", d)
				continue
			}
			if !svc.IsEnabled() {
				continue
			}
			if other, dup := owners[d]; dup {
				v.add(dp, "%q is already routed by service %q", d, other)
			} else {
				owners[d] = name
			}
		}
	}

	if f := s.FailbackAfter; f != nil && (*f < 0 || time.Duration(*f) > MaxSmartDNSFailbackAfter) {
		v.add("smartdns.failback_after", "must be between 0s and %s, got %s", MaxSmartDNSFailbackAfter, time.Duration(*f))
	}

	for i, c := range s.Checks {
		p := fmt.Sprintf("smartdns.checks[%d]", i)
		if len(c.Domains) == 0 {
			v.add(p+".domains", "at least one domain is required")
		}
		for j, d := range c.Domains {
			if !validHostname(d, false) {
				v.add(fmt.Sprintf("%s.domains[%d]", p, j), "invalid domain %q", d)
			}
		}
		if !validHostname(c.Host, false) {
			v.add(p+".host", "must be a hostname, got %q", c.Host)
		}
		// Path and host go into a raw HTTP request line.
		if !checkPathRe.MatchString(c.Path) {
			v.add(p+".path", "must start with / and contain no spaces or control characters, got %q", c.Path)
		}
		if !checkTokenRe.MatchString(c.Field) {
			v.add(p+".field", "must match %s, got %q", checkTokenRe, c.Field)
		}
		if c.CacheBuster != "" && !checkTokenRe.MatchString(c.CacheBuster) {
			v.add(p+".cache_buster", "must match %s, got %q", checkTokenRe, c.CacheBuster)
		}
	}
}

// validateServiceExits checks a service's exit list: 1 to 4 known, distinct
// exits of one country, so failing over never changes where the service
// appears to be.
func (c *Config) validateServiceExits(v *validator, p string, svc SmartDNSService) {
	s := c.SmartDNS
	if svc.Exit != "" && len(svc.Exits) > 0 {
		v.add(p, "set exit or exits, not both")
		return
	}
	list := svc.ExitList()
	switch {
	case len(list) == 0:
		v.add(p+".exits", "is required")
		return
	case len(list) > MaxSmartDNSServiceExits:
		v.add(p+".exits", "at most %d exits, got %d", MaxSmartDNSServiceExits, len(list))
	}
	seen := map[string]bool{}
	first := ""
	for i, name := range list {
		ep := fmt.Sprintf("%s.exits[%d]", p, i)
		if seen[name] {
			v.add(ep, "duplicate exit %q", name)
			continue
		}
		seen[name] = true
		ex, ok := s.Exits[name]
		if !ok {
			v.add(ep, "unknown exit %q", name)
			continue
		}
		if i == 0 {
			first = ex.Country
		} else if first != "" && ex.Country != first {
			v.add(ep, "country %s differs from %s of exits[0]", ex.Country, first)
		}
	}
}

var (
	checkPathRe  = regexp.MustCompile(`^/[\x21-\x7e]*$`)
	checkTokenRe = regexp.MustCompile(`^[A-Za-z0-9_]{1,64}$`)
)

func validUpstream(s string) bool {
	if a, err := netip.ParseAddr(s); err == nil {
		return a.Zone() == ""
	}
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		return false
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return false
	}
	_, err = netip.ParseAddr(host)
	return err == nil
}

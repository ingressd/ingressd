// SPDX-License-Identifier: Apache-2.0

package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

const (
	// MaxSmartDNSServiceExits caps a service's exit list.
	MaxSmartDNSServiceExits = 4
	// DefaultSmartDNSFailbackAfter and MaxSmartDNSFailbackAfter bound
	// failback_after.
	DefaultSmartDNSFailbackAfter = 5 * time.Minute
	MaxSmartDNSFailbackAfter     = time.Hour
	// MaxTunnelSmartDNS bounds a tunnel's signed Smart DNS config.
	MaxTunnelSmartDNS = 256 << 10
	// MaxExitVPNConfig bounds an encrypted VPN config.
	MaxExitVPNConfig = 16 << 10
)

// DefaultSmartDNSUpstream resolves names that no service routes.
var DefaultSmartDNSUpstream = []string{"1.1.1.1", "9.9.9.9"}

var (
	exitCountryRe = regexp.MustCompile(`^[A-Z]{2}$`)
	secretRefRe   = regexp.MustCompile(`^secret://[a-z0-9][a-z0-9_-]{0,63}$`)
	checkPathRe   = regexp.MustCompile(`^/[\x21-\x7e]*$`)
	checkTokenRe  = regexp.MustCompile(`^[A-Za-z0-9_]{1,64}$`)
	siteNameRe    = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,62}$`)
)

func (c *Config) applySmartDNSDefaults() {
	c.applyMeshDefaults()
	if c.SmartDNS == nil || c.SmartDNS.Exit == nil {
		return
	}
	e := c.SmartDNS.Exit
	e.Country = strings.ToUpper(strings.TrimSpace(e.Country))
	if len(e.Upstream) == 0 {
		e.Upstream = slices.Clone(DefaultSmartDNSUpstream)
	}
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

// TransitSiteAddr is the site's address in a tunnel's transit network (the
// second host).
func (c *Config) TransitSiteAddr(tunnel string) (netip.Addr, bool) {
	a, ok := c.TransitEdgeAddr(tunnel)
	if !ok {
		return netip.Addr{}, false
	}
	return a.Next(), true
}

// SmartDNSExitSites returns the tunnels allowed to use this node's exit
// that exist on the node, sorted.
func (c *Config) SmartDNSExitSites() []string {
	if c.SmartDNS == nil || c.SmartDNS.Exit == nil {
		return nil
	}
	var out []string
	for _, s := range c.SmartDNS.Exit.Sites {
		if _, ok := c.Tunnels[s]; ok {
			out = append(out, s)
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

func (c *Config) validateSmartDNS(v *validator) {
	for _, name := range sortedKeys(c.Tunnels) {
		t := c.Tunnels[name]
		if t.SmartDNS == "" {
			continue
		}
		p := "tunnels." + name + ".smartdns"
		switch {
		case t.Site != SiteConnector:
			v.add(p, "only connector sites run Smart DNS")
		case len(t.SmartDNS) > MaxTunnelSmartDNS:
			v.add(p, "is larger than %d bytes", MaxTunnelSmartDNS)
		case !json.Valid([]byte(t.SmartDNS)):
			v.add(p, "must be a signed Smart DNS config (JSON)")
		}
	}

	if c.SmartDNS == nil || c.SmartDNS.Exit == nil {
		return
	}
	e := c.SmartDNS.Exit
	p := "smartdns.exit"
	if len(c.Realms) > 0 {
		v.add(p, "is not allowed alongside realms (shared nodes host no exits)")
	}
	if !exitCountryRe.MatchString(e.Country) {
		v.add(p+".country", "must be an ISO 3166-1 alpha-2 country code, got %q", e.Country)
	}
	if len(e.Sites) == 0 {
		v.add(p+".sites", "at least one connector site is required")
	}
	for i, s := range e.Sites {
		sp := fmt.Sprintf("%s.sites[%d]", p, i)
		t, ok := c.Tunnels[s]
		switch {
		case !ok:
			v.add(sp, "unknown tunnel %q", s)
		case t.Site != SiteConnector:
			v.add(sp, "tunnel %q is not a connector site", s)
		}
	}
	for i, u := range e.Upstream {
		if !validUpstream(u) {
			v.add(fmt.Sprintf("%s.upstream[%d]", p, i), "must be an IP address or IP:port, got %q", u)
		}
	}
	validateChecks(v, p, e.Checks)
}

func validateChecks(v *validator, p string, checks []SmartDNSCheck) {
	for i, ck := range checks {
		cp := fmt.Sprintf("%s.checks[%d]", p, i)
		if len(ck.Domains) == 0 {
			v.add(cp+".domains", "at least one domain is required")
		}
		for j, d := range ck.Domains {
			if !validHostname(d, false) {
				v.add(fmt.Sprintf("%s.domains[%d]", cp, j), "invalid domain %q", d)
			}
		}
		if !validHostname(ck.Host, false) {
			v.add(cp+".host", "must be a hostname, got %q", ck.Host)
		}
		// Path and host go into a raw HTTP request line.
		if !checkPathRe.MatchString(ck.Path) {
			v.add(cp+".path", "must start with / and contain no spaces or control characters, got %q", ck.Path)
		}
		if !checkTokenRe.MatchString(ck.Field) {
			v.add(cp+".field", "must match %s, got %q", checkTokenRe, ck.Field)
		}
		if ck.CacheBuster != "" && !checkTokenRe.MatchString(ck.CacheBuster) {
			v.add(cp+".cache_buster", "must match %s, got %q", checkTokenRe, ck.CacheBuster)
		}
	}
}

// Normalize lower-cases domains, upper-cases countries and fills in the
// default upstreams.
func (s *SmartDNSSite) Normalize() {
	if len(s.Upstream) == 0 {
		s.Upstream = slices.Clone(DefaultSmartDNSUpstream)
	}
	for name, svc := range s.Services {
		for i, d := range svc.Domains {
			svc.Domains[i] = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(d)), ".")
		}
		s.Services[name] = svc
	}
	for name, e := range s.Exits {
		e.Country = strings.ToUpper(strings.TrimSpace(e.Country))
		s.Exits[name] = e
	}
}

// FailbackDuration is FailbackAfter with its default applied (an invalid
// value is refused by Validate).
func (s *SmartDNSSite) FailbackDuration() time.Duration {
	if s.FailbackAfter == "" {
		return DefaultSmartDNSFailbackAfter
	}
	d, err := time.ParseDuration(s.FailbackAfter)
	if err != nil {
		return DefaultSmartDNSFailbackAfter
	}
	return d
}

// ListenAddr returns the configured listen address (invalid when unset).
func (s *SmartDNSSite) ListenAddr() netip.Addr {
	a, _ := netip.ParseAddr(s.Listen)
	return a
}

// Validate checks a connector site's Smart DNS config (call Normalize
// first).
func (s *SmartDNSSite) Validate() error {
	v := &validator{}
	if s.Listen != "" {
		a, err := netip.ParseAddr(s.Listen)
		switch {
		case err != nil || !a.Is4():
			v.add("listen", "must be an IPv4 address, got %q", s.Listen)
		case !a.IsPrivate() && !a.IsLoopback() && !cgnat.Contains(a):
			v.add("listen", "%s is not a private address; the resolver must never listen on public interfaces", a)
		}
	}
	for i, u := range s.Upstream {
		if !validUpstream(u) {
			v.add(fmt.Sprintf("upstream[%d]", i), "must be an IP address or IP:port, got %q", u)
		}
	}
	if s.FailbackAfter != "" {
		d, err := time.ParseDuration(s.FailbackAfter)
		if err != nil || d < 0 || d > MaxSmartDNSFailbackAfter {
			v.add("failback_after", "must be a duration between 0s and %s, got %q", MaxSmartDNSFailbackAfter, s.FailbackAfter)
		}
	}
	nodes := map[string]string{}
	for _, name := range sortedKeys(s.Exits) {
		e := s.Exits[name]
		p := "exits." + name
		if !siteNameRe.MatchString(name) {
			v.add(p, "name must match %s", siteNameRe)
		}
		if !exitCountryRe.MatchString(e.Country) {
			v.add(p+".country", "must be an ISO 3166-1 alpha-2 country code, got %q", e.Country)
		}
		switch e.At {
		case ExitAtConnector:
			switch {
			case e.VPN == "":
				v.add(p+".vpn", "is required for a connector exit")
			case len(e.VPN) > MaxExitVPNConfig:
				v.add(p+".vpn", "is larger than %d bytes", MaxExitVPNConfig)
			}
			if e.Node != "" {
				v.add(p+".node", "only applies to a node exit")
			}
		case ExitAtNode:
			if !meshPeerIDRe.MatchString(e.Node) {
				v.add(p+".node", "must be a node id, got %q", e.Node)
			} else if other, dup := nodes[e.Node]; dup {
				v.add(p+".node", "node %s is already exit %q (a node has one exit)", e.Node, other)
			}
			nodes[e.Node] = name
			if e.VPN != "" {
				v.add(p+".vpn", "nodes egress from their own IP; VPNs run on the connector only")
			}
		case ExitAtOperator:
			v.add(p+".at", "operator exits are not offered")
		default:
			v.add(p+".at", "must be %s or %s, got %q", ExitAtConnector, ExitAtNode, e.At)
		}
	}
	owners := map[string]string{}
	for _, name := range sortedKeys(s.Services) {
		svc := s.Services[name]
		p := "services." + name
		if !siteNameRe.MatchString(name) {
			v.add(p, "name must match %s", siteNameRe)
		}
		s.validateServiceExits(v, p, svc)
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
	validateChecks(v, "checks", s.Checks)
	return errors.Join(v.errs...)
}

// validateServiceExits: 1 to 4 known, distinct exits, all of one country,
// so failing over never changes where the service appears to be.
func (s *SmartDNSSite) validateServiceExits(v *validator, p string, svc SmartDNSSiteService) {
	switch {
	case len(svc.Exits) == 0:
		v.add(p+".exits", "is required")
		return
	case len(svc.Exits) > MaxSmartDNSServiceExits:
		v.add(p+".exits", "at most %d exits, got %d", MaxSmartDNSServiceExits, len(svc.Exits))
	}
	seen := map[string]bool{}
	first := ""
	for i, name := range svc.Exits {
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

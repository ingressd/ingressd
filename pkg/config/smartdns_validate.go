// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"
	"hash/fnv"
	"maps"
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
	// VPNTableMin and VPNTableMax bound the routing tables (and fwmarks) of
	// VPN exits, right above the tunnels' range; the policy-routing rule
	// priority follows from the table, so 100 tables fit ingressd's range.
	VPNTableMin = TunnelTableMax + 1
	VPNTableMax = VPNTableMin + 99
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
	return fmt.Sprintf("ix-x-%s-%05x", strings.TrimRight(exit[:4], "-."), h.Sum32()&0xfffff)
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

// SmartDNSScope is one Smart DNS block: the node's own (smartdns, Realm "")
// or a realm's (realms.<r>.smartdns). Each has its own services, exits,
// upstreams and listen addresses; Listen is empty when it is disabled (a
// block may only host exits).
type SmartDNSScope struct {
	Realm  string
	DNS    *SmartDNS
	Listen []netip.Addr
}

// SmartDNSScopes returns every Smart DNS block, the node's own first, then
// the realms' by name.
func (c *Config) SmartDNSScopes() []SmartDNSScope {
	var out []SmartDNSScope
	if c.SmartDNS != nil {
		out = append(out, SmartDNSScope{DNS: c.SmartDNS, Listen: c.scopeListen("", c.SmartDNS)})
	}
	for _, name := range sortedKeys(c.Realms) {
		if s := c.Realms[name].SmartDNS; s != nil {
			out = append(out, SmartDNSScope{Realm: name, DNS: s, Listen: c.scopeListen(name, s)})
		}
	}
	return out
}

func (c *Config) applySmartDNSDefaults() {
	c.applyMeshDefaults()
	for _, sc := range c.SmartDNSScopes() {
		s := sc.DNS
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
}

// SmartDNSListen returns the addresses every resolver and relay binds: the
// union of the scopes' listen addresses.
func (c *Config) SmartDNSListen() []netip.Addr {
	var out []netip.Addr
	for _, sc := range c.SmartDNSScopes() {
		out = append(out, sc.Listen...)
	}
	slices.SortFunc(out, func(a, b netip.Addr) int { return a.Compare(b) })
	return slices.Compact(out)
}

// scopeListen returns where one block's resolver and relay bind: the
// configured addresses, or by default the edge transit address of every
// tunnel (the realm's tunnels, for a realm's block).
func (c *Config) scopeListen(realm string, s *SmartDNS) []netip.Addr {
	if s == nil || !s.Enabled {
		return nil
	}
	var out []netip.Addr
	if len(s.Listen) > 0 {
		for _, l := range s.Listen {
			if a, err := netip.ParseAddr(l); err == nil {
				out = append(out, a)
			}
		}
	} else {
		for _, name := range sortedKeys(c.Tunnels) {
			if realm != "" && c.Tunnels[name].Realm != realm {
				continue
			}
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

// SmartDNSExit looks an exit up in every block and returns the realm whose
// block defines it ("" for the node's own). Exit names are unique across
// blocks (realm exits carry their realm's namespace).
func (c *Config) SmartDNSExit(name string) (SmartDNSExit, string, bool) {
	for _, sc := range c.SmartDNSScopes() {
		if e, ok := sc.DNS.Exits[name]; ok {
			return e, sc.Realm, true
		}
	}
	return SmartDNSExit{}, "", false
}

// VPNExits returns the names of exits this node egresses for through a VPN,
// sorted.
func (c *Config) VPNExits() []string {
	var out []string
	for _, sc := range c.SmartDNSScopes() {
		for name, e := range sc.DNS.Exits {
			if e.IsSelf() && e.VPN != "" {
				out = append(out, name)
			}
		}
	}
	slices.Sort(out)
	return out
}

// VPNTable returns a VPN exit's routing table (= fwmark): its explicit
// table, else VPNTableMin + its index among the VPN exits in name order.
func (c *Config) VPNTable(exit string) (int, bool) {
	e, _, ok := c.SmartDNSExit(exit)
	if !ok || !e.IsSelf() || e.VPN == "" {
		return 0, false
	}
	if e.Table != 0 {
		return e.Table, true
	}
	return VPNTableMin + slices.Index(c.VPNExits(), exit), true
}

func (c *Config) validateSmartDNS(v *validator) {
	scopes := c.SmartDNSScopes()
	for _, sc := range scopes {
		p := "smartdns"
		if sc.Realm != "" {
			p = "realms." + sc.Realm + ".smartdns"
		}
		c.validateSmartDNSBlock(v, p, sc.Realm, sc.DNS)
	}
	c.validateVPNExits(v, scopes)
}

// validateVPNExits checks what the VPN exits of every block share on the
// node: interface names and routing tables.
func (c *Config) validateVPNExits(v *validator, scopes []SmartDNSScope) {
	type vpn struct{ name, path string }
	var vpns []vpn
	for _, sc := range scopes {
		p := "smartdns"
		if sc.Realm != "" {
			p = "realms." + sc.Realm + ".smartdns"
		}
		for _, name := range sortedKeys(sc.DNS.Exits) {
			if e := sc.DNS.Exits[name]; e.IsSelf() && e.VPN != "" {
				vpns = append(vpns, vpn{name, p + ".exits." + name})
			}
		}
	}
	slices.SortFunc(vpns, func(a, b vpn) int { return strings.Compare(a.name, b.name) })
	ifs := map[string]string{}
	tables := map[int]string{}
	implicit := map[int]string{}
	for i, x := range vpns {
		ifname := VPNInterfaceName(x.name)
		for _, t := range sortedKeys(c.Tunnels) {
			if InterfaceName(t) == ifname {
				v.add(x.path, "interface %q is already used by tunnel %q", ifname, t)
			}
		}
		if other, dup := ifs[ifname]; dup {
			v.add(x.path, "interface %q is already used by exit %q; rename one of them", ifname, other)
		}
		ifs[ifname] = x.name
		e, _, _ := c.SmartDNSExit(x.name)
		if e.Table == 0 {
			implicit[VPNTableMin+i] = x.name
			continue
		}
		if e.Table < VPNTableMin || e.Table > VPNTableMax {
			v.add(x.path+".table", "must be %d-%d, got %d", VPNTableMin, VPNTableMax, e.Table)
		} else if other, dup := tables[e.Table]; dup {
			v.add(x.path+".table", "table %d is already used by exit %q", e.Table, other)
		}
		tables[e.Table] = x.name
	}
	for _, t := range slices.Sorted(maps.Keys(tables)) {
		if other, clash := implicit[t]; clash {
			v.add("smartdns.exits."+other, "its implicit table %d is the explicit table of exit %q; give it a table too", t, tables[t])
		}
	}
}

// validateSmartDNSBlock checks one block at path p. A realm's block may
// only listen on its own tunnels' transit addresses, and its services and
// exits carry the realm's namespace ("<realm>.<name>"), which the exit API
// checks on the exit node.
func (c *Config) validateSmartDNSBlock(v *validator, p, realm string, s *SmartDNS) {
	transits := map[netip.Addr]string{}
	for _, name := range sortedKeys(c.Tunnels) {
		if a, ok := c.TransitEdgeAddr(name); ok {
			transits[a] = c.Tunnels[name].Realm
		}
	}
	meshAddr := netip.Addr{}
	if mp, ok := c.Mesh.MeshPrefix(); ok {
		meshAddr = mp.Addr()
	}
	seen := map[netip.Addr]bool{}
	for i, l := range s.Listen {
		lp := fmt.Sprintf("%s.listen[%d]", p, i)
		a, err := netip.ParseAddr(l)
		tr, onTunnel := transits[a]
		switch {
		case err != nil || !a.Is4():
			v.add(lp, "must be an IPv4 address, got %q", l)
			continue
		case seen[a]:
			v.add(lp, "duplicate address %s", a)
		case a == meshAddr:
			v.add(lp, "%s is the mesh address; the resolver must listen on tunnel transit or LAN addresses", a)
		case realm != "" && (!onTunnel || tr != realm):
			v.add(lp, "%s is not the transit address of a tunnel of realm %q", a, realm)
		case onTunnel:
		case a.IsPrivate() || cgnat.Contains(a):
			// An explicitly allowed private (LAN) address.
		default:
			v.add(lp, "%s is neither a tunnel transit address nor a private address; the resolver must never listen on public interfaces", a)
		}
		seen[a] = true
	}
	for i, u := range s.Upstream {
		if !validUpstream(u) {
			v.add(fmt.Sprintf("%s.upstream[%d]", p, i), "must be an IP address or IP:port, got %q", u)
		}
	}
	checkName := func(path, name string) {
		switch {
		case realm == "" && !nameRe.MatchString(name):
			v.add(path, "name must match %s", nameRe)
		case realm != "" && (!qualifiedNameRe.MatchString(name) || !strings.HasPrefix(name, realm+".")):
			v.add(path, "name must be %s.<name> in realm %q", realm, realm)
		}
	}

	for _, name := range sortedKeys(s.Exits) {
		e := s.Exits[name]
		ep := p + ".exits." + name
		checkName(ep, name)
		switch {
		case e.Node == "":
			v.add(ep+".node", "is required (self or a mesh peer id)")
		case e.IsSelf():
		case c.Mesh == nil:
			v.add(ep+".node", "exit on node %q needs the mesh section", e.Node)
		default:
			if _, ok := c.Mesh.Peers[e.Node]; !ok {
				v.add(ep+".node", "unknown mesh peer %q (expected self or one of mesh.peers)", e.Node)
			}
		}
		if !exitCountryRe.MatchString(e.Country) {
			v.add(ep+".country", "must be an ISO 3166-1 alpha-2 country code, got %q", e.Country)
		}
		if e.VPN != "" && !secretRefRe.MatchString(e.VPN) {
			v.add(ep+".vpn", "must be a secret reference secret://name, got %q", e.VPN)
		}
		switch {
		case e.Table != 0 && (!e.IsSelf() || e.VPN == ""):
			v.add(ep+".table", "only applies to a VPN exit on this node (node: self with vpn)")
		case realm != "" && e.IsSelf() && e.VPN != "" && e.Table == 0:
			v.add(ep+".table", "is required for a VPN exit in a realm (an explicit, stable routing table)")
		}
	}

	owners := map[string]string{}
	for _, name := range sortedKeys(s.Services) {
		svc := s.Services[name]
		sp := p + ".services." + name
		checkName(sp, name)
		validateServiceExits(v, sp, s, svc)
		if len(svc.Domains) == 0 {
			v.add(sp+".domains", "at least one domain is required")
		}
		for i, d := range svc.Domains {
			dp := fmt.Sprintf("%s.domains[%d]", sp, i)
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
		v.add(p+".failback_after", "must be between 0s and %s, got %s", MaxSmartDNSFailbackAfter, time.Duration(*f))
	}

	for i, ck := range s.Checks {
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

// validateServiceExits checks a service's exit list: 1 to 4 known, distinct
// exits of its own block, all of one country, so failing over never changes
// where the service appears to be.
func validateServiceExits(v *validator, p string, s *SmartDNS, svc SmartDNSService) {
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

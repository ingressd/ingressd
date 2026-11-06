// SPDX-License-Identifier: Apache-2.0

package config

import (
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"golang.org/x/net/idna"
)

var (
	nameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
	// qualifiedNameRe also admits one namespace label ("tq7k2m.nas"), as
	// written by a panel that merges several tenants onto one node.
	qualifiedNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}(\.[a-z0-9][a-z0-9-]{0,62})?$`)
	labelRe         = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	steerings       = []string{"round_robin", "weighted", "least_conn", "failover", "random", "ip_hash"}
)

// Error is a single validation problem, located by its YAML path.
type Error struct {
	Path string
	Msg  string
}

func (e *Error) Error() string { return e.Path + ": " + e.Msg }

type validator struct{ errs []error }

func (v *validator) add(path, format string, args ...any) {
	v.errs = append(v.errs, &Error{Path: path, Msg: fmt.Sprintf(format, args...)})
}

// prefix parses an IPv4 CIDR, recording an error if it is invalid or has host
// bits set. IPv6 site networks are not supported yet.
func (v *validator) prefix(path, s string) (netip.Prefix, bool) {
	p, err := netip.ParsePrefix(s)
	if err != nil || !p.Addr().Is4() {
		v.add(path, "invalid IPv4 CIDR %q", s)
		return netip.Prefix{}, false
	}
	if p != p.Masked() {
		v.add(path, "%q has host bits set (did you mean %s?)", s, p.Masked())
		return p.Masked(), true
	}
	return p, true
}

// Validate checks the config for semantic errors: bad references, conflicts
// and overlapping networks. It returns every problem found, joined.
func (c *Config) Validate() error {
	v := &validator{}
	if c.Version != 1 {
		v.add("version", "unsupported version %d (expected 1)", c.Version)
	}
	c.validateEdge(v)
	c.validateTunnels(v)
	c.validateSiblings(v)
	c.validatePools(v)
	c.validateApps(v)
	c.validateTLS(v)
	c.validateL4(v)
	c.validateSecurity(v)
	c.validateCache(v)
	c.validateAccess(v)
	c.validateObserve(v)
	c.validateTunnelRoutes(v)
	c.validateAdmins(v)
	c.validateSmartDNS(v)
	c.validateMesh(v)
	c.validateForward(v)
	c.validateRealms(v)
	return errors.Join(v.errs...)
}

func (c *Config) validateEdge(v *validator) {
	if s := c.Edge.PublicIPv4; s != "" {
		if a, err := netip.ParseAddr(s); err != nil || !a.Is4() {
			v.add("edge.public_ipv4", "invalid IPv4 address %q", s)
		}
	}
	if s := c.Edge.PublicIPv6; s != "" {
		if a, err := netip.ParseAddr(s); err != nil || !a.Is6() || a.Is4In6() {
			v.add("edge.public_ipv6", "invalid IPv6 address %q", s)
		}
	}
	if h := c.Edge.Admin.Hostname; h != "" && !servableHostname(h, false) {
		v.add("edge.admin.hostname", "invalid hostname %q", h)
	}
	switch c.Edge.Admin.Exposure {
	case ExposurePublic, ExposureTunnelOnly, ExposureIPAllowlist:
	default:
		v.add("edge.admin.exposure", "must be one of public, tunnel_only, ip_allowlist; got %q", c.Edge.Admin.Exposure)
	}
	for i, s := range c.Edge.Admin.IPAllowlist {
		if _, err := netip.ParsePrefix(s); err != nil {
			v.add(fmt.Sprintf("edge.admin.ip_allowlist[%d]", i), "invalid CIDR %q", s)
		}
	}
	if c.Edge.SSHPort < 1 || c.Edge.SSHPort > 65535 {
		v.add("edge.ssh_port", "must be 1-65535, got %d", c.Edge.SSHPort)
	}
	switch ca := c.Edge.ACME.CA; {
	case ca == "letsencrypt", ca == "letsencrypt_staging", ca == "internal":
	case strings.HasPrefix(ca, "https://"):
	default:
		v.add("edge.acme.ca", "must be letsencrypt, letsencrypt_staging, internal or an https:// ACME directory URL; got %q", ca)
	}
	for i, w := range c.Certificates.Wildcards {
		p := fmt.Sprintf("certificates.wildcards[%d]", i)
		if !validHostname(w, true) {
			v.add(p, "invalid hostname %q", w)
		} else if strings.HasPrefix(w, "*.") && c.Edge.ACME.DNSProvider == nil && c.Edge.ACME.CA != "internal" {
			v.add(p, "wildcard certificates need edge.acme.dns_provider (DNS-01)")
		}
	}
	if dp := c.Edge.ACME.DNSProvider; dp != nil {
		if dp.Type != "cloudflare" {
			v.add("edge.acme.dns_provider.type", "unsupported provider %q (supported: cloudflare)", dp.Type)
		}
		if dp.APIToken == "" {
			v.add("edge.acme.dns_provider.api_token", "is required")
		}
	}
}

type claim struct {
	path string
	p    netip.Prefix
}

func (c *Config) validateTunnels(v *validator) {
	names := sortedKeys(c.Tunnels)
	ports := map[int]string{}
	// Transit networks and virtual prefixes are ranges the edge itself owns.
	var claimed []claim

	for _, name := range names {
		t := c.Tunnels[name]
		p := "tunnels." + name
		if !nameRe.MatchString(name) {
			v.add(p, "name must match %s", nameRe)
		} else if len(name) > MaxTunnelNameLen {
			v.add(p, "name must be at most %d characters (it becomes interface %q)", MaxTunnelNameLen, InterfaceName(name))
		}
		if t.Type != TunnelWireGuard {
			v.add(p+".type", "unsupported type %q (expected wireguard)", t.Type)
		}
		if t.Site != SiteRouter && t.Site != SiteConnector {
			v.add(p+".site", "must be router or connector, got %q", t.Site)
		}
		if t.ListenPort < 1 || t.ListenPort > 65535 {
			v.add(p+".listen_port", "must be 1-65535, got %d", t.ListenPort)
		} else if other, dup := ports[t.ListenPort]; dup {
			v.add(p+".listen_port", "port %d is already used by tunnel %q", t.ListenPort, other)
		} else {
			ports[t.ListenPort] = name
		}

		if tp, ok := v.prefix(p+".transit", t.Transit); ok {
			if tp.Bits() > 30 {
				v.add(p+".transit", "must be /30 or larger to hold the edge and site addresses")
			}
			claimed = append(claimed, claim{p + ".transit", tp})
		}
		if t.SiteDNS != "" {
			if a, err := netip.ParseAddr(t.SiteDNS); err != nil || a.Zone() != "" {
				v.add(p+".site_dns", "must be an IP address, got %q", t.SiteDNS)
			}
		}
		// Subnets are optional: published addresses are routed individually
		// (see TunnelRoutes).
		for i, s := range t.Subnets {
			v.prefix(fmt.Sprintf("%s.subnets[%d]", p, i), s)
		}
		if t.VirtualPrefix != "" {
			if vp, ok := v.prefix(p+".virtual_prefix", t.VirtualPrefix); ok {
				claimed = append(claimed, claim{p + ".virtual_prefix", vp})
				if len(t.Subnets) != 1 {
					v.add(p+".virtual_prefix", "requires exactly one subnet")
				} else if sp, err := netip.ParsePrefix(t.Subnets[0]); err == nil && sp.Bits() != vp.Bits() {
					v.add(p+".virtual_prefix", "must be the same size as %s", t.Subnets[0])
				}
			}
		}
	}

	for i, a := range claimed {
		for _, b := range claimed[i+1:] {
			if a.p.Overlaps(b.p) {
				v.add(b.path, "%s overlaps %s (%s)", b.p, a.path, a.p)
			}
		}
		for _, name := range names {
			for _, s := range c.Tunnels[name].Subnets {
				if sp, err := netip.ParsePrefix(s); err == nil && sp.Overlaps(a.p) {
					v.add(a.path, "%s overlaps subnet %s of tunnel %q", a.p, s, name)
				}
			}
		}
	}

	c.validateTunnelTables(v, names)

	// Site subnets may only overlap when both tunnels are remapped, otherwise
	// the edge cannot tell which tunnel a destination belongs to.
	for i, a := range names {
		for _, b := range names[i+1:] {
			ta, tb := c.Tunnels[a], c.Tunnels[b]
			if sa, sb, ok := firstOverlap(ta.Subnets, tb.Subnets); ok && (ta.VirtualPrefix == "" || tb.VirtualPrefix == "") {
				v.add("tunnels."+b+".subnets", "%s overlaps %s of tunnel %q; set virtual_prefix on both tunnels", sb, sa, a)
			}
		}
	}
}

// validateTunnelTables checks explicit tables. Tunnels without one take
// TunnelTableMin + their index in sorted name order (see TunnelTable), so an
// explicit table must not land on such a number either.
func (c *Config) validateTunnelTables(v *validator, names []string) {
	tables := map[int]string{}
	for _, name := range names {
		t := c.Tunnels[name]
		if t.Table == 0 {
			continue
		}
		p := "tunnels." + name + ".table"
		switch other, dup := tables[t.Table]; {
		case t.VirtualPrefix == "":
			v.add(p, "only applies to remapped tunnels (set virtual_prefix)")
		case t.Table < TunnelTableMin || t.Table > TunnelTableMax:
			v.add(p, "must be %d-%d, got %d", TunnelTableMin, TunnelTableMax, t.Table)
		case dup:
			v.add(p, "table %d is already used by tunnel %q", t.Table, other)
		default:
			tables[t.Table] = name
		}
	}
	for i, name := range names {
		t := c.Tunnels[name]
		if t.Table != 0 || t.VirtualPrefix == "" {
			continue
		}
		if other, ok := tables[TunnelTableMin+i]; ok {
			v.add("tunnels."+other+".table", "table %d is the implicit table of tunnel %q; set a table on that tunnel too, or pick another", TunnelTableMin+i, name)
		}
	}
}

// TunnelTable returns the routing table (and fwmark) of a remapped tunnel:
// its explicit table, else TunnelTableMin + its index in sorted name order.
func (c *Config) TunnelTable(name string) int {
	if t := c.Tunnels[name].Table; t != 0 {
		return t
	}
	return TunnelTableMin + slices.Index(sortedKeys(c.Tunnels), name)
}

func (c *Config) validatePools(v *validator) {
	for _, name := range sortedKeys(c.Pools) {
		pl := c.Pools[name]
		p := "pools." + name
		if !qualifiedNameRe.MatchString(name) {
			v.add(p, "name must match %s", qualifiedNameRe)
		}
		if !slices.Contains(steerings, pl.Steering) {
			v.add(p+".steering", "must be one of %s; got %q", strings.Join(steerings, ", "), pl.Steering)
		}
		if pl.Failback != FailbackAuto && pl.Failback != FailbackManual {
			v.add(p+".failback", "must be auto or manual, got %q", pl.Failback)
		}
		if pl.Fallback != "" && pl.Fallback != "always_online" {
			v.add(p+".fallback", "must be empty or always_online, got %q", pl.Fallback)
		}
		if pl.Sticky != nil && pl.Sticky.Cookie == "" {
			v.add(p+".sticky.cookie", "is required when sticky is set")
		}
		if h := pl.Health; h != nil {
			validateHealth(v, p+".health", h)
		}

		if len(pl.Origins) == 0 {
			v.add(p+".origins", "at least one origin is required")
		}
		schemes := map[string]bool{}
		for _, o := range pl.Origins {
			if u, err := url.Parse(o.Address); err == nil {
				schemes[u.Scheme] = true
			}
		}
		if len(schemes) > 1 {
			v.add(p+".origins", "all origins in a pool must use the same scheme (http or https)")
		}
		seen := map[string]bool{}
		for i, o := range pl.Origins {
			op := fmt.Sprintf("%s.origins[%d]", p, i)
			if !nameRe.MatchString(o.Name) {
				v.add(op+".name", "must match %s, got %q", nameRe, o.Name)
			} else if seen[o.Name] {
				v.add(op+".name", "duplicate origin name %q", o.Name)
			}
			seen[o.Name] = true
			c.validateTarget(v, op+".tunnel", op+".address", o.Tunnel, o.Address)
			if o.Weight < 1 || o.Weight > 1000 {
				v.add(op+".weight", "must be 1-1000, got %d", o.Weight)
			}
			if o.Priority < 1 || o.Priority > 10 {
				v.add(op+".priority", "must be 1-10, got %d", o.Priority)
			}
			switch o.State {
			case OriginActive, OriginDraining, OriginDisabled:
			default:
				v.add(op+".state", "must be active, draining or disabled; got %q", o.State)
			}
		}
	}
}

func validateHealth(v *validator, p string, h *HealthCheck) {
	switch h.Type {
	case HealthHTTP:
		if !strings.HasPrefix(h.Path, "/") {
			v.add(p+".path", "must start with /, got %q", h.Path)
		}
	case HealthTCP:
	default:
		v.add(p+".type", "must be http or tcp, got %q", h.Type)
	}
	if h.Interval <= 0 {
		v.add(p+".interval", "must be positive")
	}
	if h.Timeout <= 0 || h.Timeout >= h.Interval {
		v.add(p+".timeout", "must be positive and shorter than interval")
	}
	for i, s := range h.ExpectStatus {
		if s < 100 || s > 599 {
			v.add(fmt.Sprintf("%s.expect_status[%d]", p, i), "invalid HTTP status %d", s)
		}
	}
	if h.UnhealthyAfter < 1 {
		v.add(p+".unhealthy_after", "must be at least 1")
	}
	if h.HealthyAfter < 1 {
		v.add(p+".healthy_after", "must be at least 1")
	}
	validateHealthHTTP(v, p, h)
}

// validateTarget checks an upstream address. Tunnelled IP origins are routed
// individually, so they only have to sit inside the tunnel's subnets when the
// tunnel is remapped (virtual_prefix translates the whole subnet).
func (c *Config) validateTarget(v *validator, tunnelPath, addrPath, tunnel, address string) {
	u, err := url.Parse(address)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || (u.Path != "" && u.Path != "/") {
		v.add(addrPath, "must be http(s)://host[:port], got %q", address)
		return
	}
	if port := u.Port(); port != "" {
		if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
			v.add(addrPath, "invalid port %q", port)
		}
	}
	if tunnel == "" {
		return // direct origin
	}
	t, ok := c.Tunnels[tunnel]
	if !ok {
		v.add(tunnelPath, "unknown tunnel %q", tunnel)
		return
	}
	addr, err := netip.ParseAddr(u.Hostname())
	if err != nil {
		return // hostnames are resolved by the edge at runtime
	}
	if !addr.Is4() {
		v.add(addrPath, "tunnelled origins must use IPv4 addresses, got %s", addr)
		return
	}
	if !tunnelCovers(t, addr) {
		v.add(addrPath, "%s is not inside the subnets of tunnel %q, which is remapped (virtual_prefix)", addr, tunnel)
	}
}

// tunnelCovers reports whether a published address is acceptable for a
// tunnel: always, unless the tunnel is remapped and the address is outside
// the remapped subnet.
func tunnelCovers(t Tunnel, a netip.Addr) bool {
	if t.VirtualPrefix == "" {
		return true
	}
	for _, s := range t.Subnets {
		if sp, err := netip.ParsePrefix(s); err == nil && sp.Contains(a) {
			return true
		}
	}
	return false
}

func (c *Config) validateApps(v *validator) {
	owners := map[string]string{}
	for _, name := range sortedKeys(c.Apps) {
		a := c.Apps[name]
		p := "apps." + name
		if !qualifiedNameRe.MatchString(name) {
			v.add(p, "name must match %s", qualifiedNameRe)
		}
		if len(a.Hosts) == 0 {
			v.add(p+".hosts", "at least one host is required")
		}
		for i, h := range a.Hosts {
			hp := fmt.Sprintf("%s.hosts[%d]", p, i)
			if !servableHostname(h, true) {
				v.add(hp, "invalid hostname %q", h)
				continue
			}
			if other, dup := owners[h]; dup {
				v.add(hp, "%q is already served by app %q", h, other)
			} else {
				owners[h] = name
			}
		}

		switch {
		case a.Pool != "" && a.Origin != "":
			v.add(p, "set either pool or origin, not both")
		case a.Pool != "":
			if _, ok := c.Pools[a.Pool]; !ok {
				v.add(p+".pool", "unknown pool %q", a.Pool)
			}
			if a.Tunnel != "" {
				v.add(p+".tunnel", "only applies to the origin shorthand; set tunnels on the pool's origins")
			}
		case a.Origin != "":
			c.validateTarget(v, p+".tunnel", p+".origin", a.Tunnel, a.Origin)
		default:
			v.add(p, "either pool or origin is required")
		}

		for i, r := range a.Redirects {
			rp := fmt.Sprintf("%s.redirects[%d]", p, i)
			if !slices.Contains(a.Hosts, r.From) {
				v.add(rp+".from", "%q must be one of the app's hosts", r.From)
			}
			if !validHostname(r.To, false) {
				v.add(rp+".to", "invalid hostname %q", r.To)
			}
			if !slices.Contains([]int{301, 302, 307, 308}, r.Code) {
				v.add(rp+".code", "must be 301, 302, 307 or 308; got %d", r.Code)
			}
		}
		if h := a.Headers; h != nil {
			switch h.Preset {
			case "", "none", "basic", "strict":
			default:
				v.add(p+".headers.preset", "must be none, basic or strict; got %q", h.Preset)
			}
			validHeaderOps(v, p+".headers.request", h.Request)
			validHeaderOps(v, p+".headers.response", h.Response)
		}
		if px := a.Proxy; px != nil {
			if px.MaxBody != "" {
				if _, err := ParseSize(px.MaxBody); err != nil {
					v.add(p+".proxy.max_body", "%v", err)
				}
			}
			if px.Timeout < 0 {
				v.add(p+".proxy.timeout", "must not be negative")
			}
		}
	}
}

// ParseSize parses a byte size such as "512MB", "10KB" or "1048576".
// Units are binary (1KB = 1024 bytes).
func ParseSize(s string) (int64, error) {
	t := strings.ToUpper(strings.TrimSpace(s))
	mult := int64(1)
	for _, u := range []struct {
		suffix string
		mult   int64
	}{{"GB", 1 << 30}, {"MB", 1 << 20}, {"KB", 1 << 10}, {"B", 1}} {
		if strings.HasSuffix(t, u.suffix) {
			t, mult = strings.TrimSpace(strings.TrimSuffix(t, u.suffix)), u.mult
			break
		}
	}
	n, err := strconv.ParseInt(t, 10, 64)
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("invalid size %q (use e.g. 512MB)", s)
	}
	return n * mult, nil
}

// headerNameRe is an RFC 9110 field name (token); Caddy's delete also takes
// "*" wildcards, which are token characters.
var headerNameRe = regexp.MustCompile("^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")

// validHeaderOps checks custom header names and values. Values are literal
// text: braces would be Caddy placeholders, and {env.*} or {file.*} would
// leak the edge's environment or files into requests and responses.
func validHeaderOps(v *validator, p string, h *HeaderOps) {
	if h == nil {
		return
	}
	for _, name := range slices.Sorted(maps.Keys(h.Set)) {
		if !headerNameRe.MatchString(name) {
			v.add(p+".set", "invalid header name %q", name)
		}
		val := h.Set[name]
		if strings.ContainsAny(val, "{}") {
			v.add(p+".set."+name, "must not contain { or } (Caddy placeholders are not allowed)")
		}
		if strings.ContainsFunc(val, func(r rune) bool { return (r < ' ' && r != '\t') || r == 0x7f }) {
			v.add(p+".set."+name, "must not contain control characters")
		}
	}
	for _, name := range h.Delete {
		if !headerNameRe.MatchString(name) {
			v.add(p+".delete", "invalid header name %q", name)
		}
	}
}

// validHostname reports whether h is a lowercase, fully qualified DNS name,
// optionally with a single leading "*." wildcard label.
func validHostname(h string, allowWildcard bool) bool {
	if allowWildcard {
		h = strings.TrimPrefix(h, "*.")
	}
	if h == "" || len(h) > 253 || h != strings.ToLower(h) {
		return false
	}
	labels := strings.Split(h, ".")
	if len(labels) < 2 {
		return false
	}
	for _, l := range labels {
		if !labelRe.MatchString(l) {
			return false
		}
	}
	return true
}

// servableHostname is validHostname for names the edge serves. Caddy converts
// every host it matches with idna.ToASCII and refuses the whole config if that
// fails, which the label syntax alone does not rule out (bad xn-- labels).
func servableHostname(h string, allowWildcard bool) bool {
	if !validHostname(h, allowWildcard) {
		return false
	}
	_, err := idna.ToASCII(h)
	return err == nil
}

func firstOverlap(a, b []string) (string, string, bool) {
	for _, x := range a {
		px, err := netip.ParsePrefix(x)
		if err != nil {
			continue
		}
		for _, y := range b {
			if py, err := netip.ParsePrefix(y); err == nil && px.Overlaps(py) {
				return x, y, true
			}
		}
	}
	return "", "", false
}

func sortedKeys[V any](m map[string]V) []string {
	return slices.Sorted(maps.Keys(m))
}

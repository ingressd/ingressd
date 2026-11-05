// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"
	"hash/fnv"
	"net/netip"
	"net/url"
	"slices"
	"strings"
)

// Realm is one isolated tenant on a shared node. A panel that merges several
// organisations onto one node gives each a realm: every tunnel, app, pool,
// policy, group and service token names its realm, references never cross
// realms, and each realm signs in with its own access settings and keys.
type Realm struct {
	// Access has the schema of the top-level access block; it is required
	// when the realm has protected apps.
	Access *Access     `yaml:"access,omitempty"`
	Shape  *RealmShape `yaml:"shape,omitempty"`
}

// RealmShape caps a realm's bandwidth on this node.
type RealmShape struct {
	RateMbit int `yaml:"rate_mbit"`
}

// MaxRealmRateMbit bounds realms.<r>.shape.rate_mbit.
const MaxRealmRateMbit = 100000

// RealmIFBName is the IFB device that shapes a realm's tunnel ingress:
// "ifb-<realm>" when it fits Linux's 15-byte limit, else the first four
// characters and a hash of the whole name.
func RealmIFBName(realm string) string {
	if len(realm) <= 11 {
		return "ifb-" + realm
	}
	h := fnv.New32a()
	_, _ = h.Write([]byte(realm)) // hash.Hash.Write never returns an error
	return fmt.Sprintf("ifb-%s-%05x", strings.TrimRight(realm[:4], "-"), h.Sum32()&0xfffff)
}

// RealmTunnels returns the names of a realm's tunnels, sorted.
func (c *Config) RealmTunnels(realm string) []string {
	var out []string
	for _, name := range sortedKeys(c.Tunnels) {
		if c.Tunnels[name].Realm == realm {
			out = append(out, name)
		}
	}
	return out
}

// RealmAccess returns a realm's access settings (nil if the realm has none
// or does not exist).
func (c *Config) RealmAccess(realm string) *Access {
	if r, ok := c.Realms[realm]; ok {
		return r.Access
	}
	return nil
}

// AppAccess returns the access settings that govern an app: its realm's when
// the config has realms, else the top-level block.
func (c *Config) AppAccess(app string) *Access {
	if len(c.Realms) > 0 {
		return c.RealmAccess(c.Apps[app].Realm)
	}
	return c.Access
}

// MachineHostFallback is where a node with realms serves its machine
// endpoints (connector enrolment, polling, WebSocket fallback) when it has
// no enrolment endpoint: realms refuse edge.admin.hostname, so it is the
// public IPv4. Configs without realms keep the admin hostname and return "".
func (c *Config) MachineHostFallback() string {
	if len(c.Realms) == 0 {
		return ""
	}
	return c.Edge.PublicIPv4
}

func (c *Config) applyRealmDefaults() {
	for _, r := range c.Realms {
		if r.Access != nil {
			defaultAccess(r.Access)
		}
	}
}

// realmRef is one object that names a realm.
type realmRef struct{ path, realm string }

func (c *Config) realmRefs() []realmRef {
	var out []realmRef
	add := func(kind string, names []string, realm func(string) string) {
		for _, n := range names {
			out = append(out, realmRef{kind + "." + n, realm(n)})
		}
	}
	add("tunnels", sortedKeys(c.Tunnels), func(n string) string { return c.Tunnels[n].Realm })
	add("apps", sortedKeys(c.Apps), func(n string) string { return c.Apps[n].Realm })
	add("pools", sortedKeys(c.Pools), func(n string) string { return c.Pools[n].Realm })
	add("policies", sortedKeys(c.Policies), func(n string) string { return c.Policies[n].Realm })
	add("groups", sortedKeys(c.Groups), func(n string) string { return c.Groups[n].Realm })
	add("service_tokens", sortedKeys(c.ServiceTokens), func(n string) string { return c.ServiceTokens[n].Realm })
	return out
}

func (c *Config) validateRealms(v *validator) {
	if len(c.Realms) == 0 {
		for _, r := range c.realmRefs() {
			if r.realm != "" {
				v.add(r.path+".realm", "unknown realm %q (no realms are configured)", r.realm)
			}
		}
		return
	}

	// Node-wide features that would be shared by every realm.
	if c.Access != nil {
		v.add("access", "is not allowed alongside realms; give each realm its own realms.<name>.access")
	}
	if len(c.L4) > 0 {
		v.add("l4", "is not supported alongside realms")
	}
	if c.Edge.Admin.Hostname != "" {
		v.add("edge.admin.hostname", "is not allowed alongside realms (the admin hostname is node-wide)")
	}
	if e := c.Edge.Admin.Exposure; e != "" && e != ExposurePublic {
		v.add("edge.admin.exposure", "is not allowed alongside realms (tunnel_only would trust every realm's tunnels)")
	}
	if len(c.Edge.Admin.IPAllowlist) > 0 {
		v.add("edge.admin.ip_allowlist", "is not allowed alongside realms")
	}
	if !c.TunnelInputRestricted() {
		v.add("security.tunnel_input", "must be restricted alongside realms (open input lets every realm's sites reach the proxy and SSH through their tunnels)")
	}

	for _, name := range sortedKeys(c.Realms) {
		r := c.Realms[name]
		p := "realms." + name
		if !nameRe.MatchString(name) {
			v.add(p, "name must match %s", nameRe)
		}
		if s := r.Shape; s != nil && (s.RateMbit < 1 || s.RateMbit > MaxRealmRateMbit) {
			v.add(p+".shape.rate_mbit", "must be 1-%d, got %d", MaxRealmRateMbit, s.RateMbit)
		}
		if r.Shape != nil {
			ifb := RealmIFBName(name)
			for _, other := range sortedKeys(c.Realms) {
				if other < name && c.Realms[other].Shape != nil && RealmIFBName(other) == ifb {
					v.add(p, "shaping device %q is already used by realm %q; rename one of them", ifb, other)
				}
			}
		}
		if r.Access == nil {
			for _, app := range sortedKeys(c.Apps) {
				if a := c.Apps[app]; a.Realm == name && a.Protected() {
					v.add(p+".access", "is required: app %q of this realm has access policies", app)
					break
				}
			}
			continue
		}
		ap := p + ".access"
		c.validateAccessBlock(v, ap, r.Access)
		switch {
		case r.Access.PortalHost != "":
			v.add(ap+".portal_host", "a realm cannot run a portal on the node (its cookie, one-time codes and email are node-wide); set portal_url")
		case r.Access.PortalURL == "":
			v.add(ap+".portal_url", "is required: realms sign in on an external portal, with the realm's own session_key and jwt_key")
		}
	}

	for _, ref := range c.realmRefs() {
		switch _, ok := c.Realms[ref.realm]; {
		case ref.realm == "":
			v.add(ref.path+".realm", "is required when realms are configured")
		case !ok:
			v.add(ref.path+".realm", "unknown realm %q", ref.realm)
		}
	}

	for _, name := range sortedKeys(c.Tunnels) {
		t := c.Tunnels[name]
		p := "tunnels." + name
		if t.VirtualPrefix == "" {
			v.add(p+".virtual_prefix", "is required in a realm (real site subnets never enter the node's main table)")
		}
		if t.Table == 0 {
			v.add(p+".table", "is required in a realm (an explicit, stable routing table)")
		}
	}

	for _, name := range sortedKeys(c.Pools) {
		pl := c.Pools[name]
		for i, o := range pl.Origins {
			op := fmt.Sprintf("pools.%s.origins[%d]", name, i)
			c.validateRealmOrigin(v, op+".tunnel", op+".address", pl.Realm, o.Tunnel, o.Address)
		}
	}

	for _, name := range sortedKeys(c.Apps) {
		a := c.Apps[name]
		p := "apps." + name
		if a.Pool != "" {
			if pl, ok := c.Pools[a.Pool]; ok && pl.Realm != a.Realm {
				v.add(p+".pool", "pool %q belongs to realm %q, not %q", a.Pool, pl.Realm, a.Realm)
			}
		} else if a.Origin != "" {
			c.validateRealmOrigin(v, p+".tunnel", p+".origin", a.Realm, a.Tunnel, a.Origin)
		}
		c.realmPolicyRefs(v, p+".access", a.Realm, a.Access)
		for i, r := range a.Paths {
			c.realmPolicyRefs(v, fmt.Sprintf("%s.paths[%d].access", p, i), a.Realm, r.Access)
		}
	}

	for _, name := range sortedKeys(c.Policies) {
		pol := c.Policies[name]
		for _, part := range []struct {
			name string
			sels []Selector
		}{{"include", pol.Include}, {"require", pol.Require}, {"exclude", pol.Exclude}} {
			for i, s := range part.sels {
				sp := fmt.Sprintf("policies.%s.%s[%d]", name, part.name, i)
				for j, g := range s.Group {
					if gr, ok := c.Groups[g]; ok && gr.Realm != pol.Realm {
						v.add(fmt.Sprintf("%s.group[%d]", sp, j), "group %q belongs to realm %q, not %q", g, gr.Realm, pol.Realm)
					}
				}
				for j, t := range s.ServiceToken {
					if tok, ok := c.ServiceTokens[t]; ok && tok.Realm != pol.Realm {
						v.add(fmt.Sprintf("%s.service_token[%d]", sp, j), "service token %q belongs to realm %q, not %q", t, tok.Realm, pol.Realm)
					}
				}
			}
		}
	}

	c.validateRealmHosts(v)
}

func (c *Config) realmPolicyRefs(v *validator, path, realm string, names []string) {
	for i, n := range names {
		if pol, ok := c.Policies[n]; ok && pol.Realm != realm {
			v.add(fmt.Sprintf("%s[%d]", path, i), "policy %q belongs to realm %q, not %q", n, pol.Realm, realm)
		}
	}
}

// validateRealmOrigin enforces the realm origin profile: through one of the
// realm's own tunnels, at an IP literal inside that tunnel's subnets. A
// hostname would be resolved by the node at runtime and could point at
// another realm's virtual addresses, the mesh or cloud metadata.
func (c *Config) validateRealmOrigin(v *validator, tunnelPath, addrPath, realm, tunnel, address string) {
	if tunnel == "" {
		v.add(tunnelPath, "is required in a realm: origins are reached through one of the realm's own tunnels")
		return
	}
	t, ok := c.Tunnels[tunnel]
	if !ok {
		return // reported by validateTarget
	}
	if t.Realm != realm {
		v.add(tunnelPath, "tunnel %q belongs to realm %q, not %q", tunnel, t.Realm, realm)
	}
	u, err := url.Parse(address)
	if err != nil {
		return
	}
	a, err := netip.ParseAddr(u.Hostname())
	if err != nil {
		v.add(addrPath, "must use an IP address in a realm (hostname origins are resolved by the node), got %q", u.Hostname())
		return
	}
	// Remapped tunnels are checked by validateTarget already.
	if a.Is4() && t.VirtualPrefix == "" && !subnetsContain(t.Subnets, a) {
		v.add(addrPath, "%s is not inside the subnets of tunnel %q", a, tunnel)
	}
}

func subnetsContain(subnets []string, a netip.Addr) bool {
	return slices.ContainsFunc(subnets, func(s string) bool {
		p, err := netip.ParsePrefix(s)
		return err == nil && p.Contains(a)
	})
}

// validateRealmHosts refuses a wildcard host of one realm that covers a host
// of another. Coverage is checked at any depth (*.example.com covers
// a.b.example.com), stricter than Caddy's one-label match, so a realm can
// never take another's traffic through a wildcard.
func (c *Config) validateRealmHosts(v *validator) {
	type owned struct{ host, realm, app, path string }
	var hosts []owned
	for _, name := range sortedKeys(c.Apps) {
		a := c.Apps[name]
		for i, h := range a.Hosts {
			hosts = append(hosts, owned{h, a.Realm, name, fmt.Sprintf("apps.%s.hosts[%d]", name, i)})
		}
	}
	for i, a := range hosts {
		for _, b := range hosts[i+1:] {
			if a.realm == b.realm || a.host == b.host {
				continue // equal hosts are refused by validateApps
			}
			if wildcardCovers(a.host, b.host) || wildcardCovers(b.host, a.host) {
				v.add(b.path, "%q overlaps %q of app %q in realm %q", b.host, a.host, a.app, a.realm)
			}
		}
	}
}

// wildcardCovers reports whether the wildcard host w matches host h or any
// name under the wildcard h.
func wildcardCovers(w, h string) bool {
	base, ok := strings.CutPrefix(w, "*.")
	return ok && strings.HasSuffix(strings.TrimPrefix(h, "*."), "."+base)
}

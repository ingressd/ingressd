// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"
	"math/big"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"time"
)

// Login methods (apps.<name>.login_methods, login_method selectors).
const (
	MethodEmail     = "email"
	MethodDiscord   = "discord"
	MethodGoogle    = "google"
	MethodMicrosoft = "microsoft"
	MethodSteam     = "steam"
	// MethodPasskey signs in with a passkey (WebAuthn) the org enrolled on
	// the panel. Only the panel's central portal offers it: it holds the
	// org's passkeys, so it needs portal_url.
	MethodPasskey = "passkey"
)

// LoginMethods lists every login method; Providers the third-party ones.
var (
	LoginMethods = []string{MethodEmail, MethodDiscord, MethodGoogle, MethodMicrosoft, MethodSteam, MethodPasskey}
	Providers    = []string{MethodDiscord, MethodGoogle, MethodMicrosoft, MethodSteam}
)

// IdentityProvider configures one third-party sign-in method
// (access.providers.<name>). See docs/ACCESS-PROVIDERS.md for how to
// register the app with each provider.
type IdentityProvider struct {
	// ClientID and ClientSecret (secret://name) are the OAuth app's
	// credentials (discord, google, microsoft).
	ClientID     string `yaml:"client_id,omitempty"`
	ClientSecret string `yaml:"client_secret,omitempty"`
	// Tenant (microsoft) restricts who can sign in: common (personal and
	// work accounts, the default), organizations (work accounts only),
	// consumers (personal accounts only) or one tenant ID. With any but one tenant ID,
	// microsoft_role grants access only alongside a microsoft_tenant requirement.
	Tenant string `yaml:"tenant,omitempty"`
	// APIKey (steam, secret://name) is a Steam Web API key; it is needed
	// only for steam_group and steam_app selectors.
	APIKey string `yaml:"api_key,omitempty"`
	// Session caps how long a sign-in with this provider lasts (default:
	// access.session). Memberships (guilds, roles, groups, owned apps) are
	// captured at sign-in, so a change at the provider applies when the
	// user signs in again: a shorter session applies it sooner.
	Session Duration `yaml:"session,omitempty"`
}

// MicrosoftConsumersTenant is the tenant ID of personal Microsoft accounts.
const MicrosoftConsumersTenant = "9188040d-6c67-4c5b-b112-36a304b66dad"

var (
	snowflakeRe   = regexp.MustCompile(`^[0-9]{15,21}$`)
	discordRoleRe = regexp.MustCompile(`^[0-9]{15,21}/[0-9]{15,21}$`)
	// Discord usernames: 2-32 of a-z, 0-9, _ and . (lowercase, unique).
	discordUserRe = regexp.MustCompile(`^[a-z0-9_.]{2,32}$`)
	guidRe        = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	// App role values may not contain spaces (Entra rule).
	msRoleRe      = regexp.MustCompile(`^[A-Za-z0-9._:/-]{1,120}$`)
	steamIDRe     = regexp.MustCompile(`^7656119[0-9]{10}$`)
	numericRe     = regexp.MustCompile(`^[0-9]{1,20}$`)
	steamAppRe    = regexp.MustCompile(`^[0-9]{1,10}$`)
	tokenHeaderRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]{0,63}$`)
	// Passkey names (the panel's slugs): lowercase, digits and -.
	passkeyRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
)

// steamGroupBase is added to a group's 32-bit account ID to get its
// groupID64 (the ID shown in group URLs and the XML profile).
var steamGroupBase = big.NewInt(103582791429521408)

// NormalizeSteamGroup returns a Steam group ID as its groupID64, accepting
// either form (the Web API returns 32-bit "gid"s). ok is false if s is not
// a group ID.
func NormalizeSteamGroup(s string) (string, bool) {
	if !numericRe.MatchString(s) {
		return "", false
	}
	n, ok := new(big.Int).SetString(s, 10)
	if !ok {
		return "", false
	}
	if n.Cmp(steamGroupBase) < 0 {
		if n.Sign() == 0 || n.BitLen() > 32 {
			return "", false
		}
		n.Add(n, steamGroupBase)
	} else if new(big.Int).Sub(n, steamGroupBase).BitLen() > 32 {
		return "", false
	}
	return n.String(), true
}

// IdentityKinds are the selector kinds matched against facts captured at
// sign-in (Attr). login_method is one of them: the method is a fact too.
var IdentityKinds = []string{"login_method", "discord_user", "discord_username", "discord_guild", "discord_role",
	"google_hd", "microsoft_tenant", "microsoft_group", "microsoft_role", "steam_id", "steam_group", "steam_app", "passkey"}

// IsIdentityKind reports whether kind is one of IdentityKinds.
func IsIdentityKind(kind string) bool { return slices.Contains(IdentityKinds, kind) }

// Attr is the canonical form of one identity fact, "<kind>:<value>",
// shared by the policy engine, sign-in tokens and edge_auth. Values are
// normalised the way the provider reports them (lowercase where the
// provider is case-insensitive; Steam groups as groupID64).
func Attr(kind, value string) string {
	value = strings.TrimSpace(value)
	switch kind {
	case "login_method", "discord_username", "google_hd", "microsoft_tenant", "microsoft_group", "passkey":
		value = strings.ToLower(value)
	case "steam_group":
		if g, ok := NormalizeSteamGroup(value); ok {
			value = g
		}
	}
	return kind + ":" + value
}

// Attrs returns an identity selector's values as facts (nil for other
// kinds).
func (s Selector) Attrs() []string {
	k := s.Kind()
	if !IsIdentityKind(k) {
		return nil
	}
	var out []string
	for _, v := range s.Values() {
		out = append(out, Attr(k, v))
	}
	return out
}

// methodOf names the provider an identity selector kind belongs to.
func methodOf(kind string) string {
	m, _, _ := strings.Cut(kind, "_")
	return m
}

func (c *Config) validateProviders(v *validator, prefix string, a *Access) {
	if len(a.Providers) == 0 {
		return
	}
	if a.PortalURL != "" {
		v.add(prefix+".providers", "sign-in providers of a node on an external portal (portal_url) are configured on the portal (the ingressd panel), not here")
	}
	for _, name := range sortedKeys(a.Providers) {
		p := a.Providers[name]
		path := prefix + ".providers." + name
		if !slices.Contains(Providers, name) {
			v.add(path, "unknown provider %q (use %s)", name, strings.Join(Providers, ", "))
			continue
		}
		if name == MethodSteam {
			if p.ClientID != "" || p.ClientSecret != "" {
				v.add(path, "steam uses OpenID 2.0 and has no client_id or client_secret (set api_key for group and app selectors)")
			}
			if p.APIKey != "" && !strings.HasPrefix(p.APIKey, "secret://") {
				v.add(path+".api_key", "must be a secret:// reference")
			}
		} else {
			if p.ClientID == "" || len(p.ClientID) > 256 || strings.ContainsAny(p.ClientID, " \t\r\n") {
				v.add(path+".client_id", "is required (the OAuth app's client ID)")
			}
			if !strings.HasPrefix(p.ClientSecret, "secret://") {
				v.add(path+".client_secret", "must be a secret:// reference")
			}
			if p.APIKey != "" {
				v.add(path+".api_key", "is only used by steam")
			}
		}
		if p.Tenant != "" && name != MethodMicrosoft {
			v.add(path+".tenant", "is only used by microsoft")
		}
		if name == MethodMicrosoft && p.Tenant != "" && !ValidMicrosoftTenant(p.Tenant) {
			v.add(path+".tenant", "must be common, organizations, consumers or a tenant ID (GUID), got %q", p.Tenant)
		}
		if p.Session != 0 && p.Session < Duration(time.Minute) {
			v.add(path+".session", "must be at least 1m")
		}
	}
}

// ValidMicrosoftTenant reports whether t is a usable tenant setting.
func ValidMicrosoftTenant(t string) bool {
	return t == "common" || t == "organizations" || t == "consumers" || guidRe.MatchString(t)
}

// AttrMicrosoftRoleUnbound marks a role from a provider open to many tenants.
// It always counts against a user (a deny, or an exclude on an allow), but works
// for one (an allow, or an exclude on a deny) only where the policy also requires
// a microsoft_tenant.
const AttrMicrosoftRoleUnbound = "microsoft_role_unbound"

// MicrosoftSingleTenant reports whether t limits sign-in to one organization's
// directory: a tenant ID other than the personal accounts tenant.
func MicrosoftSingleTenant(t string) bool {
	return guidRe.MatchString(t) && t != MicrosoftConsumersTenant
}

// ownPortal reports whether this node runs the sign-in portal itself (so
// it, not an external portal, needs the providers' credentials).
func ownPortal(a *Access) bool { return a != nil && a.PortalURL == "" }

func (c *Config) validateLoginMethods(v *validator, a *Access, path string, methods []string) {
	seen := map[string]bool{}
	for i, m := range methods {
		p := fmt.Sprintf("%s[%d]", path, i)
		switch {
		case !slices.Contains(LoginMethods, m):
			v.add(p, "unknown login method %q (use %s)", m, strings.Join(LoginMethods, ", "))
		case seen[m]:
			v.add(p, "%q listed twice", m)
		case m == MethodPasskey && ownPortal(a):
			v.add(p, "passkey sign-in is offered by the ingressd panel's central portal (access.portal_url) only")
		case m != MethodEmail && m != MethodPasskey && ownPortal(a) && !hasProvider(a, m):
			v.add(p, "needs access.providers.%s", m)
		}
		seen[m] = true
	}
}

func hasProvider(a *Access, name string) bool {
	if a == nil {
		return false
	}
	_, ok := a.Providers[name]
	return ok
}

func (c *Config) validateIdentitySelector(v *validator, path, kind string, s Selector) {
	vals := s.Values()
	check := func(re *regexp.Regexp, what string) {
		for i, x := range vals {
			if !re.MatchString(x) {
				v.add(fmt.Sprintf("%s.%s[%d]", path, kind, i), "must be %s, got %q", what, x)
			}
		}
	}
	switch kind {
	case "login_method":
		for i, m := range vals {
			if !slices.Contains(LoginMethods, m) {
				v.add(fmt.Sprintf("%s.login_method[%d]", path, i), "unknown login method %q (use %s)", m, strings.Join(LoginMethods, ", "))
			}
		}
		return
	case "discord_user", "discord_guild":
		check(snowflakeRe, "a Discord ID (digits; enable Developer Mode in Discord and use Copy ID)")
	case "discord_username":
		check(discordUserRe, "a lowercase Discord username")
	case "discord_role":
		check(discordRoleRe, "<server ID>/<role ID>")
	case "google_hd":
		for i, d := range vals {
			if !validHostname(d, false) || d != strings.ToLower(d) {
				v.add(fmt.Sprintf("%s.google_hd[%d]", path, i), "must be a lowercase domain, got %q", d)
			}
		}
	case "microsoft_tenant", "microsoft_group":
		check(guidRe, "a lowercase GUID")
	case "microsoft_role":
		check(msRoleRe, "an app role value (letters, digits and ._:/-)")
	case "steam_id":
		check(steamIDRe, "a SteamID64 (17 digits starting 7656119)")
	case "steam_group":
		for i, g := range vals {
			if _, ok := NormalizeSteamGroup(g); !ok {
				v.add(fmt.Sprintf("%s.steam_group[%d]", path, i), "must be a Steam group ID (groupID64), got %q", g)
			}
		}
	case "steam_app":
		check(steamAppRe, "a Steam app ID")
	case "passkey":
		check(passkeyRe, "a passkey name (lowercase letters, digits and -)")
		if ownPortal(c.Access) {
			v.add(path+".passkey", "passkey sign-in is offered by the ingressd panel's central portal (access.portal_url) only")
		}
		return
	default:
		return
	}
	// Facts that need the Steam Web API need its key on a node that runs
	// its own portal.
	if (kind == "steam_group" || kind == "steam_app") && ownPortal(c.Access) {
		if p, ok := c.Access.Providers[MethodSteam]; !ok || p.APIKey == "" {
			v.add(path+"."+kind, "needs access.providers.steam.api_key (a Steam Web API key)")
		}
	}
	if m := methodOf(kind); ownPortal(c.Access) && !hasProvider(c.Access, m) {
		v.add(path+"."+kind, "needs access.providers.%s", m)
	}
}

// reservedHeaders may not carry header tokens: they are hop-by-hop, set by
// the edge, or needed by the request itself.
var reservedHeaders = []string{"host", "cookie", "connection", "keep-alive", "te", "trailer", "transfer-encoding",
	"upgrade", "content-length", "content-type", "content-encoding", "forwarded", "via", "x-real-ip",
	"edge-client-id", "edge-client-secret", "edge-jwt-assertion", "origin", "referer", "user-agent", "accept"}

var reservedHeaderPrefixes = []string{"x-forwarded-", "x-edge-", "proxy-", "sec-", "cf-", "content-", "if-", "accept-"}

func validTokenHeader(v *validator, path, h string) {
	l := strings.ToLower(h)
	switch {
	case !tokenHeaderRe.MatchString(h):
		v.add(path, "must be a header name (letters, digits and -), got %q", h)
	case slices.Contains(reservedHeaders, l) || slices.ContainsFunc(reservedHeaderPrefixes, func(p string) bool { return strings.HasPrefix(l, p) }):
		v.add(path, "%s is reserved; pick a header of your own such as X-Bot-Token", http.CanonicalHeaderKey(h))
	}
}

// IdentityFeatures lists the config paths that use features added with
// identity providers and header tokens. A node needs
// nodeproto.CapabilityAccessIdentity to load a config with any of them
// (older nodes reject the unknown fields); the panel checks this before it
// sends one.
func (c *Config) IdentityFeatures() []string {
	var out []string
	if c.Access != nil && len(c.Access.Providers) > 0 {
		out = append(out, "access.providers")
	}
	for _, name := range sortedKeys(c.ServiceTokens) {
		if c.ServiceTokens[name].Header != "" {
			out = append(out, "service_tokens."+name+".header")
		}
	}
	for _, name := range sortedKeys(c.Apps) {
		if len(c.Apps[name].LoginMethods) > 0 {
			out = append(out, "apps."+name+".login_methods")
		}
	}
	for _, name := range sortedKeys(c.Policies) {
		p := c.Policies[name]
		for _, sels := range [][]Selector{p.Include, p.Require, p.Exclude} {
			if slices.ContainsFunc(sels, func(s Selector) bool { return IsIdentityKind(s.Kind()) }) {
				out = append(out, "policies."+name)
				break
			}
		}
	}
	return slices.Compact(out)
}

// validPasskeyPrincipal reports whether who is a passkey user,
// "passkey:<name>".
func validPasskeyPrincipal(who string) bool {
	name, ok := strings.CutPrefix(who, MethodPasskey+":")
	return ok && passkeyRe.MatchString(name)
}

// PasskeyFeatures lists the config paths that use passkey sign-in (the
// passkey login method or selector). A node needs
// nodeproto.CapabilityAccessPasskey to load them.
func (c *Config) PasskeyFeatures() []string {
	var out []string
	if c.Access != nil {
		for _, who := range sortedKeys(c.Access.RevokedBefore) {
			if validPasskeyPrincipal(who) {
				out = append(out, "access.revoked_before")
				break
			}
		}
	}
	for _, name := range sortedKeys(c.Apps) {
		if slices.Contains(c.Apps[name].LoginMethods, MethodPasskey) {
			out = append(out, "apps."+name+".login_methods")
		}
	}
	for _, name := range sortedKeys(c.Policies) {
		p := c.Policies[name]
		for _, sels := range [][]Selector{p.Include, p.Require, p.Exclude} {
			if slices.ContainsFunc(sels, func(s Selector) bool {
				return len(s.Passkey) > 0 || slices.Contains(s.LoginMethod, MethodPasskey)
			}) {
				out = append(out, "policies."+name)
				break
			}
		}
	}
	return out
}

// AppLoginMethods returns the login methods offered for an app (default
// [email]).
func AppLoginMethods(a App) []string {
	if len(a.LoginMethods) == 0 {
		return []string{MethodEmail}
	}
	return a.LoginMethods
}

// loginMethodWarnings flags apps whose policies refer to a provider's
// facts while the app does not offer that provider's sign-in: nobody can
// satisfy those selectors there.
func (c *Config) loginMethodWarnings() []string {
	var out []string
	for _, name := range sortedKeys(c.Apps) {
		app := c.Apps[name]
		methods := AppLoginMethods(app)
		var missing []string
		for _, list := range appLists(app) {
			for _, pn := range list {
				p := c.Policies[pn]
				for _, sels := range [][]Selector{p.Include, p.Require} {
					for _, s := range sels {
						k := s.Kind()
						if !IsIdentityKind(k) || k == "login_method" {
							continue
						}
						if m := methodOf(k); !slices.Contains(methods, m) && !slices.Contains(missing, m) {
							missing = append(missing, m)
						}
					}
				}
			}
		}
		if len(missing) > 0 {
			slices.Sort(missing)
			out = append(out, fmt.Sprintf("apps.%s.login_methods: its policies use %s selectors but the app does not offer %s sign-in; add it to login_methods",
				name, strings.Join(missing, "/"), strings.Join(missing, " or ")))
		}
	}
	return out
}

// microsoftRoleWarnings reports allow policies whose role selectors cannot
// grant access: that needs a provider limited to one tenant, or a required
// microsoft_tenant. An external portal's provider settings are not visible here.
func (c *Config) microsoftRoleWarnings() []string {
	a := c.Access
	if !ownPortal(a) || MicrosoftSingleTenant(a.Providers[MethodMicrosoft].Tenant) {
		return nil
	}
	kind := func(k string) func(Selector) bool {
		return func(s Selector) bool { return s.Kind() == k }
	}
	role := kind("microsoft_role")
	var out []string
	for _, name := range sortedKeys(c.Policies) {
		p := c.Policies[name]
		uses := slices.ContainsFunc(p.Include, role) || slices.ContainsFunc(p.Require, role)
		if uses && p.Action != ActionDeny && !slices.ContainsFunc(p.Require, kind("microsoft_tenant")) {
			out = append(out, fmt.Sprintf("policies.%s: microsoft_role grants nothing here; add a microsoft_tenant selector under require, "+
				"or set access.providers.microsoft.tenant to your tenant ID", name))
		}
	}
	return out
}

func appLists(a App) [][]string {
	lists := [][]string{a.Access}
	for _, r := range a.Paths {
		lists = append(lists, r.Access)
	}
	return lists
}

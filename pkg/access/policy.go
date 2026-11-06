// SPDX-License-Identifier: Apache-2.0

// Package access holds the parts of ingressd Access shared by the node
// (internal/auth) and the hosted panel's central sign-in portal: the key
// format and derivations, the sealed token formats (callback codes, portal
// and app cookies) and the policy engine.
package access

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"path"
	"slices"
	"strings"
	"time"

	"github.com/ingressd/ingressd/pkg/config"
)

// Identity is what a policy is evaluated against. Zero fields never match
// the selectors that need them.
type Identity struct {
	// Email is a verified email address ("" when the sign-in proved none,
	// e.g. Steam). Build user identities with UserIdentity, which derives
	// it from the session's principal.
	Email        string
	IP           netip.Addr
	Country      string // ISO 3166 alpha-2, "" when unknown
	ServiceToken string // name of an authenticated service token
	// Attrs are the facts captured at sign-in, as config.Attr strings
	// ("discord_guild:123", "login_method:steam", ...). Identity selectors
	// match them.
	Attrs []string
}

// UserIdentity is the identity of a signed-in user: principal is the
// session's user (an email address, or "<method>:<id>" for sign-ins that
// proved none), method the login method ("" means email: sessions from
// before login methods) and attrs the facts from sign-in. The login method
// is added to the facts.
func UserIdentity(principal, method string, attrs []string) Identity {
	if method == "" {
		method = config.MethodEmail
	}
	id := Identity{Email: EmailOf(principal)}
	id.Attrs = append(append(make([]string, 0, len(attrs)+1), attrs...), config.Attr("login_method", method))
	return id
}

// EmailOf returns the principal if it is an email address, else "".
// Provider principals ("steam:7656119...") never contain "@".
func EmailOf(principal string) string {
	if strings.Contains(principal, "@") {
		return principal
	}
	return ""
}

// Principal names the user of a sign-in: the verified email when there is
// one (so every method that proves the same address is the same user),
// else "<method>:<subject>".
func Principal(method, subject, verifiedEmail string) string {
	if verifiedEmail != "" {
		return verifiedEmail
	}
	return method + ":" + subject
}

// ReferencedAttrs returns every identity fact the config's policies refer
// to. Sign-in keeps only these in the session, so cookies stay small and
// carry no more personal data than the policies need.
func (e *Engine) ReferencedAttrs() map[string]bool {
	out := map[string]bool{}
	for _, p := range e.policies {
		for _, sels := range [][]config.Selector{p.p.Include, p.p.Require, p.p.Exclude} {
			for _, s := range sels {
				for _, a := range s.Attrs() {
					out[a] = true
				}
				for _, v := range s.MicrosoftRole {
					out[config.Attr(config.AttrMicrosoftRoleUnbound, v)] = true
				}
			}
		}
	}
	return out
}

// KeepAttrs filters sign-in facts to those in ref, sorted. login_method
// facts are dropped (UserIdentity adds the method).
func KeepAttrs(attrs []string, ref map[string]bool) []string {
	var out []string
	for _, a := range attrs {
		if ref[a] && !strings.HasPrefix(a, "login_method:") {
			out = append(out, a)
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// Decision is the outcome of evaluating a policy list.
type Decision struct {
	// Action is the matching policy's action, or ActionDeny when no policy
	// matched (the implicit default).
	Action string
	// Policy is the matching policy name ("" when none matched).
	Policy  string
	Session time.Duration
}

// Allowed reports whether the decision lets a signed-in identity through.
func (d Decision) Allowed() bool {
	return d.Action == config.ActionAllow || d.Action == config.ActionBypass
}

// Engine evaluates the policies of one config. It is immutable and safe for
// concurrent use.
type Engine struct {
	cfg      *config.Config
	policies map[string]*policy
}

type policy struct {
	name    string
	p       config.Policy
	include []matcher
	require []matcher
	exclude []matcher
	version string
}

type matcher func(Identity) bool

// NewEngine compiles the config's policies. The config must be valid.
func NewEngine(cfg *config.Config) *Engine {
	e := &Engine{cfg: cfg, policies: map[string]*policy{}}
	for name, p := range cfg.Policies {
		cp := &policy{name: name, p: p, version: policyVersion(cfg, p)}
		// An unbound role can only count against a user, unless the policy
		// pins the tenant. Excluding from a deny policy would work for them.
		tenant := slices.ContainsFunc(p.Require, func(s config.Selector) bool { return s.Kind() == "microsoft_tenant" })
		deny := p.Action == config.ActionDeny
		cp.include = e.roleMatchers(p.Include, deny || tenant)
		cp.require = e.roleMatchers(p.Require, deny || tenant)
		cp.exclude = e.roleMatchers(p.Exclude, !deny || tenant)
		e.policies[name] = cp
	}
	return e
}

func (e *Engine) matchers(sels []config.Selector) []matcher {
	ms := make([]matcher, 0, len(sels))
	for _, s := range sels {
		ms = append(ms, e.matcher(s))
	}
	return ms
}

// roleMatchers is matchers, with microsoft_role also matching unbound roles if
// unbound is set.
func (e *Engine) roleMatchers(sels []config.Selector, unbound bool) []matcher {
	ms := e.matchers(sels)
	if !unbound {
		return ms
	}
	for i, s := range sels {
		if s.Kind() != "microsoft_role" {
			continue
		}
		bound := ms[i]
		attrs := make([]string, 0, len(s.MicrosoftRole))
		for _, v := range s.MicrosoftRole {
			attrs = append(attrs, config.Attr(config.AttrMicrosoftRoleUnbound, v))
		}
		ms[i] = func(id Identity) bool {
			return bound(id) || slices.ContainsFunc(id.Attrs, func(a string) bool { return slices.Contains(attrs, a) })
		}
	}
	return ms
}

func (e *Engine) matcher(s config.Selector) matcher {
	switch s.Kind() {
	case "everyone":
		return func(Identity) bool { return true }
	case "email":
		return func(id Identity) bool { return id.Email != "" && containsFold(s.Email, id.Email) }
	case "email_domain":
		return func(id Identity) bool { return id.Email != "" && containsFold(s.EmailDomain, emailDomain(id.Email)) }
	case "group":
		groups := make([]config.Group, 0, len(s.Group))
		for _, g := range s.Group {
			groups = append(groups, e.cfg.Groups[g])
		}
		return func(id Identity) bool {
			if id.Email == "" {
				return false
			}
			for _, g := range groups {
				if containsFold(g.Emails, id.Email) || containsFold(g.EmailDomains, emailDomain(id.Email)) {
					return true
				}
			}
			return false
		}
	case "ip":
		var ps []netip.Prefix
		for _, v := range s.IP {
			if p, err := config.ParsePrefixOrAddr(v); err == nil {
				ps = append(ps, p)
			}
		}
		return func(id Identity) bool {
			if !id.IP.IsValid() {
				return false
			}
			ip := id.IP.Unmap()
			for _, p := range ps {
				if p.Contains(ip) {
					return true
				}
			}
			return false
		}
	case "country":
		return func(id Identity) bool { return id.Country != "" && containsFold(s.Country, id.Country) }
	case "service_token":
		return func(id Identity) bool {
			return id.ServiceToken != "" && slices.Contains(s.ServiceToken, id.ServiceToken)
		}
	}
	if attrs := s.Attrs(); len(attrs) > 0 {
		return func(id Identity) bool {
			for _, a := range id.Attrs {
				if slices.Contains(attrs, a) {
					return true
				}
			}
			return false
		}
	}
	return func(Identity) bool { return false } // invalid or reserved selector
}

// Match reports whether the identity matches the policy: any include, all
// requires and no excludes. An empty include list never matches.
func (p *policy) match(id Identity) bool {
	if !anyMatch(p.include, id) {
		return false
	}
	for _, m := range p.require {
		if !m(id) {
			return false
		}
	}
	return !anyMatch(p.exclude, id)
}

func anyMatch(ms []matcher, id Identity) bool {
	for _, m := range ms {
		if m(id) {
			return true
		}
	}
	return false
}

// Evaluate walks a policy list; the first matching policy wins. Unknown
// names are skipped. No match is an implicit deny.
func (e *Engine) Evaluate(names []string, id Identity) Decision {
	for _, n := range names {
		p, ok := e.policies[n]
		if !ok || !p.match(id) {
			continue
		}
		return Decision{Action: p.p.Action, Policy: n, Session: time.Duration(p.p.Session)}
	}
	return Decision{Action: config.ActionDeny}
}

// Version is a short hash of a policy's definition and of the groups it
// refers to. App cookies record it, so editing a policy (or a group it uses)
// signs everyone out of the apps using it.
func (e *Engine) Version(name string) string {
	if p, ok := e.policies[name]; ok {
		return p.version
	}
	return ""
}

// Policy returns a policy definition by name.
func (e *Engine) Policy(name string) (config.Policy, bool) {
	p, ok := e.policies[name]
	if !ok {
		return config.Policy{}, false
	}
	return p.p, true
}

func policyVersion(cfg *config.Config, p config.Policy) string {
	groups := map[string]config.Group{}
	for _, sels := range [][]config.Selector{p.Include, p.Require, p.Exclude} {
		for _, s := range sels {
			for _, g := range s.Group {
				groups[g] = cfg.Groups[g]
			}
		}
	}
	b, _ := json.Marshal(struct {
		P config.Policy
		G map[string]config.Group
	}{p, groups})
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:6])
}

// ListFor returns the policy list that applies to an escaped request path
// (url.URL.EscapedPath) of an app: the first matching path override, else
// the app's own list. edge_auth rejects ambiguous paths of apps with path
// overrides, so for those the app's own list is returned.
func ListFor(app config.App, reqPath string) []string {
	canon, err := CanonicalPath(reqPath)
	if err != nil {
		return app.Access
	}
	for _, r := range app.Paths {
		if PathRuleMatch(r.Match, canon) {
			return r.Access
		}
	}
	return app.Access
}

// AllLists returns every policy list of an app (its own list first).
func AllLists(app config.App) [][]string {
	lists := [][]string{app.Access}
	for _, r := range app.Paths {
		lists = append(lists, r.Access)
	}
	return lists
}

// PathMatch matches an escaped request path against an exact path or a
// prefix pattern ending in "*" (see CanonicalPath and PathRuleMatch, which
// edge_auth shares). Ambiguous paths match nothing.
func PathMatch(pattern, reqPath string) bool {
	canon, err := CanonicalPath(reqPath)
	return err == nil && PathRuleMatch(pattern, canon)
}

// CleanPath normalises a request path (resolving dot segments and duplicate
// slashes) but keeps a trailing slash, so /a/../b/ and /b/ match alike.
// Path rules are matched with CanonicalPath, which also does this.
func CleanPath(p string) string {
	if p == "" {
		return "/"
	}
	c := path.Clean("/" + p)
	if strings.HasSuffix(p, "/") && c != "/" {
		c += "/"
	}
	return c
}

// CouldAllow reports whether an email could ever satisfy one of the
// policies, assuming the most favourable network conditions. The portal
// only sends codes to such emails (but answers identically either way).
func (e *Engine) CouldAllow(names []string, email string) bool {
	for _, n := range names {
		p, ok := e.policies[n]
		if !ok || p.p.Action != config.ActionAllow {
			continue
		}
		if p.couldMatch(email) {
			return true
		}
	}
	return false
}

// couldMatch treats network selectors (ip, country) as satisfiable for
// include/require and not matching for exclude.
func (p *policy) couldMatch(email string) bool {
	opt := func(sels []config.Selector, ms []matcher, network bool) []bool {
		out := make([]bool, len(ms))
		for i, s := range sels {
			k := s.Kind()
			if k == "ip" || k == "country" {
				out[i] = network
			} else {
				out[i] = ms[i](UserIdentity(email, config.MethodEmail, nil))
			}
		}
		return out
	}
	if !slices.Contains(opt(p.p.Include, p.include, true), true) {
		return false
	}
	if slices.Contains(opt(p.p.Require, p.require, true), false) {
		return false
	}
	return !slices.Contains(opt(p.p.Exclude, p.exclude, false), true)
}

// NormalizeEmail lowercases and trims an address and checks its shape.
func NormalizeEmail(s string) (string, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	at := strings.LastIndexByte(s, '@')
	if len(s) > 254 || at < 1 || at == len(s)-1 || strings.ContainsAny(s, " \t\r\n<>()[],;:\"\\") ||
		!strings.Contains(s[at+1:], ".") {
		return "", fmt.Errorf("invalid email address")
	}
	return s, nil
}

func emailDomain(email string) string {
	if i := strings.LastIndexByte(email, '@'); i >= 0 {
		return email[i+1:]
	}
	return ""
}

func containsFold(list []string, v string) bool {
	for _, s := range list {
		if strings.EqualFold(s, v) {
			return true
		}
	}
	return false
}

// HostAllowed reports whether host is one of hosts (or under a "*." one,
// one label deep, as Caddy matches).
func HostAllowed(hosts []string, host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for _, h := range hosts {
		if h == host {
			return true
		}
		if suffix, ok := strings.CutPrefix(h, "*"); ok {
			label, ok := strings.CutSuffix(host, suffix)
			if ok && label != "" && !strings.Contains(label, ".") {
				return true
			}
		}
	}
	return false
}

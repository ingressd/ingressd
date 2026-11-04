// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"fmt"
	"slices"
	"strings"

	"github.com/ingressd/ingressd/pkg/config"
)

// ControlHost is the Host the edge_auth module uses for its requests to the
// control socket (code exchange, revocations). Caddy never forwards this
// name to the control plane, so these endpoints are unreachable from the
// internet.
const ControlHost = "access.ingressd.internal"

// EdgeConfig is the JSON configuration of the edge_auth Caddy module
// (edge/modules/edgeauth). Field names are shared with that module.
type EdgeConfig struct {
	Handler   string `json:"handler"`
	App       string `json:"app"`
	PortalURL string `json:"portal_url"`
	// SessionKey and JWTKey are the stored secrets (see KeyRefs); the
	// module derives its per-app keys from them.
	SessionKey    string                `json:"session_key"`
	JWTKey        string                `json:"jwt_key"`
	ControlSocket string                `json:"control_socket,omitempty"`
	ControlHost   string                `json:"control_host"`
	Policies      map[string]EdgePolicy `json:"policies"`
	// Default is the app's policy list; Paths override it per path.
	Default       []string           `json:"default,omitempty"`
	Paths         []EdgePath         `json:"paths,omitempty"`
	ServiceTokens []EdgeServiceToken `json:"service_tokens,omitempty"`
	// CountryDB is the MaxMind country database for country selectors
	// ("" when none is downloaded: country selectors then never match, as
	// in the control plane).
	CountryDB string `json:"country_db,omitempty"`
}

// EdgePolicy is a policy as edge_auth sees it, with all its selectors:
// the module evaluates every policy on every request, against the client
// address, its country and, for signed-in users, the cookie's email. An
// allow policy additionally needs a grant for its current version in the
// app cookie, which proves the email passed the portal for it. Offline
// policies (no email, email_domain, group or identity-provider selectors) are also evaluated
// for anonymous requests; the others are left to the portal until the user
// has signed in.
type EdgePolicy struct {
	Action  string         `json:"action"`
	Version string         `json:"version"`
	Offline bool           `json:"offline,omitempty"`
	Include []EdgeSelector `json:"include,omitempty"`
	Require []EdgeSelector `json:"require,omitempty"`
	Exclude []EdgeSelector `json:"exclude,omitempty"`
}

// EdgeSelector is one selector; groups are expanded into their emails and
// email domains. A selector the edge cannot evaluate (reserved or invalid
// kinds, which the engine never matches either) is rendered as Never.
type EdgeSelector struct {
	Everyone     bool     `json:"everyone,omitempty"`
	Never        bool     `json:"never,omitempty"`
	Email        []string `json:"email,omitempty"`
	EmailDomain  []string `json:"email_domain,omitempty"`
	IP           []string `json:"ip,omitempty"`
	Country      []string `json:"country,omitempty"`
	ServiceToken []string `json:"service_token,omitempty"`
	// Attr matches facts captured at sign-in (config.Attr strings, from
	// the identity-provider selectors), which the app cookie carries.
	Attr []string `json:"attr,omitempty"`
}

type EdgePath struct {
	Match    string   `json:"match"`
	Policies []string `json:"policies"`
}

// EdgeServiceToken lets the module verify Edge-Client-Id/Edge-Client-Secret
// without holding the secret: Verifier is HMAC-SHA256(secret) under a key
// derived from the session key.
type EdgeServiceToken struct {
	Name     string `json:"name"`
	ClientID string `json:"client_id,omitempty"`
	// Header (header tokens) carries the secret alone; edge_auth removes
	// it from every request.
	Header   string `json:"header,omitempty"`
	Verifier string `json:"verifier"`
	Expires  int64  `json:"expires,omitempty"` // unix seconds, 0 = never
}

// Resolver resolves secret://name references.
type Resolver interface {
	Resolve(v string) (string, error)
}

// BuildEdgeConfig renders the edge_auth configuration for a protected app.
func BuildEdgeConfig(cfg *config.Config, res Resolver, appName, controlSocket string) (*EdgeConfig, error) {
	keys, err := LoadConfigKeys(cfg, res)
	if err != nil {
		return nil, err
	}
	sk, jk := keys.SessionRaw, keys.JWTRaw
	app := cfg.Apps[appName]
	eng := NewEngine(cfg)
	portal := "https://" + cfg.Access.PortalHost
	if External(cfg) {
		portal = strings.TrimSuffix(cfg.Access.PortalURL, "/")
	}
	ec := &EdgeConfig{
		Handler:       "edge_auth",
		App:           appName,
		PortalURL:     portal,
		SessionKey:    sk,
		JWTKey:        jk,
		ControlSocket: controlSocket,
		ControlHost:   ControlHost,
		Policies:      map[string]EdgePolicy{},
		Default:       app.Access,
	}
	var tokens []string
	for _, r := range app.Paths {
		ec.Paths = append(ec.Paths, EdgePath{Match: r.Match, Policies: r.Access})
	}
	for _, list := range AllLists(app) {
		for _, name := range list {
			p, _ := eng.Policy(name)
			ec.Policies[name] = EdgePolicy{Action: p.Action, Version: eng.Version(name), Offline: offline(p),
				Include: edgeSelectors(cfg, p.Include), Require: edgeSelectors(cfg, p.Require), Exclude: edgeSelectors(cfg, p.Exclude)}
			for _, sels := range [][]config.Selector{p.Include, p.Require, p.Exclude} {
				for _, s := range sels {
					tokens = append(tokens, s.ServiceToken...)
				}
			}
		}
	}
	slices.Sort(tokens)
	for _, name := range slices.Compact(tokens) {
		t := cfg.ServiceTokens[name]
		secret, err := res.Resolve(t.ClientSecret)
		if err != nil {
			return nil, fmt.Errorf("service_tokens.%s.client_secret: %w", name, err)
		}
		if t.Header != "" && len(secret) < MinHeaderTokenSecret {
			return nil, fmt.Errorf("service_tokens.%s.client_secret: a header token secret must be at least %d characters", name, MinHeaderTokenSecret)
		}
		et := EdgeServiceToken{Name: name, ClientID: t.ClientID, Header: t.Header, Verifier: keys.ServiceTokenVerifier(secret)}
		if !t.Expires.IsZero() {
			et.Expires = t.Expires.Unix()
		}
		ec.ServiceTokens = append(ec.ServiceTokens, et)
	}
	return ec, nil
}

// MinHeaderTokenSecret is the shortest secret a header token may have.
const MinHeaderTokenSecret = 16

// offline reports whether a policy can be evaluated without knowing who
// the user is (it has no email, email_domain or group selectors).
func offline(p config.Policy) bool {
	for _, sels := range [][]config.Selector{p.Include, p.Require, p.Exclude} {
		for _, s := range sels {
			switch s.Kind() {
			case "email", "email_domain", "group":
				return false
			}
			if config.IsIdentityKind(s.Kind()) {
				return false
			}
		}
	}
	return true
}

// edgeSelectors must match the engine's matchers (pkg/access): one kind per
// selector, groups by their emails and email domains.
func edgeSelectors(cfg *config.Config, sels []config.Selector) []EdgeSelector {
	out := make([]EdgeSelector, 0, len(sels))
	for _, s := range sels {
		var es EdgeSelector
		switch s.Kind() {
		case "everyone":
			es.Everyone = true
		case "email":
			es.Email = s.Email
		case "email_domain":
			es.EmailDomain = s.EmailDomain
		case "group":
			for _, g := range s.Group {
				es.Email = append(es.Email, cfg.Groups[g].Emails...)
				es.EmailDomain = append(es.EmailDomain, cfg.Groups[g].EmailDomains...)
			}
			es.Never = len(es.Email) == 0 && len(es.EmailDomain) == 0
		case "ip":
			es.IP = s.IP
		case "country":
			es.Country = s.Country
		case "service_token":
			es.ServiceToken = s.ServiceToken
		default:
			es.Attr = s.Attrs()
			es.Never = len(es.Attr) == 0
		}
		out = append(out, es)
	}
	return out
}

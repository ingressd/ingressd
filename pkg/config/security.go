// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Edge security (PLAN §10): WAF, rate limiting, IP/geo rules, the bot
// challenge and CrowdSec.

const (
	WAFOff    = "off"
	WAFDetect = "detect"
	WAFBlock  = "block"

	ChallengeOff         = "off"
	ChallengeSuspicious  = "suspicious"
	ChallengeAlways      = "always"
	ChallengeUnderAttack = "under_attack"

	RateLimitBlock     = "block"
	RateLimitChallenge = "challenge"

	// DefaultChallengeDifficulty is the number of leading zero bits the
	// proof of work needs (~65k SHA-256 hashes on average).
	DefaultChallengeDifficulty = 16
	// UnderAttackExtraDifficulty is added to the difficulty in under-attack mode.
	UnderAttackExtraDifficulty = 4
	DefaultChallengeTTL        = 24 * time.Hour

	DefaultCrowdSecLAPI = "http://127.0.0.1:8080"

	// ChallengeKeySecret is the secrets.age entry holding the HMAC key that
	// signs bot-challenge tokens and clearance cookies (generated on apply).
	ChallengeKeySecret = "edge_challenge_key"
)

// DefaultGeoIPEditions are the MaxMind databases downloaded when
// edge.geoip.editions is empty.
var DefaultGeoIPEditions = []string{"GeoLite2-Country", "GeoLite2-ASN"}

// WAF configures Coraza with the OWASP Core Rule Set for one app.
type WAF struct {
	Mode     string `yaml:"mode"`     // off | detect | block (default block)
	Paranoia int    `yaml:"paranoia"` // 1-4 (default 1)
	// Anomaly score thresholds (CRS defaults 5 and 4).
	InboundThreshold  int `yaml:"inbound_threshold"`
	OutboundThreshold int `yaml:"outbound_threshold"`
	// ResponseBody enables response-body inspection (off by default for speed).
	ResponseBody bool           `yaml:"response_body"`
	Exclusions   []WAFExclusion `yaml:"exclusions"`
}

// WAFExclusion turns off a CRS rule (by ID) or a group of rules (by tag),
// optionally only below a path prefix and only for one target such as
// ARGS:q, REQUEST_HEADERS:User-Agent or REQUEST_COOKIES:session.
type WAFExclusion struct {
	Rule   int    `yaml:"rule"`
	Tag    string `yaml:"tag"`
	Path   string `yaml:"path"`
	Target string `yaml:"target"`
}

// Enabled reports whether the WAF inspects requests.
func (w *WAF) Enabled() bool { return w != nil && w.Mode != WAFOff }

// RateLimitRule is one rate-limit zone of an app.
type RateLimitRule struct {
	Match    string   `yaml:"match"` // path pattern, e.g. /login or /api/*
	Requests int      `yaml:"requests"`
	Per      Duration `yaml:"per"`
	// Key: ip (default) | ip_path | header:<name> | email (authenticated user).
	Key    string `yaml:"key"`
	Action string `yaml:"action"` // block (429, default) | challenge
}

// BotChallenge is written either as a mode ("suspicious") or a mapping.
type BotChallenge struct {
	Mode       string   `yaml:"mode"`
	Difficulty int      `yaml:"difficulty"` // leading zero bits, default 16
	TTL        Duration `yaml:"ttl"`        // clearance cookie lifetime, default 24h
	// ExemptPaths are never challenged (API endpoints, webhooks). Prefixes;
	// a trailing * is allowed.
	ExemptPaths []string `yaml:"exempt_paths"`
}

var botChallengeFields = []string{"mode", "difficulty", "ttl", "exempt_paths"}

func (b *BotChallenge) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind == yaml.ScalarNode {
		return n.Decode(&b.Mode)
	}
	if n.Kind == yaml.MappingNode {
		// Node.Decode does not inherit KnownFields, so check keys here.
		for i := 0; i < len(n.Content); i += 2 {
			if k := n.Content[i].Value; !slices.Contains(botChallengeFields, k) {
				return fmt.Errorf("line %d: field %s not found in type config.BotChallenge", n.Content[i].Line, k)
			}
		}
	}
	type plain BotChallenge
	return n.Decode((*plain)(b))
}

// Security holds IP and geo rules. It appears globally (top-level
// `security`) and per app; see Config.EffectiveSecurity for how they merge.
type Security struct {
	// IPAllow, when set, is the only CIDRs that may reach the app.
	IPAllow []string `yaml:"ip_allow"`
	IPDeny  []string `yaml:"ip_deny"`
	// Country rules use ISO 3166-1 alpha-2 codes and need edge.geoip.
	CountryAllow []string `yaml:"country_allow"`
	CountryDeny  []string `yaml:"country_deny"`
	ASNDeny      []int    `yaml:"asn_deny"`
	// UnderAttack challenges every visitor with a harder proof of work.
	UnderAttack bool `yaml:"under_attack"`
	// GoodBots lets verified search engine crawlers skip the bot challenge.
	// Default true.
	GoodBots *bool `yaml:"good_bots"`
	// TunnelInput (top-level only) is what sites may reach on the edge
	// itself through their tunnels: open (default) or restricted.
	TunnelInput string `yaml:"tunnel_input,omitempty"`
	// EdgeOutputDeny (top-level only, restricted mode) adds IPv4/IPv6
	// networks the proxy may not connect to, e.g. a provider's private
	// network, to the built-in metadata and mesh denylist.
	EdgeOutputDeny []string `yaml:"edge_output_deny,omitempty"`
}

type GeoIP struct {
	MaxMindAccountID  string   `yaml:"maxmind_account_id"`
	MaxMindLicenseKey string   `yaml:"maxmind_license_key"` // secret://
	Editions          []string `yaml:"editions"`
}

type CrowdSec struct {
	Enabled bool   `yaml:"enabled"`
	LAPIURL string `yaml:"lapi_url"`
	APIKey  string `yaml:"api_key"` // secret://
}

func (c *Config) applySecurityDefaults() {
	if g := c.Edge.GeoIP; g != nil && len(g.Editions) == 0 {
		g.Editions = slices.Clone(DefaultGeoIPEditions)
	}
	if cs := c.Edge.CrowdSec; cs != nil && cs.LAPIURL == "" {
		cs.LAPIURL = DefaultCrowdSecLAPI
	}
	for name, a := range c.Apps {
		if w := a.WAF; w != nil {
			if w.Mode == "" {
				w.Mode = WAFBlock
			}
			if w.Paranoia == 0 {
				w.Paranoia = 1
			}
			if w.InboundThreshold == 0 {
				w.InboundThreshold = 5
			}
			if w.OutboundThreshold == 0 {
				w.OutboundThreshold = 4
			}
		}
		for i := range a.RateLimit {
			r := &a.RateLimit[i]
			if r.Key == "" {
				r.Key = "ip"
			}
			if r.Action == "" {
				r.Action = RateLimitBlock
			}
		}
		if b := a.BotChallenge; b != nil {
			if b.Mode == "" {
				b.Mode = ChallengeSuspicious
			}
			if b.Difficulty == 0 {
				b.Difficulty = DefaultChallengeDifficulty
			}
			if b.TTL == 0 {
				b.TTL = Duration(DefaultChallengeTTL)
			}
		}
		c.Apps[name] = a
	}
}

// EffectiveSecurity merges the global and app security rules: deny lists
// add up, allow lists set on the app replace the global ones, and
// under-attack mode applies if either enables it.
func (c *Config) EffectiveSecurity(a App) Security {
	g := c.Security
	s := Security{
		IPAllow:      g.IPAllow,
		IPDeny:       slices.Concat(g.IPDeny),
		CountryAllow: g.CountryAllow,
		CountryDeny:  slices.Concat(g.CountryDeny),
		ASNDeny:      slices.Concat(g.ASNDeny),
		UnderAttack:  g.UnderAttack,
		GoodBots:     g.GoodBots,
	}
	if as := a.Security; as != nil {
		if len(as.IPAllow) > 0 {
			s.IPAllow = as.IPAllow
		}
		if len(as.CountryAllow) > 0 {
			s.CountryAllow = as.CountryAllow
		}
		s.IPDeny = append(s.IPDeny, as.IPDeny...)
		s.CountryDeny = append(s.CountryDeny, as.CountryDeny...)
		s.ASNDeny = append(s.ASNDeny, as.ASNDeny...)
		s.UnderAttack = s.UnderAttack || as.UnderAttack
		if as.GoodBots != nil {
			s.GoodBots = as.GoodBots
		}
	}
	if s.GoodBots == nil {
		t := true
		s.GoodBots = &t
	}
	return s
}

// EffectiveChallenge returns the app's bot challenge after applying
// under-attack mode. Mode is ChallengeOff when the app is not challenged
// (rate-limit rules with action challenge still work then).
func (c *Config) EffectiveChallenge(a App) BotChallenge {
	b := BotChallenge{Mode: ChallengeOff, Difficulty: DefaultChallengeDifficulty, TTL: Duration(DefaultChallengeTTL)}
	if a.BotChallenge != nil {
		b = *a.BotChallenge
	}
	if b.Mode == ChallengeUnderAttack || c.EffectiveSecurity(a).UnderAttack {
		b.Mode = ChallengeUnderAttack
		b.Difficulty += UnderAttackExtraDifficulty
	}
	return b
}

// NeedsChallenge reports whether the app uses the edge_challenge handler.
func (c *Config) NeedsChallenge(a App) bool {
	if c.EffectiveChallenge(a).Mode != ChallengeOff {
		return true
	}
	return slices.ContainsFunc(a.RateLimit, func(r RateLimitRule) bool { return r.Action == RateLimitChallenge })
}

// countryRe is shared with access.go.
var (
	wafTagRe    = regexp.MustCompile(`^[A-Za-z0-9_./:-]+$`)
	safePathRe  = regexp.MustCompile(`^/[A-Za-z0-9_.~/%:@!$&()+,;=-]*\*?$`)
	headerRe    = regexp.MustCompile(`^[A-Za-z0-9-]+$`)
	editionRe   = regexp.MustCompile(`^[A-Za-z0-9-]+$`)
	wafTargetRe = regexp.MustCompile(`^(ARGS|ARGS_GET|ARGS_POST|ARGS_NAMES|ARGS_GET_NAMES|ARGS_POST_NAMES|REQUEST_HEADERS|REQUEST_HEADERS_NAMES|REQUEST_COOKIES|REQUEST_COOKIES_NAMES|REQUEST_BODY|REQUEST_URI|REQUEST_FILENAME|FILES|FILES_NAMES|XML|JSON)(:[A-Za-z0-9_.\[\]-]+)?$`)
)

// Tunnel input modes (security.tunnel_input).
const (
	TunnelInputOpen       = "open"
	TunnelInputRestricted = "restricted"
)

// TunnelInputRestricted reports whether sites may reach only their own
// connector control port and Smart DNS address on the edge.
func (c *Config) TunnelInputRestricted() bool {
	return c.Security.TunnelInput == TunnelInputRestricted
}

func (c *Config) validateSecurity(v *validator) {
	c.validateSecurityRules(v, "security", &c.Security)
	switch c.Security.TunnelInput {
	case "", TunnelInputOpen:
	case TunnelInputRestricted:
		if !c.Edge.FirewallManaged() {
			v.add("security.tunnel_input", "restricted needs the managed firewall (edge.manage_firewall)")
		}
	default:
		v.add("security.tunnel_input", "must be open or restricted, got %q", c.Security.TunnelInput)
	}
	for i, s := range c.Security.EdgeOutputDeny {
		if _, err := netip.ParsePrefix(s); err != nil {
			v.add(fmt.Sprintf("security.edge_output_deny[%d]", i), "invalid CIDR %q", s)
		}
	}
	if len(c.Security.EdgeOutputDeny) > 0 && !c.TunnelInputRestricted() {
		v.add("security.edge_output_deny", "only applies with tunnel_input: restricted")
	}
	if g := c.Edge.GeoIP; g != nil {
		if g.MaxMindAccountID == "" {
			v.add("edge.geoip.maxmind_account_id", "is required")
		}
		if g.MaxMindLicenseKey == "" {
			v.add("edge.geoip.maxmind_license_key", "is required (use secret://name)")
		}
		for i, e := range g.Editions {
			if !editionRe.MatchString(e) {
				v.add(fmt.Sprintf("edge.geoip.editions[%d]", i), "invalid edition %q", e)
			}
		}
	}
	if cs := c.Edge.CrowdSec; cs != nil && cs.Enabled {
		if u, err := url.Parse(cs.LAPIURL); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			v.add("edge.crowdsec.lapi_url", "must be an http(s) URL, got %q", cs.LAPIURL)
		}
		if cs.APIKey == "" {
			v.add("edge.crowdsec.api_key", "is required when crowdsec is enabled (use secret://name)")
		}
	}

	for _, name := range sortedKeys(c.Apps) {
		a := c.Apps[name]
		p := "apps." + name
		if a.Security != nil {
			c.validateSecurityRules(v, p+".security", a.Security)
			if a.Security.TunnelInput != "" {
				v.add(p+".security.tunnel_input", "is node-wide; set it in the top-level security block")
			}
			if len(a.Security.EdgeOutputDeny) > 0 {
				v.add(p+".security.edge_output_deny", "is node-wide; set it in the top-level security block")
			}
		}
		if w := a.WAF; w != nil {
			validateWAF(v, p+".waf", w)
		}
		for i, r := range a.RateLimit {
			validateRateLimit(v, fmt.Sprintf("%s.rate_limit[%d]", p, i), r)
		}
		if b := a.BotChallenge; b != nil {
			bp := p + ".bot_challenge"
			switch b.Mode {
			case ChallengeOff, ChallengeSuspicious, ChallengeAlways, ChallengeUnderAttack:
			default:
				v.add(bp+".mode", "must be off, suspicious, always or under_attack; got %q", b.Mode)
			}
			if b.Difficulty < 1 || b.Difficulty > 28 {
				v.add(bp+".difficulty", "must be 1-28 leading zero bits, got %d", b.Difficulty)
			}
			if b.TTL < Duration(time.Minute) {
				v.add(bp+".ttl", "must be at least 1m")
			}
			for i, ep := range b.ExemptPaths {
				if !safePathRe.MatchString(ep) {
					v.add(fmt.Sprintf("%s.exempt_paths[%d]", bp, i), "invalid path %q", ep)
				}
			}
		}
	}
}

func (c *Config) validateSecurityRules(v *validator, p string, s *Security) {
	cidrs := func(field string, list []string) {
		for i, s := range list {
			if _, err := ParseCIDR(s); err != nil {
				v.add(fmt.Sprintf("%s.%s[%d]", p, field, i), "invalid IP or CIDR %q", s)
			}
		}
	}
	cidrs("ip_allow", s.IPAllow)
	cidrs("ip_deny", s.IPDeny)
	countries := func(field string, list []string) {
		for i, cc := range list {
			if !countryRe.MatchString(cc) {
				v.add(fmt.Sprintf("%s.%s[%d]", p, field, i), "must be an uppercase ISO 3166-1 alpha-2 code, got %q", cc)
			}
		}
	}
	countries("country_allow", s.CountryAllow)
	countries("country_deny", s.CountryDeny)
	for i, asn := range s.ASNDeny {
		if asn <= 0 {
			v.add(fmt.Sprintf("%s.asn_deny[%d]", p, i), "invalid ASN %d", asn)
		}
	}
	if len(s.CountryAllow)+len(s.CountryDeny)+len(s.ASNDeny) > 0 && c.Edge.GeoIP == nil {
		v.add(p, "country and ASN rules need edge.geoip (MaxMind credentials)")
	}
}

func validateWAF(v *validator, p string, w *WAF) {
	switch w.Mode {
	case WAFOff, WAFDetect, WAFBlock:
	default:
		v.add(p+".mode", "must be off, detect or block; got %q", w.Mode)
	}
	if w.Paranoia < 1 || w.Paranoia > 4 {
		v.add(p+".paranoia", "must be 1-4, got %d", w.Paranoia)
	}
	if w.InboundThreshold < 1 {
		v.add(p+".inbound_threshold", "must be at least 1")
	}
	if w.OutboundThreshold < 1 {
		v.add(p+".outbound_threshold", "must be at least 1")
	}
	for i, e := range w.Exclusions {
		ep := fmt.Sprintf("%s.exclusions[%d]", p, i)
		switch {
		case e.Rule != 0 && e.Tag != "":
			v.add(ep, "set either rule or tag, not both")
		case e.Rule == 0 && e.Tag == "":
			v.add(ep, "rule or tag is required")
		case e.Rule < 0 || e.Rule > 9999999:
			v.add(ep+".rule", "invalid rule ID %d", e.Rule)
		case e.Tag != "" && !wafTagRe.MatchString(e.Tag):
			v.add(ep+".tag", "invalid tag %q", e.Tag)
		}
		if e.Path != "" && !safePathRe.MatchString(e.Path) {
			v.add(ep+".path", "must be a path prefix starting with / (no spaces or quotes), got %q", e.Path)
		}
		if e.Target != "" && !wafTargetRe.MatchString(e.Target) {
			v.add(ep+".target", "must be a collection with optional key, e.g. ARGS:q or REQUEST_HEADERS:User-Agent; got %q", e.Target)
		}
	}
}

func validateRateLimit(v *validator, p string, r RateLimitRule) {
	if !safePathRe.MatchString(r.Match) {
		v.add(p+".match", "must be a path pattern starting with /, got %q", r.Match)
	}
	if r.Requests < 1 {
		v.add(p+".requests", "must be at least 1")
	}
	if r.Per <= 0 {
		v.add(p+".per", "must be a positive duration such as 1m")
	}
	switch {
	case r.Key == "ip", r.Key == "ip_path", r.Key == "email":
	case strings.HasPrefix(r.Key, "header:") && headerRe.MatchString(strings.TrimPrefix(r.Key, "header:")):
	default:
		v.add(p+".key", "must be ip, ip_path, header:<name> or email; got %q", r.Key)
	}
	if r.Action != RateLimitBlock && r.Action != RateLimitChallenge {
		v.add(p+".action", "must be block or challenge; got %q", r.Action)
	}
}

// ParseCIDR parses a CIDR or a bare IP address (as a single-host prefix).
func ParseCIDR(s string) (netip.Prefix, error) {
	if p, err := netip.ParsePrefix(s); err == nil {
		return p.Masked(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	return netip.PrefixFrom(a, a.BitLen()), nil
}

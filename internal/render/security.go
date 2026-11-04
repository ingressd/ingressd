// SPDX-License-Identifier: Apache-2.0

package render

import (
	"cmp"
	"fmt"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/ingressd/ingressd/pkg/config"
)

// SecurityOptions carries facts about the edge host that security rendering
// depends on but cannot look up itself (render is pure).
type SecurityOptions struct {
	// StateDir is ingressd's state directory (default /var/lib/ingressd).
	// The WAF audit log is written to <StateDir>/waf/audit.log.
	StateDir string
	// CountryDB and ASNDB are the MaxMind databases on disk, or "" if they
	// have not been downloaded yet (country/ASN rules are skipped then).
	CountryDB, ASNDB string
}

// EmailHeader carries the authenticated user's email from edge_auth.
const EmailHeader = "X-Edge-User-Email"

// WAFAuditLog is the Coraza JSON audit log for a state directory.
func WAFAuditLog(stateDir string) string {
	return path.Join(cmp.Or(stateDir, "/var/lib/ingressd"), "waf", "audit.log")
}

// securityHandlers returns an app's security middleware, cheapest first:
// IP/geo rules, CrowdSec, rate limits, the bot challenge, then the WAF.
func securityHandlers(cfg *config.Config, name string, app config.App, res Resolver, opts Options) ([]obj, error) {
	var hs []obj
	sec := cfg.EffectiveSecurity(app)
	if h := ipGeoHandler(sec, opts.Security); h != nil {
		hs = append(hs, h)
	}
	if cs := cfg.Edge.CrowdSec; cs != nil && cs.Enabled {
		hs = append(hs, obj{"handler": "crowdsec"})
	}
	if h := rateLimitHandler(name, app); h != nil {
		hs = append(hs, h)
	}
	if cfg.NeedsChallenge(app) {
		key, err := res.Resolve("secret://" + config.ChallengeKeySecret)
		if err != nil {
			return nil, fmt.Errorf("bot challenge key: %w", err)
		}
		hs = append(hs, challengeHandler(cfg, app, sec, key))
	}
	if app.WAF.Enabled() {
		hs = append(hs, obj{
			"handler":        "waf",
			"load_owasp_crs": true,
			"directives":     wafDirectives(app.WAF, WAFAuditLog(opts.Security.StateDir)),
		})
	}
	return hs, nil
}

var forbidden = []obj{{"handler": "static_response", "status_code": 403, "body": "Forbidden\n"}}

// ipGeoHandler blocks requests that fail the IP, country or ASN rules.
func ipGeoHandler(s config.Security, so SecurityOptions) obj {
	var routes []obj
	block := func(m obj) { routes = append(routes, obj{"match": []obj{m}, "handle": forbidden}) }
	cidrs := func(list []string) []string {
		out := make([]string, 0, len(list))
		for _, c := range list {
			if p, err := config.ParseCIDR(c); err == nil {
				out = append(out, p.String())
			}
		}
		return out
	}
	if len(s.IPDeny) > 0 {
		block(obj{"remote_ip": obj{"ranges": cidrs(s.IPDeny)}})
	}
	if len(s.IPAllow) > 0 {
		block(obj{"not": []obj{{"remote_ip": obj{"ranges": cidrs(s.IPAllow)}}}})
	}
	// The maxmind matcher matches allowed requests, so block on "not".
	geo := func(db, field string, list []string) {
		if db != "" && len(list) > 0 {
			block(obj{"not": []obj{{"maxmind_geolocation": obj{"db_path": db, field: list}}}})
		}
	}
	geo(so.CountryDB, "allow_countries", s.CountryAllow)
	geo(so.CountryDB, "deny_countries", s.CountryDeny)
	asns := make([]string, len(s.ASNDeny))
	for i, a := range s.ASNDeny {
		asns[i] = strconv.Itoa(a)
	}
	geo(so.ASNDB, "deny_asn", asns)
	if len(routes) == 0 {
		return nil
	}
	return obj{"handler": "subroute", "routes": routes}
}

// rateLimitKey maps a config key to the caddy-ratelimit key placeholder.
func rateLimitKey(k string) string {
	switch {
	case k == "ip_path":
		return "{http.vars.client_ip} {http.request.uri.path}"
	case k == "email":
		return "{http.request.header." + EmailHeader + "}"
	case strings.HasPrefix(k, "header:"):
		return "{http.request.header." + strings.TrimPrefix(k, "header:") + "}"
	default:
		return "{http.vars.client_ip}"
	}
}

// rateLimitHandler renders the app's blocking rate limits (429 with
// Retry-After). Rules with action challenge are handled by edge_challenge.
func rateLimitHandler(name string, app config.App) obj {
	zones := obj{}
	for i, r := range app.RateLimit {
		if r.Action != config.RateLimitBlock {
			continue
		}
		m := obj{"path": []string{r.Match}}
		if r.Key == "email" {
			// Only authenticated requests are limited per user.
			m["header_regexp"] = obj{EmailHeader: obj{"pattern": ".+"}}
		}
		// Zone state is global to the Caddy process, so names include the app.
		zones[fmt.Sprintf("%s_%d", name, i)] = obj{
			"match":      []obj{m},
			"key":        rateLimitKey(r.Key),
			"max_events": r.Requests,
			"window":     time.Duration(r.Per).String(),
		}
	}
	if len(zones) == 0 {
		return nil
	}
	return obj{"handler": "rate_limit", "rate_limits": zones}
}

func challengeHandler(cfg *config.Config, app config.App, sec config.Security, key string) obj {
	b := cfg.EffectiveChallenge(app)
	h := obj{
		"handler":    "edge_challenge",
		"mode":       b.Mode,
		"difficulty": b.Difficulty,
		"ttl":        time.Duration(b.TTL).String(),
		"key":        key,
		"good_bots":  *sec.GoodBots,
	}
	if len(b.ExemptPaths) > 0 {
		h["exempt_paths"] = b.ExemptPaths
	}
	var rules []obj
	for _, r := range app.RateLimit {
		if r.Action == config.RateLimitChallenge {
			rules = append(rules, obj{
				"path": r.Match, "requests": r.Requests, "window": time.Duration(r.Per).String(), "key": r.Key,
			})
		}
	}
	if len(rules) > 0 {
		h["rate_rules"] = rules
	}
	return h
}

// wafExclusionBase is the first rule ID used for generated exclusions.
const wafExclusionBase = 10000

// wafDirectives builds the Coraza configuration: the CRS with the app's
// paranoia level, thresholds and exclusions, and JSON audit logging of
// blocked (or, in detect mode, would-be-blocked) requests.
func wafDirectives(w *config.WAF, auditLog string) string {
	engine := map[string]string{config.WAFBlock: "On", config.WAFDetect: "DetectionOnly"}[w.Mode]
	onOff := map[bool]string{true: "On", false: "Off"}
	l := []string{
		"Include @coraza.conf-recommended",
		"Include @crs-setup.conf.example",
		"SecRuleEngine " + engine,
		"SecResponseBodyAccess " + onOff[w.ResponseBody],
		"SecAuditEngine RelevantOnly",
		`SecAuditLogRelevantStatus "^40[03]$"`,
		"SecAuditLogParts ABFHKZ",
		"SecAuditLogFormat JSON",
		"SecAuditLogType Serial",
		"SecAuditLogFileMode 0640",
		"SecAuditLog " + auditLog,
		fmt.Sprintf(`SecAction "id:900000,phase:1,pass,t:none,nolog,setvar:tx.blocking_paranoia_level=%d"`, w.Paranoia),
		fmt.Sprintf(`SecAction "id:900110,phase:1,pass,t:none,nolog,setvar:tx.inbound_anomaly_score_threshold=%d,setvar:tx.outbound_anomaly_score_threshold=%d"`,
			w.InboundThreshold, w.OutboundThreshold),
	}
	for i, e := range w.Exclusions {
		var ctl string
		switch {
		case e.Rule != 0 && e.Target != "":
			ctl = fmt.Sprintf("ctl:ruleRemoveTargetById=%d;%s", e.Rule, e.Target)
		case e.Rule != 0:
			ctl = fmt.Sprintf("ctl:ruleRemoveById=%d", e.Rule)
		case e.Target != "":
			ctl = fmt.Sprintf("ctl:ruleRemoveTargetByTag=%s;%s", e.Tag, e.Target)
		default:
			ctl = "ctl:ruleRemoveByTag=" + e.Tag
		}
		action := fmt.Sprintf("id:%d,phase:1,pass,t:none,nolog,%s", wafExclusionBase+i, ctl)
		if p := strings.TrimSuffix(e.Path, "*"); p != "" {
			l = append(l, fmt.Sprintf(`SecRule REQUEST_FILENAME "@beginsWith %s" "%s"`, p, action))
		} else {
			l = append(l, fmt.Sprintf(`SecAction "%s"`, action))
		}
	}
	l = append(l, "Include @owasp_crs/*.conf")
	return strings.Join(l, "\n") + "\n"
}

// renderSecurityApps adds top-level Caddy apps used by security features.
func renderSecurityApps(cfg *config.Config, res Resolver, apps obj) error {
	cs := cfg.Edge.CrowdSec
	if cs == nil || !cs.Enabled {
		return nil
	}
	key, err := res.Resolve(cs.APIKey)
	if err != nil {
		return fmt.Errorf("edge.crowdsec.api_key: %w", err)
	}
	f := false
	apps["crowdsec"] = obj{"api_url": cs.LAPIURL, "api_key": key, "enable_hard_fails": &f}
	return nil
}

// SPDX-License-Identifier: Apache-2.0

package config

import (
	"strings"
	"testing"
	"time"
)

func TestSecurityParseAndDefaults(t *testing.T) {
	c := mustParse(t, baseYAML+`    waf: { exclusions: [{ rule: 942100, path: /api/search }] }
    rate_limit: [{ match: /login, requests: 10, per: 1m }]
    bot_challenge: always
`)
	a := c.Apps["web"]
	if w := a.WAF; w.Mode != WAFBlock || w.Paranoia != 1 || w.InboundThreshold != 5 || w.OutboundThreshold != 4 {
		t.Errorf("waf defaults = %+v", w)
	}
	if r := a.RateLimit[0]; r.Key != "ip" || r.Action != RateLimitBlock || time.Duration(r.Per) != time.Minute {
		t.Errorf("rate limit defaults = %+v", r)
	}
	if b := a.BotChallenge; b.Mode != ChallengeAlways || b.Difficulty != DefaultChallengeDifficulty || time.Duration(b.TTL) != DefaultChallengeTTL {
		t.Errorf("bot challenge = %+v", b)
	}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}

	c = mustParse(t, baseYAML+"    bot_challenge: { mode: suspicious, difficulty: 18 }\n")
	if b := c.Apps["web"].BotChallenge; b.Mode != ChallengeSuspicious || b.Difficulty != 18 {
		t.Errorf("bot challenge mapping = %+v", b)
	}
	if _, err := Parse([]byte(baseYAML + "    bot_challenge: { mode: always, bogus: 1 }\n")); err == nil {
		t.Error("unknown bot_challenge field accepted")
	}
}

func TestEffectiveSecurity(t *testing.T) {
	c := mustParse(t, `
version: 1
security: { ip_deny: [192.0.2.0/24], ip_allow: [10.0.0.0/8], under_attack: false }
apps:
  web:
    hosts: [web.example.com]
    origin: http://192.168.0.1
    security: { ip_deny: [198.51.100.7], ip_allow: [172.16.0.0/12], under_attack: true, good_bots: false }
  blog:
    hosts: [blog.example.com]
    origin: http://192.168.0.1
`)
	s := c.EffectiveSecurity(c.Apps["web"])
	if strings.Join(s.IPDeny, ",") != "192.0.2.0/24,198.51.100.7" || strings.Join(s.IPAllow, ",") != "172.16.0.0/12" || !s.UnderAttack || *s.GoodBots {
		t.Errorf("web = %+v", s)
	}
	s = c.EffectiveSecurity(c.Apps["blog"])
	if strings.Join(s.IPDeny, ",") != "192.0.2.0/24" || strings.Join(s.IPAllow, ",") != "10.0.0.0/8" || s.UnderAttack || !*s.GoodBots {
		t.Errorf("blog = %+v", s)
	}
	if b := c.EffectiveChallenge(c.Apps["web"]); b.Mode != ChallengeUnderAttack || b.Difficulty != DefaultChallengeDifficulty+UnderAttackExtraDifficulty {
		t.Errorf("web challenge = %+v", b)
	}
	if c.NeedsChallenge(c.Apps["blog"]) {
		t.Error("blog needs no challenge")
	}
}

func TestValidateSecurity(t *testing.T) {
	tests := []struct {
		name, yaml, wantErr string
	}{
		{"bad waf mode", "    waf: { mode: on }\n", "waf.mode: must be off, detect or block"},
		{"paranoia range", "    waf: { paranoia: 5 }\n", "waf.paranoia: must be 1-4"},
		{"exclusion needs rule or tag", "    waf: { exclusions: [{ path: /x }] }\n", "rule or tag is required"},
		{"exclusion rule and tag", "    waf: { exclusions: [{ rule: 1, tag: x }] }\n", "either rule or tag"},
		{"exclusion path injection", "    waf: { exclusions: [{ rule: 942100, path: '/a\" \"id:1' }] }\n", "exclusions[0].path"},
		{"exclusion target", "    waf: { exclusions: [{ rule: 942100, target: 'ARGS:q;x' }] }\n", "exclusions[0].target"},
		{"rate limit key", "    rate_limit: [{ match: /x, requests: 1, per: 1s, key: cookie }]\n", "rate_limit[0].key"},
		{"rate limit per", "    rate_limit: [{ match: /x, requests: 1 }]\n", "rate_limit[0].per"},
		{"rate limit action", "    rate_limit: [{ match: /x, requests: 1, per: 1s, action: drop }]\n", "rate_limit[0].action"},
		{"challenge mode", "    bot_challenge: sometimes\n", "bot_challenge.mode"},
		{"challenge difficulty", "    bot_challenge: { difficulty: 40 }\n", "bot_challenge.difficulty"},
		{"bad cidr", "    security: { ip_deny: [nope] }\n", "security.ip_deny[0]: invalid IP or CIDR"},
		{"country code", "    security: { country_deny: [gb] }\n", "country_deny[0]"},
		{"country needs geoip", "    security: { country_deny: [GB] }\n", "need edge.geoip"},
		{"header key ok", "    rate_limit: [{ match: /api/*, requests: 1, per: 1s, key: 'header:X-Api-Key' }]\n", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c, err := Parse([]byte(baseYAML + tc.yaml))
			if err == nil {
				err = c.Validate()
			}
			switch {
			case tc.wantErr == "" && err != nil:
				t.Fatalf("unexpected error: %v", err)
			case tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)):
				t.Fatalf("error = %v, want %q", err, tc.wantErr)
			}
		})
	}
}

func TestValidateEdgeSecurity(t *testing.T) {
	c := mustParse(t, strings.Replace(baseYAML, "  acme: { ca: internal }", `  acme: { ca: internal }
  geoip: { maxmind_account_id: "1" }
  crowdsec: { enabled: true, lapi_url: "ftp://x" }`, 1))
	err := c.Validate()
	for _, want := range []string{"edge.geoip.maxmind_license_key", "edge.crowdsec.lapi_url", "edge.crowdsec.api_key"} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("error = %v, want %s", err, want)
		}
	}
}

func TestLargeStoredRateLimitStaysValid(t *testing.T) {
	v := &validator{}
	validateRateLimit(v, "r", RateLimitRule{Match: "/x", Requests: 2_000_000_000, Per: Duration(time.Minute), Key: "ip", Action: RateLimitBlock})
	if len(v.errs) > 0 {
		t.Fatal(v.errs)
	}
}

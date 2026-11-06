// SPDX-License-Identifier: Apache-2.0

package render

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/ingressd/ingressd/internal/secrets"
	"github.com/ingressd/ingressd/pkg/config"
)

const securityConfig = `
version: 1
edge:
  acme: { ca: internal }
  geoip: { maxmind_account_id: "42", maxmind_license_key: secret://mm }
  crowdsec: { enabled: true, api_key: secret://cs }
security:
  ip_deny: [203.0.113.0/24]
  country_deny: [KP]
apps:
  web:
    hosts: [web.example.com]
    origin: http://192.168.0.17:8080
    waf:
      mode: block
      paranoia: 2
      exclusions:
        - { rule: 942100, path: /api/search, target: "ARGS:q" }
        - { tag: attack-xss, path: /cms/* }
        - { rule: 920350 }
    rate_limit:
      - { match: /login, requests: 10, per: 1m }
      - { match: /api/*, requests: 100, per: 1m, key: "header:X-Api-Key" }
      - { match: /signup, requests: 3, per: 10m, action: challenge }
    bot_challenge: { mode: suspicious, exempt_paths: [/api/*] }
    security: { ip_allow: [198.51.100.0/24, 2001:db8::/32], asn_deny: [64496] }
  docs:
    hosts: [docs.example.com]
    origin: http://192.168.0.18:8080
    waf: { mode: detect, response_body: true }
    rate_limit: [{ match: /search, requests: 5, per: 1s, key: email }]
`

func renderSecurity(t *testing.T, so SecurityOptions, mutate func(*config.Config)) string {
	t.Helper()
	cfg, err := config.Parse([]byte(securityConfig))
	if err != nil {
		t.Fatal(err)
	}
	if mutate != nil {
		mutate(cfg)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	st := secrets.NewMemory(map[string]string{"mm": "MM", "cs": "CS-KEY", config.ChallengeKeySecret: "CHALLENGE-KEY"})
	p, err := Render(cfg, st, fakeKeys{}, Options{AdminListen: "unix//run/ingressd/caddy-admin.sock", Security: so})
	if err != nil {
		t.Fatal(err)
	}
	return string(p.Caddy)
}

func TestSecurityGolden(t *testing.T) {
	s := renderSecurity(t, SecurityOptions{
		StateDir:  "/var/lib/ingressd",
		CountryDB: "/var/lib/ingressd/geoip/GeoLite2-Country-20261102T000000.mmdb",
		ASNDB:     "/var/lib/ingressd/geoip/GeoLite2-ASN-20261102T000000.mmdb",
	}, nil)
	golden(t, "security.json", s+"\n")
}

// handlerNames lists an app's handler types in order.
func handlerNames(t *testing.T, caddyJSON, host string) []string {
	t.Helper()
	var root struct {
		Apps struct {
			HTTP struct {
				Servers map[string]struct {
					Routes []struct {
						Match []struct {
							Host []string `json:"host"`
						} `json:"match"`
						Handle []struct {
							Routes []struct {
								Handle []map[string]any `json:"handle"`
							} `json:"routes"`
						} `json:"handle"`
					} `json:"routes"`
				} `json:"servers"`
			} `json:"http"`
		} `json:"apps"`
	}
	if err := json.Unmarshal([]byte(caddyJSON), &root); err != nil {
		t.Fatal(err)
	}
	for _, r := range root.Apps.HTTP.Servers["edge"].Routes {
		if len(r.Match) == 1 && len(r.Match[0].Host) > 0 && r.Match[0].Host[0] == host {
			var names []string
			for _, h := range r.Handle[0].Routes[0].Handle {
				names = append(names, h["handler"].(string))
			}
			return names
		}
	}
	t.Fatalf("no route for %s", host)
	return nil
}

func useClientNet(t *testing.T) {
	t.Helper()
	clientNetKeys = true
	t.Cleanup(func() { clientNetKeys = false })
}

func TestSecurityOrder(t *testing.T) {
	useClientNet(t)
	s := renderSecurity(t, SecurityOptions{}, nil)
	got := strings.Join(handlerNames(t, s, "web.example.com"), ",")
	// Public apps first strip spoofable identity headers (access), then security.
	if want := "headers,subroute,crowdsec,edge_client_net,rate_limit,edge_challenge,waf,reverse_proxy"; got != want {
		t.Errorf("handler order = %s, want %s", got, want)
	}
	for _, want := range []string{
		`SecRuleEngine On`,
		`SecRuleEngine DetectionOnly`,
		`setvar:tx.blocking_paranoia_level=2`,
		`SecRule REQUEST_FILENAME \"@beginsWith /api/search\" \"id:10000,phase:1,pass,t:none,nolog,ctl:ruleRemoveTargetById=942100;ARGS:q\"`,
		`SecRule REQUEST_FILENAME \"@beginsWith /cms/\" \"id:10001,phase:1,pass,t:none,nolog,ctl:ruleRemoveByTag=attack-xss\"`,
		`SecAction \"id:10002,phase:1,pass,t:none,nolog,ctl:ruleRemoveById=920350\"`,
		`SecAuditLog /var/lib/ingressd/waf/audit.log`,
		`"key": "{http.request.header.X-Api-Key}"`,
		`"X-Edge-User-Email": {`,
		`"api_key": "CS-KEY"`,
		`"key": "CHALLENGE-KEY"`,
		`"rate_rules": [`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("caddy config missing %s", want)
		}
	}
	// No GeoIP database yet: country and ASN rules are skipped.
	if strings.Contains(s, "maxmind_geolocation") {
		t.Error("maxmind matcher rendered without a database")
	}
}

func TestUnderAttack(t *testing.T) {
	s := renderSecurity(t, SecurityOptions{}, func(c *config.Config) { c.Security.UnderAttack = true })
	got := strings.Join(handlerNames(t, s, "docs.example.com"), ",")
	if !strings.Contains(got, "edge_challenge") {
		t.Fatalf("under attack: docs handlers = %s", got)
	}
	if !strings.Contains(s, `"mode": "under_attack"`) || !strings.Contains(s, `"difficulty": 20`) {
		t.Error("under-attack challenge not rendered with raised difficulty")
	}
}

func TestProtectedAppFilterOrder(t *testing.T) {
	useClientNet(t)
	const cfg = `
version: 1
edge: { acme: { ca: internal }, crowdsec: { enabled: true, api_key: secret://cs } }
email: { provider: log, log: { path: /var/lib/ingressd/mail.log } }
access: { portal_host: auth.example.com }
policies:
  staff: { action: allow, include: [{ email_domain: example.com }] }
apps:
  web:
    hosts: [web.example.com]
    origin: http://192.0.2.10:8080
    access: [staff]
    security: { ip_deny: [203.0.113.0/24] }
    rate_limit:
      - { match: /login, requests: 10, per: 1m }
      - { match: /api/*, requests: 100, per: 1m, key: email }
      - { match: /files/*, requests: 100, per: 1m, key: "header:X-Api-Key" }
`
	c, err := config.Parse([]byte(cfg))
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	st := map[string]string{"cs": "CS-KEY"}
	for k, v := range accessSecrets {
		st[k] = v
	}
	p, err := Render(c, secrets.NewMemory(st), fakeKeys{}, Options{AdminListen: "unix//run/ingressd/caddy-admin.sock"})
	if err != nil {
		t.Fatal(err)
	}
	s := string(p.Caddy)
	got := strings.Join(handlerNames(t, s, "web.example.com"), ",")
	if want := "subroute,crowdsec,edge_client_net,rate_limit,edge_auth,rate_limit,reverse_proxy"; got != want {
		t.Errorf("handler order = %s, want %s", got, want)
	}
	auth := strings.Index(s, `"handler": "edge_auth"`)
	for _, after := range []string{`"web_1"`, `"web_2"`} {
		if i := strings.Index(s, after); i < auth {
			t.Errorf("zone %s comes before edge_auth", after)
		}
	}
	if i := strings.Index(s, `"web_0"`); i < 0 || i > auth {
		t.Error("address zone does not come before edge_auth")
	}
}

func TestRateLimitRequestsClamped(t *testing.T) {
	s := renderSecurity(t, SecurityOptions{}, func(c *config.Config) {
		a := c.Apps["web"]
		a.RateLimit[0].Requests = 2_000_000_000
		c.Apps["web"] = a
	})
	if strings.Contains(s, "2000000000") || !strings.Contains(s, `"max_events": 100000`) {
		t.Error("rate limit size was not clamped")
	}
}

func TestRateLimitKeysDefaultToClientIP(t *testing.T) {
	if got := rateLimitKey("ip"); got != "{http.vars.client_ip}" {
		t.Errorf("rateLimitKey(ip) = %q", got)
	}
}

func TestRateLimitKeysUseClientNet(t *testing.T) {
	useClientNet(t)
	for k, want := range map[string]string{
		"ip":      "{http.vars.client_net}",
		"ip_path": "{http.vars.client_net} {http.request.uri.path}",
	} {
		if got := rateLimitKey(k); got != want {
			t.Errorf("rateLimitKey(%q) = %q, want %q", k, got, want)
		}
	}
}

func TestWAFAuditLogParts(t *testing.T) {
	d := wafDirectives(&config.WAF{Mode: config.WAFBlock, Paranoia: 1}, "/tmp/audit.log")
	if !strings.Contains(d, "SecAuditLogParts AFHKZ\n") {
		t.Errorf("audit log parts: %s", d)
	}
}

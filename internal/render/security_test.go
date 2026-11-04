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
						Match  []map[string][]string `json:"match"`
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
		if len(r.Match) == 1 && len(r.Match[0]["host"]) > 0 && r.Match[0]["host"][0] == host {
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

func TestSecurityOrder(t *testing.T) {
	s := renderSecurity(t, SecurityOptions{}, nil)
	got := strings.Join(handlerNames(t, s, "web.example.com"), ",")
	// Public apps first strip spoofable identity headers (access), then security.
	if want := "headers,subroute,crowdsec,rate_limit,edge_challenge,waf,reverse_proxy"; got != want {
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

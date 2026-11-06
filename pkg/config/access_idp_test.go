// SPDX-License-Identifier: Apache-2.0

package config

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
)

const idpBase = `
version: 1
edge: { acme: { ca: internal } }
email: { provider: log, log: { path: /tmp/mail.log } }
access:
  portal_host: auth.example.com
  providers:
    discord: { client_id: "123", client_secret: secret://discord }
    steam: { api_key: secret://steam, session: 1h }
service_tokens:
  bot: { header: X-Bot-Token, client_secret: secret://bot, expires: 2027-11-01 }
policies:
  mods:
    action: allow
    include: [{ discord_role: ["100000000000000001/200000000000000002"] }]
    require: [{ login_method: discord }]
  gamers:
    action: allow
    include: [{ steam_group: ["4"] }, { steam_app: ["440"] }]
  bot:
    action: service_auth
    include: [{ service_token: bot }]
    require: [{ ip: 10.0.0.0/8 }]
apps:
  web:
    hosts: [web.example.com]
    origin: http://192.0.2.10:80
    access: [bot, mods, gamers]
    login_methods: [discord, steam, email]
`

func TestIdentityConfigValid(t *testing.T) {
	c, err := Parse([]byte(idpBase))
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	if got := c.Policies["gamers"].Include[0].Attrs(); !slices.Equal(got, []string{"steam_group:103582791429521412"}) {
		t.Errorf("steam group attr %v", got)
	}
	want := []string{"access.providers", "service_tokens.bot.header", "apps.web.login_methods", "policies.gamers", "policies.mods"}
	if got := c.IdentityFeatures(); !slices.Equal(got, want) {
		t.Errorf("IdentityFeatures = %v, want %v", got, want)
	}
	// A config without the new features has none.
	c2, _ := Parse([]byte(accessBase))
	if f := c2.IdentityFeatures(); len(f) != 0 {
		t.Errorf("accessBase features %v", f)
	}
}

// Policy versions hash the policy's JSON: the new selector fields must not
// change it for existing policies (or everyone would be signed out).
func TestSelectorJSONUnchanged(t *testing.T) {
	b, _ := json.Marshal(Selector{Email: StringList{"a@b.c"}})
	const want = `{"Everyone":false,"Email":["a@b.c"],"EmailDomain":null,"Group":null,"IP":null,"Country":null,"ServiceToken":null,"LoginMethod":null}`
	if string(b) != want {
		t.Fatalf("selector JSON changed:\n got %s\nwant %s", b, want)
	}
}

func TestIdentityConfigErrors(t *testing.T) {
	for _, tc := range []struct{ name, from, to, want string }{
		{"unknown provider", "    discord: {", "    github: {", "unknown provider"},
		{"missing provider for method", "login_methods: [discord, steam, email]", "login_methods: [discord, steam, google]", "needs access.providers.google"},
		{"unknown method", "login_methods: [discord, steam, email]", "login_methods: [myspace]", "unknown login method"},
		{"bad role", "100000000000000001/200000000000000002", "admins", "<server ID>/<role ID>"},
		{"bad login_method", "login_method: discord", "login_method: facebook", "unknown login method"},
		{"steam selectors need api key", "steam: { api_key: secret://steam, session: 1h }", "steam: { session: 1h }", "needs access.providers.steam.api_key"},
		{"steam has no client", "steam: { api_key: secret://steam, session: 1h }", "steam: { client_id: x, client_secret: secret://x }", "no client_id"},
		{"plain secret", "client_secret: secret://discord", "client_secret: hunter2", "secret:// reference"},
		{"reserved header", "header: X-Bot-Token", "header: Cookie", "reserved"},
		{"forwarded header", "header: X-Bot-Token", "header: X-Forwarded-For", "reserved"},
		{"header and client id", "header: X-Bot-Token,", "header: X-Bot-Token, client_id: bot.access.id,", "must be empty for a header token"},
		{"identity selector in service_auth", "require: [{ ip: 10.0.0.0/8 }]", "require: [{ discord_user: \"100000000000000001\" }]", "can only use everyone, ip and service_token"},
		{"providers with portal_url", "  portal_host: auth.example.com\n", "  portal_url: https://auth.ingressd.test/a/x\n  session_key: secret://a\n  jwt_key: secret://b\n", "configured on the portal"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if !strings.Contains(idpBase, tc.from) {
				t.Fatalf("fixture lacks %q", tc.from)
			}
			c, err := Parse([]byte(strings.Replace(idpBase, tc.from, tc.to, 1)))
			if err == nil {
				err = c.Validate()
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestNormalizeSteamGroup(t *testing.T) {
	for in, want := range map[string]string{"4": "103582791429521412", "103582791429521412": "103582791429521412", "0": "", "abc": "", "99999999999999999999": ""} {
		got, _ := NormalizeSteamGroup(in)
		if got != want {
			t.Errorf("%s: %q, want %q", in, got, want)
		}
	}
}

const passkeyBase = `
version: 1
edge: { acme: { ca: internal } }
email: { provider: log, log: { path: /tmp/mail.log } }
access:
  portal_url: https://auth.ingressd.test/a/org_x
  session_key: secret://a
  jwt_key: secret://b
  revoked_before: { "passkey:old-phone": 2026-11-01T00:00:00Z }
policies:
  family:
    action: allow
    include: [{ passkey: [jack-iphone, mum-ipad] }]
apps:
  plex:
    hosts: [plex.example.com]
    origin: http://192.0.2.10:32400
    access: [family]
    login_methods: [passkey]
`

func TestPasskeyConfig(t *testing.T) {
	c, err := Parse([]byte(passkeyBase))
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	if got := c.Policies["family"].Include[0].Attrs(); !slices.Equal(got, []string{"passkey:jack-iphone", "passkey:mum-ipad"}) {
		t.Errorf("passkey attrs %v", got)
	}
	if got, want := c.PasskeyFeatures(), []string{"access.revoked_before", "apps.plex.login_methods", "policies.family"}; !slices.Equal(got, want) {
		t.Errorf("PasskeyFeatures = %v, want %v", got, want)
	}
	if !slices.Contains(c.IdentityFeatures(), "policies.family") {
		t.Errorf("IdentityFeatures %v lacks the passkey policy", c.IdentityFeatures())
	}
	if f, _ := Parse([]byte(idpBase)); len(f.PasskeyFeatures()) != 0 {
		t.Errorf("idpBase passkey features %v", f.PasskeyFeatures())
	}

	for _, tc := range []struct{ name, from, to, want string }{
		{"bad name", "jack-iphone", "Jack iPhone", "a passkey name"},
		{"own portal method", "  portal_url: https://auth.ingressd.test/a/org_x\n  session_key: secret://a\n  jwt_key: secret://b\n",
			"  portal_host: auth.example.com\n", "central portal"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if !strings.Contains(passkeyBase, tc.from) {
				t.Fatalf("fixture lacks %q", tc.from)
			}
			c, err := Parse([]byte(strings.Replace(passkeyBase, tc.from, tc.to, 1)))
			if err == nil {
				err = c.Validate()
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestMicrosoftRoleWarnings(t *testing.T) {
	const tid = "11111111-2222-3333-4444-555555555555"
	cfg := func(tenant, require string) *Config {
		c, err := Parse([]byte(`
version: 1
edge: { acme: { ca: internal } }
email: { provider: log, log: { path: /tmp/mail.log } }
access:
  portal_host: auth.example.com
  providers:
    microsoft: { client_id: "c", client_secret: secret://ms` + tenant + ` }
policies:
  admins: { action: allow, include: [{ microsoft_role: [Admin] }]` + require + ` }
apps:
  web: { hosts: [web.example.com], origin: "http://192.0.2.10:80", access: [admins], login_methods: [microsoft] }
`))
		if err != nil {
			t.Fatal(err)
		}
		if err := c.Validate(); err != nil {
			t.Fatal(err)
		}
		return c
	}
	warned := func(c *Config) bool {
		return slices.ContainsFunc(c.AccessWarnings(), func(w string) bool { return strings.Contains(w, "microsoft_role") })
	}
	if !warned(cfg("", "")) {
		t.Error("no warning without a tenant")
	}
	if warned(cfg(", tenant: "+tid, "")) {
		t.Error("warning with a single-tenant provider")
	}
	if warned(cfg("", ", require: [{ microsoft_tenant: ["+tid+"] }]")) {
		t.Error("warning with a required tenant")
	}
}

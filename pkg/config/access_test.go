// SPDX-License-Identifier: Apache-2.0

package config

import (
	"strings"
	"testing"
	"time"
)

const accessBase = `
version: 1
edge:
  acme: { ca: internal }
email: { provider: log, log: { path: /tmp/mail.log } }
access: { portal_host: auth.example.com }
groups:
  family: { emails: [alice@gmail.com] }
service_tokens:
  hook: { client_id: hook.access, client_secret: secret://hook, expires: 2027-11-01 }
policies:
  family: { action: allow, include: [{ group: family }] }
  hook: { action: service_auth, include: [{ service_token: hook }] }
  public: { action: bypass, include: [{ everyone: true }] }
apps:
  web:
    hosts: [web.example.com]
    origin: http://192.0.2.10:80
    access: [family]
    paths: [{ match: /hook/*, access: [hook] }]
`

func TestAccessDefaults(t *testing.T) {
	c, err := Parse([]byte(accessBase))
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	o := c.Access.OTP
	if o.Length != 6 || o.TTL != Duration(5*time.Minute) || o.Attempts != 5 || o.ResendCooldown != Duration(time.Minute) ||
		o.PerEmail.Codes != 5 || o.PerIP.Codes != 20 || o.Lockout != Duration(15*time.Minute) {
		t.Errorf("otp defaults %+v", o)
	}
	if c.Policies["family"].Session != Duration(24*time.Hour) || c.Access.Session != Duration(24*time.Hour) {
		t.Error("session defaults")
	}
	if c.ServiceTokens["hook"].Expires.Format("2006-01-02") != "2027-11-01" {
		t.Error("expires not parsed")
	}
	if !c.Apps["web"].Protected() {
		t.Error("app not protected")
	}
	// Configs without access still parse and validate.
	c2, _ := Parse([]byte("version: 1\nedge: { acme: { ca: internal } }\n"))
	if err := c2.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestValidateAccess(t *testing.T) {
	for _, tc := range []struct {
		name, from, to, want string
	}{
		{"portal host required", "access: { portal_host: auth.example.com }", "", "access.portal_host: is required"},
		{"email provider required", "email: { provider: log, log: { path: /tmp/mail.log } }", "", "email.provider: is required"},
		{"unknown policy", "access: [family]", "access: [nope]", `apps.web.access[0]: unknown policy "nope"`},
		{"unknown group", "{ group: family }", "{ group: nope }", `unknown group "nope"`},
		{"unknown token", "{ service_token: hook }", "{ service_token: nope }", `unknown service token "nope"`},
		{"bad action", "action: allow", "action: maybe", "policies.family.action"},
		{"two kinds", "{ group: family }", "{ group: family, email: [a@b.com] }", "exactly one of"},
		{"bypass with identity", "{ everyone: true }", "{ email: [a@b.com] }", "bypass policies can only use"},
		{"token in allow", "{ group: family }", "{ service_token: hook }", "only allowed in service_auth"},
		{"bad ip", "{ everyone: true }", "{ ip: [nope] }", "invalid IP or CIDR"},
		{"bad country", "include: [{ group: family }]", "include: [{ group: family }], exclude: [{ country: [gb] }]", "ISO 3166"},
		{"bad path", "match: /hook/*", "match: /a*b", "exact path or a prefix"},
		{"encoded path", "match: /hook/*", "match: /ho%6Bk/*", "plain path"},
		{"path params", "match: /hook/*", "match: /hook;x/*", "plain path"},
		{"otp length", "portal_host: auth.example.com", "portal_host: auth.example.com, otp: { length: 9 }", "access.otp.length"},
		{"otp ttl", "portal_host: auth.example.com", "portal_host: auth.example.com, otp: { ttl: 30m }", "access.otp.ttl"},
		{"secret ref", "client_secret: secret://hook", "client_secret: plain", "must be a secret:// reference"},
		{"uppercase email", "[alice@gmail.com]", "[Alice@gmail.com]", "invalid email"},
		{"portal clashes with app", "portal_host: auth.example.com", "portal_host: web.example.com", "already served by app"},
		{"smtp host", "email: { provider: log, log: { path: /tmp/mail.log } }", "email: { provider: smtp, from: a@b.com }", "email.smtp.host"},
		{"bad color", "portal_host: auth.example.com", "portal_host: auth.example.com, branding: { color: red }", "access.branding.color"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			src := strings.Replace(accessBase, tc.from, tc.to, 1)
			if src == accessBase {
				t.Fatalf("replacement %q not found", tc.from)
			}
			c, err := Parse([]byte(src))
			if err != nil {
				t.Fatal(err)
			}
			err = c.Validate()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Validate = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestAccessWarnings(t *testing.T) {
	c, err := Parse([]byte(accessBase))
	if err != nil {
		t.Fatal(err)
	}
	if w := c.AccessWarnings(); len(w) != 0 {
		t.Fatalf("protected-by-default app warned: %v", w)
	}
	c, err = Parse([]byte(strings.Replace(accessBase, "    access: [family]\n", "", 1)))
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	w := c.AccessWarnings()
	if len(w) != 1 || !strings.HasPrefix(w[0], "apps.web.access: empty, so only /hook/* is protected") {
		t.Fatalf("warnings = %q", w)
	}
}

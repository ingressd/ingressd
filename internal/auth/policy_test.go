// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"net/netip"
	"testing"

	"github.com/ingressd/ingressd/pkg/config"
)

const policyConfig = `
version: 1
edge:
  acme: { ca: internal }
email: { provider: log, log: { path: /tmp/mail.log } }
access: { portal_host: auth.example.com }
groups:
  family: { emails: [alice@gmail.com, bob@outlook.com] }
  work: { email_domains: [example.com] }
service_tokens:
  hook: { client_id: hook.access, client_secret: secret://hook }
policies:
  blocked:
    action: deny
    include: [{ email: [eve@example.com] }, { country: [RU] }]
  family-or-work:
    action: allow
    include: [{ group: family }, { group: work }]
    exclude: [{ country: [CN] }, { ip: [203.0.113.0/24] }]
    session: 12h
  admins:
    action: allow
    include: [{ email: [me@example.org] }]
    require: [{ ip: [81.2.3.0/24, 2001:db8::/32] }]
  domain-and-net:
    action: allow
    include: [{ email_domain: [corp.test] }]
    require: [{ ip: [10.0.0.0/8] }, { country: [GB, IE] }]
  public:
    action: bypass
    include: [{ everyone: true }]
  hook:
    action: service_auth
    include: [{ service_token: hook }]
apps:
  web:
    hosts: [web.example.com, "*.lab.example.com"]
    origin: http://192.0.2.10:80
    access: [blocked, family-or-work, admins, domain-and-net]
    paths:
      - { match: /public/*, access: [public] }
      - { match: /hook, access: [hook] }
  open:
    hosts: [open.example.com]
    origin: http://192.0.2.11:80
`

func testConfig(t testing.TB) *config.Config {
	t.Helper()
	cfg, err := config.Parse([]byte(policyConfig))
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	return cfg
}

func TestEvaluate(t *testing.T) {
	cfg := testConfig(t)
	e := NewEngine(cfg)
	list := cfg.Apps["web"].Access
	ip := netip.MustParseAddr
	for _, tc := range []struct {
		name   string
		id     Identity
		action string
		policy string
	}{
		{"family member", Identity{Email: "alice@gmail.com"}, "allow", "family-or-work"},
		{"case-insensitive email", Identity{Email: "Alice@Gmail.com"}, "allow", "family-or-work"},
		{"work domain", Identity{Email: "sam@example.com"}, "allow", "family-or-work"},
		{"subdomain is not the domain", Identity{Email: "sam@evil.example.com"}, "deny", ""},
		{"deny wins by order", Identity{Email: "eve@example.com"}, "deny", "blocked"},
		{"denied country", Identity{Email: "alice@gmail.com", Country: "RU"}, "deny", "blocked"},
		{"excluded country falls through", Identity{Email: "alice@gmail.com", Country: "CN"}, "deny", ""},
		{"excluded ip", Identity{Email: "alice@gmail.com", IP: ip("203.0.113.9")}, "deny", ""},
		{"admin from allowed net", Identity{Email: "me@example.org", IP: ip("81.2.3.4")}, "allow", "admins"},
		{"admin from v6 net", Identity{Email: "me@example.org", IP: ip("2001:db8::1")}, "allow", "admins"},
		{"admin from mapped v4", Identity{Email: "me@example.org", IP: ip("::ffff:81.2.3.4")}, "allow", "admins"},
		{"admin elsewhere", Identity{Email: "me@example.org", IP: ip("8.8.8.8")}, "deny", ""},
		{"admin without ip", Identity{Email: "me@example.org"}, "deny", ""},
		{"require all", Identity{Email: "x@corp.test", IP: ip("10.1.1.1"), Country: "GB"}, "allow", "domain-and-net"},
		{"require all, missing country", Identity{Email: "x@corp.test", IP: ip("10.1.1.1")}, "deny", ""},
		{"stranger", Identity{Email: "nobody@nowhere.test"}, "deny", ""},
		{"no identity", Identity{}, "deny", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := e.Evaluate(list, tc.id)
			if d.Action != tc.action || d.Policy != tc.policy {
				t.Fatalf("Evaluate = %+v, want %s/%s", d, tc.action, tc.policy)
			}
		})
	}
	if d := e.Evaluate(list, Identity{Email: "alice@gmail.com"}); d.Session.Hours() != 12 {
		t.Errorf("session = %s, want 12h", d.Session)
	}
	if d := e.Evaluate([]string{"public"}, Identity{}); d.Action != "bypass" {
		t.Errorf("bypass = %+v", d)
	}
	if d := e.Evaluate([]string{"hook"}, Identity{ServiceToken: "hook"}); d.Action != "service_auth" {
		t.Errorf("service_auth = %+v", d)
	}
	if d := e.Evaluate([]string{"missing", "public"}, Identity{}); d.Policy != "public" {
		t.Errorf("unknown policy not skipped: %+v", d)
	}
}

func TestListFor(t *testing.T) {
	app := testConfig(t).Apps["web"]
	for path, want := range map[string]string{
		"/":               "blocked",
		"/public/a":       "public",
		"/public/":        "public",
		"/public":         "blocked",
		"/hook":           "hook",
		"/hook/x":         "blocked",
		"/public/../x":    "blocked",
		"//public/a":      "public",
		"/x/../public/a/": "public",
	} {
		if got := ListFor(app, path)[0]; got != want {
			t.Errorf("ListFor(%q) = %s, want %s", path, got, want)
		}
	}
}

func TestCouldAllow(t *testing.T) {
	cfg := testConfig(t)
	e := NewEngine(cfg)
	list := cfg.Apps["web"].Access
	for email, want := range map[string]bool{
		"alice@gmail.com":     true,
		"me@example.org":      true, // ip requirement assumed satisfiable
		"x@corp.test":         true,
		"nobody@nowhere.test": false,
	} {
		if got := e.CouldAllow(list, email); got != want {
			t.Errorf("CouldAllow(%s) = %v", email, got)
		}
	}
}

func TestVersionChangesWithGroups(t *testing.T) {
	cfg := testConfig(t)
	v1 := NewEngine(cfg).Version("family-or-work")
	if v1 == "" || v1 != NewEngine(cfg).Version("family-or-work") {
		t.Fatal("version not stable")
	}
	g := cfg.Groups["family"]
	g.Emails = append(g.Emails, "carol@gmail.com")
	cfg.Groups["family"] = g
	if NewEngine(cfg).Version("family-or-work") == v1 {
		t.Fatal("version unchanged after group edit")
	}
	if NewEngine(cfg).Version("admins") != NewEngine(testConfig(t)).Version("admins") {
		t.Fatal("unrelated policy version changed")
	}
}

func TestHostAllowed(t *testing.T) {
	hosts := []string{"web.example.com", "*.lab.example.com"}
	for host, want := range map[string]bool{
		"web.example.com":       true,
		"WEB.example.com":       true,
		"a.lab.example.com":     true,
		"a.b.lab.example.com":   false,
		"lab.example.com":       false,
		"evil.com":              false,
		"web.example.com.evil":  false,
		"xweb.example.com":      false,
		"web.example.com.":      true,
		".lab.example.com":      false,
		"evil.com/.example.com": false,
	} {
		if got := HostAllowed(hosts, host); got != want {
			t.Errorf("HostAllowed(%q) = %v", host, got)
		}
	}
}

func TestNormalizeEmail(t *testing.T) {
	for in, want := range map[string]string{
		" Alice@Gmail.COM ": "alice@gmail.com",
		"a@b":               "",
		"@b.com":            "",
		"a@":                "",
		"a b@c.com":         "",
		"a@b.com\r\nBcc: x": "",
		"<a@b.com>":         "",
	} {
		got, err := NormalizeEmail(in)
		if (err != nil) != (want == "") || got != want && want != "" {
			t.Errorf("NormalizeEmail(%q) = %q, %v", in, got, err)
		}
	}
}

// FuzzEvaluate checks the engine never panics and that its invariants hold
// for arbitrary identities: a match is always from the list, and allow
// decisions come only from allow policies.
func FuzzEvaluate(f *testing.F) {
	cfg := testConfig(f)
	e := NewEngine(cfg)
	list := cfg.Apps["web"].Access
	f.Add("alice@gmail.com", "81.2.3.4", "GB", "")
	f.Add("", "", "", "hook")
	f.Add("ME@EXAMPLE.ORG", "::ffff:81.2.3.4", "cn", "x")
	f.Fuzz(func(t *testing.T, email, ip, country, token string) {
		id := Identity{Email: email, Country: country, ServiceToken: token}
		id.IP, _ = netip.ParseAddr(ip)
		d := e.Evaluate(list, id)
		if d.Policy == "" {
			if d.Action != config.ActionDeny {
				t.Fatalf("no match but action %s", d.Action)
			}
			return
		}
		p, ok := e.Policy(d.Policy)
		if !ok || p.Action != d.Action {
			t.Fatalf("decision %+v does not match policy %+v", d, p)
		}
		if d.Action == config.ActionAllow && email == "" {
			t.Fatalf("allowed without an email: %+v", d)
		}
		_ = e.CouldAllow(list, email)
		_ = PathMatch("/a/*", email)
	})
}

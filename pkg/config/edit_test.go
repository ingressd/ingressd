// SPDX-License-Identifier: Apache-2.0

package config

import (
	"strings"
	"testing"
)

const commented = `# ingressd config
version: 1

edge:
  public_ipv4: 203.0.113.10           # this VM
  acme: { ca: internal }

tunnels:
  home:
    site: router                       # UDM Pro
    listen_port: 51820
    transit: 10.100.1.0/24
    subnets: [192.168.0.0/24]          # home LAN

apps: {}
#  example:
#    hosts: [x.example.com]
`

func TestEditPreservesFormatting(t *testing.T) {
	d, err := ParseDocument([]byte(commented))
	if err != nil {
		t.Fatal(err)
	}
	app, err := ParseJSONNode([]byte(`{"hosts": ["web.example.com"], "origin": "http://192.168.0.17:8080", "tunnel": "home"}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Set(app, "apps", "web"); err != nil {
		t.Fatal(err)
	}
	sub, _ := ParseJSONNode([]byte(`["192.168.0.0/24", "192.168.1.0/24"]`))
	if err := d.Set(sub, "tunnels", "home", "subnets"); err != nil {
		t.Fatal(err)
	}
	out, err := d.Render([]byte(commented))
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	for _, want := range []string{
		"public_ipv4: 203.0.113.10           # this VM", // untouched line kept byte-for-byte
		"site: router                       # UDM Pro",
		"# ingressd config",
		"192.168.1.0/24",
		"web:",
		"origin: http://192.168.0.17:8080",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q in:\n%s", want, s)
		}
	}
	if strings.Contains(s, "apps: {") {
		t.Errorf("apps should become a block mapping:\n%s", s)
	}
	c, err := Parse(out)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	if got := c.Apps["web"].Origin; got != "http://192.168.0.17:8080" {
		t.Errorf("origin = %q", got)
	}
	if len(c.Tunnels["home"].Subnets) != 2 {
		t.Errorf("subnets = %v", c.Tunnels["home"].Subnets)
	}
}

func TestEditMergeKeepsEntryComments(t *testing.T) {
	src := "apps:\n  web:\n    hosts: [web.example.com]  # public name\n    origin: http://10.0.0.1:80   # old box\n"
	d, _ := ParseDocument([]byte(src))
	n, _ := ParseJSONNode([]byte(`{"hosts": ["web.example.com"], "origin": "http://10.0.0.2:80"}`))
	if err := d.Set(n, "apps", "web"); err != nil {
		t.Fatal(err)
	}
	out, _ := d.Render([]byte(src))
	if !strings.Contains(string(out), "hosts: [web.example.com]  # public name") {
		t.Errorf("unchanged line reformatted:\n%s", out)
	}
	if !strings.Contains(string(out), "10.0.0.2:80") || !strings.Contains(string(out), "# old box") {
		t.Errorf("changed line lost value or comment:\n%s", out)
	}
	if !d.Delete("apps", "web") || d.Delete("apps", "web") {
		t.Error("Delete should report existence")
	}
}

func TestValidateAdmins(t *testing.T) {
	for name, tc := range map[string]struct {
		admins string
		want   string
	}{
		"none is bootstrap": {"", ""},
		"ok":                {"admins:\n  - { name: A, email: a@example.com, role: owner }\n  - { name: B, email: b@example.com, role: operator, scope: { l4: [fivem] } }", ""},
		"no owner":          {"admins:\n  - { name: A, email: a@example.com, role: admin }", "at least one owner"},
		"dup email":         {"admins:\n  - { name: A, email: a@example.com, role: owner }\n  - { name: B, email: A@example.com, role: viewer }", "duplicate admin"},
		"bad role":          {"admins:\n  - { name: A, email: a@example.com, role: god }", "admins[0].role"},
		"bad email":         {"admins:\n  - { name: A, email: nope, role: owner }", "admins[0].email"},
		"scoped owner":      {"admins:\n  - { name: A, email: a@example.com, role: owner, scope: { apps: [web] } }", "owners cannot be scoped"},
	} {
		t.Run(name, func(t *testing.T) {
			c := mustParse(t, baseYAML+tc.admins)
			err := c.Validate()
			if tc.want == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want %q, got %v", tc.want, err)
			}
		})
	}
}

func TestJSONSchema(t *testing.T) {
	s := JSONSchema()
	props := s["properties"].(map[string]any)
	for _, k := range []string{"edge", "tunnels", "apps", "admins"} {
		if _, ok := props[k]; !ok {
			t.Errorf("schema lacks %s", k)
		}
	}
}

func TestMergeKeepsKeyOrder(t *testing.T) {
	src := "tunnels:\n  home:\n    site: router\n    listen_port: 51820\n    transit: 10.100.1.0/24\n"
	d, _ := ParseDocument([]byte(src))
	n, _ := ParseJSONNode([]byte(`{"transit": "10.100.1.0/24", "listen_port": 51820, "site": "router"}`))
	if err := d.Set(n, "tunnels", "home"); err != nil {
		t.Fatal(err)
	}
	if out, _ := d.Render([]byte(src)); string(out) != src {
		t.Errorf("no-op edit changed the file:\n%s", out)
	}
}

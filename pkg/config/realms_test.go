// SPDX-License-Identifier: Apache-2.0

package config

import (
	"strings"
	"testing"
)

// realmsYAML is two tenants merged onto one node the way a panel writes it:
// identical LAN subnets, origin IPs and app names apart from the namespace.
const realmsYAML = `
version: 1
edge:
  public_ipv4: 203.0.113.10
  acme: { ca: internal }
security: { tunnel_input: restricted }
realms:
  tq7k2m:
    access: { portal_url: https://auth.ingressd.com/a/tq7k2m, session_key: secret://tq7k2m_session, jwt_key: secret://tq7k2m_jwt }
    shape: { rate_mbit: 50 }
  tb4x9p:
    access: { portal_url: https://auth.ingressd.com/a/tb4x9p, session_key: secret://tb4x9p_session, jwt_key: secret://tb4x9p_jwt }
tunnels:
  tq7k2m01: { realm: tq7k2m, table: 1201, site: connector, listen_port: 51820, transit: 10.100.1.0/30, subnets: [192.168.1.0/24], virtual_prefix: 10.0.4.0/24 }
  tb4x9p01: { realm: tb4x9p, table: 1202, site: connector, listen_port: 51821, transit: 10.100.2.0/30, subnets: [192.168.1.0/24], virtual_prefix: 10.0.5.0/24 }
groups:
  tq7k2m.family: { realm: tq7k2m, emails: [alice@example.com] }
  tb4x9p.family: { realm: tb4x9p, emails: [bob@example.org] }
service_tokens:
  tq7k2m.ci: { realm: tq7k2m, client_id: ci-client-1, client_secret: secret://tq7k2m_ci }
policies:
  tq7k2m.family: { realm: tq7k2m, action: allow, include: [{ group: tq7k2m.family }] }
  tq7k2m.ci: { realm: tq7k2m, action: service_auth, include: [{ service_token: tq7k2m.ci }] }
  tb4x9p.family: { realm: tb4x9p, action: allow, include: [{ group: tb4x9p.family }] }
pools:
  tb4x9p.web: { realm: tb4x9p, origins: [{ name: a, tunnel: tb4x9p01, address: http://192.168.1.10:5000 }] }
apps:
  tq7k2m.nas: { realm: tq7k2m, hosts: [nas.alice.example], tunnel: tq7k2m01, origin: http://192.168.1.10:5000, access: [tq7k2m.family], paths: [{ match: /ci/*, access: [tq7k2m.ci] }] }
  tq7k2m.lab: { realm: tq7k2m, hosts: ["*.lab.alice.example"], tunnel: tq7k2m01, origin: http://192.168.1.11:80 }
  tb4x9p.nas: { realm: tb4x9p, hosts: [nas.bob.example], pool: tb4x9p.web, access: [tb4x9p.family] }
`

func TestRealmsValid(t *testing.T) {
	c := mustParse(t, realmsYAML)
	if err := c.Validate(); err != nil {
		t.Fatalf("realms config is invalid:\n%v", err)
	}
	if c.Access != nil {
		t.Error("top-level access was defaulted into a realms config")
	}
	if a := c.AppAccess("tb4x9p.nas"); a == nil || a.PortalURL != "https://auth.ingressd.com/a/tb4x9p" || a.OTP.Length != 6 {
		t.Errorf("AppAccess(tb4x9p.nas) = %+v, want the realm's defaulted block", a)
	}
	if got := c.TunnelTable("tb4x9p01"); got != 1202 {
		t.Errorf("TunnelTable = %d, want 1202", got)
	}
	if got := c.MachineHostFallback(); got != "203.0.113.10" {
		t.Errorf("MachineHostFallback = %q, want the public IPv4", got)
	}
	if got := mustParse(t, baseYAML).MachineHostFallback(); got != "" {
		t.Errorf("MachineHostFallback without realms = %q", got)
	}
}

func TestRealmsValidation(t *testing.T) {
	app := func(c *Config, name string, f func(*App)) {
		a := c.Apps[name]
		f(&a)
		c.Apps[name] = a
	}
	tunnel := func(c *Config, name string, f func(*Tunnel)) {
		tn := c.Tunnels[name]
		f(&tn)
		c.Tunnels[name] = tn
	}
	realmAccess := func(c *Config, name string, f func(*Access)) { f(c.Realms[name].Access) }

	tests := []struct {
		name   string
		mutate func(*Config)
		want   string // "" = valid
	}{
		{"object without realm", func(c *Config) { app(c, "tq7k2m.lab", func(a *App) { a.Realm = "" }) },
			"apps.tq7k2m.lab.realm: is required when realms are configured"},
		{"unknown realm", func(c *Config) {
			g := c.Groups["tb4x9p.family"]
			g.Realm = "nope"
			c.Groups["tb4x9p.family"] = g
		}, `groups.tb4x9p.family.realm: unknown realm "nope"`},
		{"service token without realm", func(c *Config) {
			tk := c.ServiceTokens["tq7k2m.ci"]
			tk.Realm = ""
			c.ServiceTokens["tq7k2m.ci"] = tk
		}, "service_tokens.tq7k2m.ci.realm: is required"},
		{"realm tunnel without virtual prefix", func(c *Config) {
			tunnel(c, "tq7k2m01", func(tn *Tunnel) { tn.VirtualPrefix, tn.Table, tn.Subnets = "", 0, []string{"192.168.7.0/24"} })
		}, "tunnels.tq7k2m01.virtual_prefix: is required in a realm"},
		{"realm tunnel without table", func(c *Config) { tunnel(c, "tq7k2m01", func(tn *Tunnel) { tn.Table = 0 }) },
			"tunnels.tq7k2m01.table: is required in a realm"},
		{"origin through another realm's tunnel", func(c *Config) { app(c, "tq7k2m.nas", func(a *App) { a.Tunnel = "tb4x9p01" }) },
			`apps.tq7k2m.nas.tunnel: tunnel "tb4x9p01" belongs to realm "tb4x9p", not "tq7k2m"`},
		{"pool of another realm", func(c *Config) {
			app(c, "tq7k2m.nas", func(a *App) { a.Origin, a.Tunnel, a.Pool = "", "", "tb4x9p.web" })
		},
			`apps.tq7k2m.nas.pool: pool "tb4x9p.web" belongs to realm "tb4x9p"`},
		{"policy of another realm", func(c *Config) { app(c, "tq7k2m.nas", func(a *App) { a.Access = []string{"tb4x9p.family"} }) },
			`apps.tq7k2m.nas.access[0]: policy "tb4x9p.family" belongs to realm "tb4x9p"`},
		{"path policy of another realm", func(c *Config) { app(c, "tq7k2m.nas", func(a *App) { a.Paths[0].Access = []string{"tb4x9p.family"} }) },
			`apps.tq7k2m.nas.paths[0].access[0]: policy "tb4x9p.family"`},
		{"group of another realm", func(c *Config) {
			p := c.Policies["tq7k2m.family"]
			p.Include = []Selector{{Group: StringList{"tb4x9p.family"}}}
			c.Policies["tq7k2m.family"] = p
		}, `policies.tq7k2m.family.include[0].group[0]: group "tb4x9p.family" belongs to realm "tb4x9p"`},
		{"service token of another realm", func(c *Config) {
			tk := c.ServiceTokens["tq7k2m.ci"]
			tk.Realm = "tb4x9p"
			c.ServiceTokens["tq7k2m.ci"] = tk
		}, `policies.tq7k2m.ci.include[0].service_token[0]: service token "tq7k2m.ci" belongs to realm "tb4x9p"`},
		{"pool origin through another realm's tunnel", func(c *Config) { c.Pools["tb4x9p.web"].Origins[0].Tunnel = "tq7k2m01" },
			`pools.tb4x9p.web.origins[0].tunnel: tunnel "tq7k2m01" belongs to realm "tq7k2m"`},
		{"pool origin without tunnel", func(c *Config) { c.Pools["tb4x9p.web"].Origins[0].Tunnel = "" },
			"pools.tb4x9p.web.origins[0].tunnel: is required in a realm"},
		{"hostname origin", func(c *Config) { app(c, "tq7k2m.nas", func(a *App) { a.Origin = "http://nas.lan:5000" }) },
			`apps.tq7k2m.nas.origin: must use an IP address in a realm (hostname origins are resolved by the node), got "nas.lan"`},
		{"metadata origin", func(c *Config) { app(c, "tq7k2m.nas", func(a *App) { a.Origin = "http://169.254.169.254" }) },
			"apps.tq7k2m.nas.origin: 169.254.169.254 is not inside the subnets of tunnel"},
		{"another realm's virtual address", func(c *Config) { app(c, "tq7k2m.nas", func(a *App) { a.Origin = "http://10.0.5.10:5000" }) },
			"apps.tq7k2m.nas.origin: 10.0.5.10 is not inside the subnets of tunnel"},
		{"public origin", func(c *Config) {
			app(c, "tq7k2m.nas", func(a *App) { a.Origin, a.Tunnel = "https://203.0.113.80", "" })
		},
			"apps.tq7k2m.nas.tunnel: is required in a realm"},
		{"exact host in two realms", func(c *Config) { app(c, "tb4x9p.nas", func(a *App) { a.Hosts = []string{"nas.alice.example"} }) },
			`is already served by app "tb4x9p.nas"`},
		{"wildcard covers another realm's host", func(c *Config) { app(c, "tb4x9p.nas", func(a *App) { a.Hosts = []string{"x.lab.alice.example"} }) },
			`apps.tq7k2m.lab.hosts[0]: "*.lab.alice.example" overlaps "x.lab.alice.example" of app "tb4x9p.nas" in realm "tb4x9p"`},
		{"wildcard covers another realm's deeper host", func(c *Config) { app(c, "tb4x9p.nas", func(a *App) { a.Hosts = []string{"a.b.lab.alice.example"} }) },
			`overlaps "a.b.lab.alice.example"`},
		{"wildcard covers another realm's wildcard", func(c *Config) { app(c, "tb4x9p.nas", func(a *App) { a.Hosts = []string{"*.x.lab.alice.example"} }) },
			`"*.lab.alice.example" overlaps "*.x.lab.alice.example"`},
		{"wildcard over own realm's host", func(c *Config) { app(c, "tq7k2m.nas", func(a *App) { a.Hosts = []string{"nas.lab.alice.example"} }) }, ""},
		{"wildcard apex in another realm", func(c *Config) { app(c, "tb4x9p.nas", func(a *App) { a.Hosts = []string{"lab.alice.example"} }) }, ""},
		{"l4 refused", func(c *Config) {
			c.L4 = L4Services{"ssh": {Listen: []string{"2222/tcp"}, Target: L4Target{Tunnel: "tq7k2m01", Address: "192.168.1.10", Port: 22}}}
		}, "l4: is not supported alongside realms"},
		{"admin hostname refused", func(c *Config) { c.Edge.Admin.Hostname = "edge.example.com" },
			"edge.admin.hostname: is not allowed alongside realms"},
		{"admin exposure refused", func(c *Config) { c.Edge.Admin.Exposure = ExposureTunnelOnly },
			"edge.admin.exposure: is not allowed alongside realms"},
		{"admin allowlist refused", func(c *Config) { c.Edge.Admin.IPAllowlist = []string{"192.0.2.0/24"} },
			"edge.admin.ip_allowlist: is not allowed alongside realms"},
		{"top-level access refused", func(c *Config) { c.Access = &Access{}; defaultAccess(c.Access) },
			"access: is not allowed alongside realms"},
		{"open tunnel input refused", func(c *Config) { c.Security.TunnelInput = "" },
			"security.tunnel_input: must be restricted alongside realms"},
		{"top-level smartdns refused", func(c *Config) { c.SmartDNS = &SmartDNS{} },
			"smartdns: is not allowed alongside realms (it would serve every realm's tunnels); use realms.<name>.smartdns"},
		{"protected app needs realm access", func(c *Config) { c.Realms["tq7k2m"] = Realm{} },
			`realms.tq7k2m.access: is required: app "tq7k2m.nas" of this realm has access policies`},
		{"realm without protected apps needs no access", func(c *Config) {
			c.Realms["tb4x9p"] = Realm{}
			app(c, "tb4x9p.nas", func(a *App) { a.Access = nil })
		}, ""},
		{"realm portal on the node refused", func(c *Config) {
			realmAccess(c, "tq7k2m", func(a *Access) { a.PortalURL, a.PortalHost = "", "auth.alice.example" })
		},
			"realms.tq7k2m.access.portal_host: a realm cannot run a portal on the node"},
		{"realm portal_url required", func(c *Config) { realmAccess(c, "tq7k2m", func(a *Access) { a.PortalURL = "" }) },
			"realms.tq7k2m.access.portal_url: is required"},
		{"realm keys required", func(c *Config) { realmAccess(c, "tq7k2m", func(a *Access) { a.SessionKey, a.JWTKey = "", "" }) },
			"realms.tq7k2m.access.portal_url: needs org-wide keys (session_key and jwt_key)"},
		{"realm keys are secret references", func(c *Config) { realmAccess(c, "tq7k2m", func(a *Access) { a.JWTKey = "plain" }) },
			"realms.tq7k2m.access.jwt_key: must be a secret:// reference"},
		{"realm access validated like top-level", func(c *Config) { realmAccess(c, "tb4x9p", func(a *Access) { a.OTP.Length = 3 }) },
			"realms.tb4x9p.access.otp.length: must be 4-8"},
		{"realm revocations validated", func(c *Config) {
			realmAccess(c, "tb4x9p", func(a *Access) { a.RevokedBefore = map[string]Instant{"Bob": {}} })
		}, "realms.tb4x9p.access.revoked_before.Bob"},
		{"realm providers refused", func(c *Config) {
			realmAccess(c, "tb4x9p", func(a *Access) {
				a.Providers = map[string]IdentityProvider{"google": {ClientID: "x", ClientSecret: "secret://g"}}
			})
		}, "realms.tb4x9p.access.providers: sign-in providers of a node on an external portal"},
		{"realm shape", func(c *Config) { c.Realms["tq7k2m"].Shape.RateMbit = 0 },
			"realms.tq7k2m.shape.rate_mbit: must be 1-100000, got 0"},
		{"realm name", func(c *Config) { c.Realms["Bad_Realm"] = Realm{} }, "realms.Bad_Realm: name must match"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := mustParse(t, realmsYAML)
			tt.mutate(c)
			err := c.Validate()
			switch {
			case tt.want == "" && err != nil:
				t.Fatalf("unexpected error:\n%v", err)
			case tt.want != "" && err == nil:
				t.Fatalf("expected error containing %q", tt.want)
			case tt.want != "" && !strings.Contains(err.Error(), tt.want):
				t.Fatalf("error does not contain %q:\n%v", tt.want, err)
			}
		})
	}
}

func TestRealmFieldWithoutRealms(t *testing.T) {
	c := mustParse(t, baseYAML)
	tn := c.Tunnels["home"]
	tn.Realm = "tq7k2m"
	c.Tunnels["home"] = tn
	err := c.Validate()
	if err == nil || !strings.Contains(err.Error(), `tunnels.home.realm: unknown realm "tq7k2m" (no realms are configured)`) {
		t.Fatalf("Validate = %v", err)
	}
}

func TestQualifiedNames(t *testing.T) {
	for _, name := range []string{"tq7k2m.nas", "nas", "a-b.c-d"} {
		if !qualifiedNameRe.MatchString(name) {
			t.Errorf("%q rejected", name)
		}
	}
	for _, name := range []string{".nas", "tq.", "a..b", "a.b.c", "A.b", "a_b.c"} {
		if qualifiedNameRe.MatchString(name) {
			t.Errorf("%q accepted", name)
		}
	}
	c := mustParse(t, strings.ReplaceAll(strings.ReplaceAll(baseYAML, "web:", "tq7k2m.web:"), "pool: web", "pool: tq7k2m.web"))
	if err := c.Validate(); err != nil {
		t.Fatalf("dotted app and pool names: %v", err)
	}
}

func TestTunnelTables(t *testing.T) {
	two := func(tbl, officeTbl int, officeVP string) *Config {
		c := mustParse(t, baseYAML)
		home := c.Tunnels["home"]
		home.VirtualPrefix, home.Table = "10.201.0.0/24", tbl
		c.Tunnels["home"] = home
		o := office("192.168.0.0/24", officeVP)
		o.Table, o.Keepalive = officeTbl, 25
		c.Tunnels["office"] = o
		return c
	}
	tests := []struct {
		name string
		c    *Config
		want string
	}{
		{"explicit tables", two(1500, 1400, "10.202.0.0/24"), ""},
		{"one explicit, one implicit", two(1500, 0, "10.202.0.0/24"), ""},
		{"no virtual prefix", func() *Config {
			c := mustParse(t, baseYAML)
			h := c.Tunnels["home"]
			h.Table = 1200
			c.Tunnels["home"] = h
			return c
		}(), "tunnels.home.table: only applies to remapped tunnels"},
		{"below range", two(999, 0, "10.202.0.0/24"), "tunnels.home.table: must be 1000-1899 (tables from 1900 belong to Smart DNS VPN exits), got 999"},
		{"VPN range", two(1900, 0, "10.202.0.0/24"), "tunnels.home.table: must be 1000-1899"},
		{"duplicate", two(1500, 1500, "10.202.0.0/24"), `tunnels.office.table: table 1500 is already used by tunnel "home"`},
		// office sorts second: its implicit table is 1001.
		{"implicit collision", two(1001, 0, "10.202.0.0/24"), `tunnels.home.table: table 1001 is the implicit table of tunnel "office"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.c.Validate()
			switch {
			case tt.want == "" && err != nil:
				t.Fatalf("unexpected error:\n%v", err)
			case tt.want != "" && (err == nil || !strings.Contains(err.Error(), tt.want)):
				t.Fatalf("error %v does not contain %q", err, tt.want)
			}
		})
	}
	c := two(1500, 0, "10.202.0.0/24")
	if got := c.TunnelTable("home"); got != 1500 {
		t.Errorf("explicit TunnelTable = %d", got)
	}
	if got := c.TunnelTable("office"); got != 1001 {
		t.Errorf("implicit TunnelTable = %d, want TunnelTableMin + index", got)
	}
}

func TestTunnelInput(t *testing.T) {
	c := mustParse(t, baseYAML+"security: { tunnel_input: restricted }\n")
	if err := c.Validate(); err != nil || !c.TunnelInputRestricted() {
		t.Fatalf("restricted: %v", err)
	}
	for _, tt := range []struct{ yaml, want string }{
		{"security: { tunnel_input: closed }\n", `security.tunnel_input: must be open or restricted, got "closed"`},
		{"security: { tunnel_input: restricted }\n", "security.tunnel_input: restricted needs the managed firewall"},
	} {
		y := baseYAML + tt.yaml
		if strings.Contains(tt.want, "managed firewall") {
			y = strings.Replace(y, "  acme: { ca: internal }", "  acme: { ca: internal }\n  manage_firewall: false", 1)
		}
		err := mustParse(t, y).Validate()
		if err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("Validate = %v, want %q", err, tt.want)
		}
	}
	c = mustParse(t, baseYAML)
	a := c.Apps["web"]
	a.Security = &Security{TunnelInput: TunnelInputRestricted, EdgeOutputDeny: []string{"10.0.0.0/8"}}
	c.Apps["web"] = a
	err := c.Validate()
	if err == nil || !strings.Contains(err.Error(), "apps.web.security.tunnel_input: is node-wide") ||
		!strings.Contains(err.Error(), "apps.web.security.edge_output_deny: is node-wide") {
		t.Errorf("app-level tunnel_input and edge_output_deny: %v", err)
	}
}

func TestEdgeOutputDeny(t *testing.T) {
	ok := mustParse(t, baseYAML+"security: { tunnel_input: restricted, edge_output_deny: [10.1.0.0/16, \"fd12:3456::/48\"] }\n")
	if err := ok.Validate(); err != nil {
		t.Fatalf("valid denylist: %v", err)
	}
	for _, tt := range []struct{ yaml, want string }{
		{"security: { tunnel_input: restricted, edge_output_deny: [10.1.0.0] }\n", `security.edge_output_deny[0]: invalid CIDR "10.1.0.0"`},
		{"security: { edge_output_deny: [10.1.0.0/16] }\n", "security.edge_output_deny: only applies with tunnel_input: restricted"},
	} {
		if err := mustParse(t, baseYAML+tt.yaml).Validate(); err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("Validate = %v, want %q", err, tt.want)
		}
	}
}

func TestRealmIFBName(t *testing.T) {
	if got := RealmIFBName("tq7k2m"); got != "ifb-tq7k2m" {
		t.Errorf("RealmIFBName(tq7k2m) = %q", got)
	}
	long := RealmIFBName("averylongrealmname")
	if len(long) > 15 || !strings.HasPrefix(long, "ifb-aver-") || long == RealmIFBName("averylongrealmnamf") {
		t.Errorf("RealmIFBName(long) = %q", long)
	}
	if got := RealmIFBName("abcdefghijk"); got != "ifb-abcdefghijk" || len(got) != 15 {
		t.Errorf("11-character realm: %q", got)
	}
}

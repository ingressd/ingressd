// SPDX-License-Identifier: Apache-2.0

package config

import (
	"slices"
	"strings"
	"testing"
)

// realmsSmartDNSYAML gives both realms of realmsYAML their own Smart DNS:
// the same domain routed to different exits, and a VPN exit each on this
// node with explicit tables.
var realmsSmartDNSYAML = strings.NewReplacer(
	"    shape: { rate_mbit: 50 }\n", `    shape: { rate_mbit: 50 }
    smartdns:
      enabled: true
      exits:
        tq7k2m.nl: { node: nod_nl, country: NL }
        tq7k2m.gb: { node: self, country: GB, vpn: "secret://tq7k2m-vpn-gb", table: 1901 }
      services:
        tq7k2m.streamtv: { domains: [stream.example], exits: [tq7k2m.nl] }
`,
	"jwt_key: secret://tb4x9p_jwt }\n", `jwt_key: secret://tb4x9p_jwt }
    smartdns:
      enabled: true
      exits:
        tb4x9p.gb: { node: self, country: GB, vpn: "secret://tb4x9p-vpn-gb", table: 1900 }
      services:
        tb4x9p.tv: { domains: [stream.example], exit: tb4x9p.gb }
`,
	"security: { tunnel_input: restricted }\n", `security: { tunnel_input: restricted }
mesh:
  address: 10.255.0.1/16
  peers:
    nod_nl: { public_key: "eEvqkSJVw/7cGUEcJXmeHiNFDLBGOz8GpScshecvNHU=", endpoint: "nl.example.net:51900", address: 10.255.0.2/32 }
`).Replace(realmsYAML)

func TestRealmSmartDNSValid(t *testing.T) {
	c := mustParse(t, realmsSmartDNSYAML)
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	scopes := c.SmartDNSScopes()
	if len(scopes) != 2 || scopes[0].Realm != "tb4x9p" || scopes[1].Realm != "tq7k2m" {
		t.Fatalf("scopes %+v", scopes)
	}
	if l := scopes[0].Listen; len(l) != 1 || l[0].String() != "10.100.2.1" {
		t.Errorf("tb4x9p listens on %v, want its own transit address only", l)
	}
	if l := scopes[1].Listen; len(l) != 1 || l[0].String() != "10.100.1.1" {
		t.Errorf("tq7k2m listens on %v, want its own transit address only", l)
	}
	if l := c.SmartDNSListen(); len(l) != 2 {
		t.Errorf("SmartDNSListen = %v", l)
	}
	if e, realm, ok := c.SmartDNSExit("tq7k2m.nl"); !ok || realm != "tq7k2m" || e.Node != "nod_nl" {
		t.Errorf("SmartDNSExit(tq7k2m.nl) = %+v %q %v", e, realm, ok)
	}
	if got := c.VPNExits(); !slices.Equal(got, []string{"tb4x9p.gb", "tq7k2m.gb"}) {
		t.Errorf("VPNExits = %v", got)
	}
	if tb, _ := c.VPNTable("tb4x9p.gb"); tb != 1900 {
		t.Errorf("VPNTable(tb4x9p.gb) = %d", tb)
	}
	if tb, _ := c.VPNTable("tq7k2m.gb"); tb != 1901 {
		t.Errorf("VPNTable(tq7k2m.gb) = %d", tb)
	}
	if c.Realms["tb4x9p"].SmartDNS.Services["tb4x9p.tv"].Exits[0] != "tb4x9p.gb" || len(c.Realms["tq7k2m"].SmartDNS.Upstream) != 2 {
		t.Error("realm Smart DNS blocks were not defaulted")
	}
}

func TestRealmSmartDNSValidation(t *testing.T) {
	for _, tc := range []struct{ name, old, new, want string }{
		{"exit outside the namespace", "tq7k2m.nl: { node", "nl: { node", `realms.tq7k2m.smartdns.exits.nl: name must be tq7k2m.<name> in realm "tq7k2m"`},
		{"exit in another realm's namespace", "tq7k2m.nl: { node", "tb4x9p.nl: { node", `realms.tq7k2m.smartdns.exits.tb4x9p.nl: name must be tq7k2m.<name>`},
		{"service outside the namespace", "tb4x9p.tv: {", "tv: {", `realms.tb4x9p.smartdns.services.tv: name must be tb4x9p.<name>`},
		{"service using another realm's exit", "exit: tb4x9p.gb }", "exit: tq7k2m.gb }", `realms.tb4x9p.smartdns.services.tb4x9p.tv.exits[0]: unknown exit "tq7k2m.gb"`},
		{"listen on another realm's tunnel", "    smartdns:\n      enabled: true\n      exits:\n        tb4x9p", "    smartdns:\n      enabled: true\n      listen: [10.100.1.1]\n      exits:\n        tb4x9p", `realms.tb4x9p.smartdns.listen[0]: 10.100.1.1 is not the transit address of a tunnel of realm "tb4x9p"`},
		{"listen on a LAN address", "    smartdns:\n      enabled: true\n      exits:\n        tb4x9p", "    smartdns:\n      enabled: true\n      listen: [192.168.1.5]\n      exits:\n        tb4x9p", `realms.tb4x9p.smartdns.listen[0]: 192.168.1.5 is not the transit address`},
		{"VPN exit without a table", `vpn: "secret://tb4x9p-vpn-gb", table: 1900 }`, `vpn: "secret://tb4x9p-vpn-gb" }`, "realms.tb4x9p.smartdns.exits.tb4x9p.gb.table: is required for a VPN exit in a realm"},
		{"table used twice", "table: 1901 }", "table: 1900 }", `realms.tq7k2m.smartdns.exits.tq7k2m.gb.table: table 1900 is already used by exit "tb4x9p.gb"`},
		{"table out of range", "table: 1901 }", "table: 1201 }", "realms.tq7k2m.smartdns.exits.tq7k2m.gb.table: must be 1900-1999"},
		{"table on a remote exit", "{ node: nod_nl, country: NL }", "{ node: nod_nl, country: NL, table: 1950 }", "realms.tq7k2m.smartdns.exits.tq7k2m.nl.table: only applies to a VPN exit"},
	} {
		y := strings.Replace(realmsSmartDNSYAML, tc.old, tc.new, 1)
		if y == realmsSmartDNSYAML {
			t.Fatalf("%s: replacement did not apply", tc.name)
		}
		err := mustParse(t, y).Validate()
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: got %v, want %q", tc.name, err, tc.want)
		}
	}
}

func TestVPNTablesExplicitAndImplicit(t *testing.T) {
	y := strings.Replace(sdBase, `here: { node: self, country: GB, vpn: "secret://proton-gb" }`,
		`here: { node: self, country: GB, vpn: "secret://proton-gb" }
    later: { node: self, country: GB, vpn: "secret://vpn-b", table: 1950 }`, 1)
	c := mustParse(t, y)
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	if tb, _ := c.VPNTable("here"); tb != 1900 {
		t.Errorf("implicit table %d", tb)
	}
	if tb, _ := c.VPNTable("later"); tb != 1950 {
		t.Errorf("explicit table %d", tb)
	}
	c = mustParse(t, strings.Replace(y, "table: 1950", "table: 1900", 1))
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), `smartdns.exits.here: its implicit table 1900 is the explicit table of exit "later"`) {
		t.Errorf("implicit/explicit clash: %v", err)
	}
}

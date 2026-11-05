// SPDX-License-Identifier: Apache-2.0

package config

import (
	"strings"
	"testing"
)

const sdBase = `version: 1
tunnels:
  home: { site: router, listen_port: 51820, transit: 10.100.1.0/24, subnets: [192.168.0.0/24] }
mesh:
  address: 10.255.0.1/16
  peers:
    nod_nl: { public_key: "eEvqkSJVw/7cGUEcJXmeHiNFDLBGOz8GpScshecvNHU=", endpoint: "nl.example.net:51900", address: 10.255.0.2/32 }
smartdns:
  enabled: true
  exits:
    nl: { node: nod_nl, country: nl }
    here: { node: self, country: GB, vpn: "secret://proton-gb" }
  services:
    streamtv: { domains: [Stream.example., streamtv.example], exit: nl, catalog: streamtv }
  checks:
    - { domains: [stream.example], host: tv.stream.example, path: /v1/location, field: countryCode, cache_buster: cb }
`

func TestSmartDNSValid(t *testing.T) {
	c, err := Parse([]byte(sdBase))
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	if c.Mesh.ListenPort != DefaultMeshPort {
		t.Errorf("mesh port default %d", c.Mesh.ListenPort)
	}
	if strings.Join(c.SmartDNS.Upstream, ",") != "1.1.1.1,9.9.9.9" {
		t.Errorf("upstream default %v", c.SmartDNS.Upstream)
	}
	if c.SmartDNS.Services["streamtv"].Domains[0] != "stream.example" || c.SmartDNS.Exits["nl"].Country != "NL" {
		t.Errorf("not normalized: %+v", c.SmartDNS)
	}
	if l := c.SmartDNSListen(); len(l) != 1 || l[0].String() != "10.100.1.1" {
		t.Errorf("default listen %v", l)
	}
	if v := c.VPNExits(); len(v) != 1 || v[0] != "here" {
		t.Errorf("vpn exits %v", v)
	}
}

func TestSmartDNSValidation(t *testing.T) {
	for _, tc := range []struct {
		name, old, new, want string
	}{
		{"unknown exit", "exit: nl, catalog", "exit: de, catalog", `smartdns.services.streamtv.exits[0]: unknown exit "de"`},
		{"unknown peer", "node: nod_nl, country", "node: nod_de, country", `smartdns.exits.nl.node: unknown mesh peer "nod_de"`},
		{"bad country", "country: nl", "country: Netherlands", "smartdns.exits.nl.country"},
		{"bad vpn ref", `vpn: "secret://proton-gb"`, `vpn: "/etc/proton.conf"`, "smartdns.exits.here.vpn: must be a secret reference"},
		{"bad domain", "streamtv.example]", "\"*.streamtv.example\"]", `smartdns.services.streamtv.domains[1]: invalid domain`},
		{"public listen", "enabled: true", "enabled: true\n  listen: [203.0.113.1]", "smartdns.listen[0]: 203.0.113.1 is neither"},
		{"mesh listen", "enabled: true", "enabled: true\n  listen: [10.255.0.1]", "smartdns.listen[0]: 10.255.0.1 is the mesh address"},
		{"bad upstream", "enabled: true", "enabled: true\n  upstream: [dns.google]", "smartdns.upstream[0]"},
		{"dup domain", "    streamtv: {", "    video: { domains: [stream.example], exit: nl }\n    streamtv: {", `"stream.example" is already routed by service "streamtv"`},
		{"mesh overlaps transit", "address: 10.255.0.1/16", "address: 10.100.1.5/16", "mesh.address: mesh network 10.100.0.0/16 overlaps tunnels.home.transit"},
		{"mesh overlaps subnet", "address: 10.255.0.1/16\n", "address: 192.168.0.200/24\n", "overlaps tunnels.home route"},
		{"mesh public", "address: 10.255.0.1/16", "address: 8.8.8.1/24", "mesh.address: must be a private address"},
		{"peer outside mesh", "address: 10.255.0.2/32", "address: 10.254.0.2/32", "mesh.peers.nod_nl.address: 10.254.0.2 is outside"},
		{"peer is self", "address: 10.255.0.2/32", "address: 10.255.0.1/32", "this node's own mesh address"},
		{"peer /24", "address: 10.255.0.2/32", "address: 10.255.0.0/24", "mesh.peers.nod_nl.address: must be an IPv4 address (/32)"},
		{"peer key", `public_key: "eEvqkSJVw/7cGUEcJXmeHiNFDLBGOz8GpScshecvNHU="`, `public_key: "nope"`, "mesh.peers.nod_nl.public_key"},
		{"peer endpoint", `endpoint: "nl.example.net:51900"`, `endpoint: "nl.example.net"`, "mesh.peers.nod_nl.endpoint"},
		{"mesh port clash", "address: 10.255.0.1/16\n", "address: 10.255.0.1/16\n  listen_port: 51820\n", `mesh.listen_port: port 51820 is already used by tunnel "home"`},
		{"tunnel clashes with vpn interface", "  home: {", "  x-here: { site: connector, listen_port: 51822, transit: 10.100.9.0/24 }\n  home: {", `interface "ix-x-here" is already used by tunnel "x-here"`},
		{"tunnel named mesh", "  home: {", "  mesh: {", "tunnels.mesh: the name mesh is reserved"},
		{"check path", "path: /v1/location", "path: \"/v1 HTTP/1.1\r\nX: y\"", "smartdns.checks[0].path: must start with /"},
		{"check field", "field: countryCode", "field: \"a\\\"b\"", "smartdns.checks[0].field"},
		{"check host", "host: tv.stream.example", "host: \"a b\"", "smartdns.checks[0].host"},
		{"check domains", "domains: [stream.example], host", "domains: [], host", "smartdns.checks[0].domains: at least one domain"},
	} {
		y := strings.Replace(sdBase, tc.old, tc.new, 1)
		if y == sdBase {
			t.Fatalf("%s: replacement did not apply", tc.name)
		}
		c, err := Parse([]byte(y))
		if err != nil {
			t.Fatalf("%s: parse: %v", tc.name, err)
		}
		err = c.Validate()
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: got %v, want %q", tc.name, err, tc.want)
		}
	}
}

func TestSmartDNSExitWithoutMesh(t *testing.T) {
	y := `version: 1
smartdns:
  enabled: true
  listen: [192.168.1.5]
  exits:
    nl: { node: nod_nl, country: NL }
  services:
    streamtv: { domains: [stream.example], exit: nl }
`
	c, err := Parse([]byte(y))
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "needs the mesh section") {
		t.Errorf("got %v", err)
	}
}

func TestVPNInterfaceNameLongExits(t *testing.T) {
	if got := VPNInterfaceName("proton-gb"); got != "ix-x-proton-gb" {
		t.Errorf("short name: %q", got)
	}
	seen := map[string]string{}
	for _, n := range []string{"proton-gb-2", "proton-gb-3", "mullvad-se-gothenburg", "a-b-c-d-e-f-g", "airvpn-de"} {
		got := VPNInterfaceName(n)
		if len(got) > 15 || !strings.HasPrefix(got, "ix-x-") {
			t.Errorf("%s: %q is not a valid interface name", n, got)
		}
		if o, dup := seen[got]; dup {
			t.Errorf("%s and %s share %q", n, o, got)
		}
		seen[got] = n
		if VPNInterfaceName(n) != got {
			t.Errorf("%s: not stable", n)
		}
	}
	// Several long-named VPN exits on one node validate.
	y := strings.Replace(sdBase, "    here: { node: self, country: GB, vpn: \"secret://proton-gb\" }",
		"    here: { node: self, country: GB, vpn: \"secret://proton-gb\" }\n    proton-netherlands-1: { node: self, country: NL, vpn: \"secret://vpn-a\" }\n    proton-netherlands-2: { node: self, country: NL, vpn: \"secret://vpn-b\" }", 1)
	c, err := Parse([]byte(y))
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	if v := c.VPNExits(); len(v) != 3 {
		t.Errorf("vpn exits %v", v)
	}
}

func TestSmartDNSServiceExits(t *testing.T) {
	const exits = "    nl: { node: nod_nl, country: nl }\n"
	more := exits + "    nl2: { node: nod_nl, country: NL }\n    nl3: { node: self, country: NL }\n    nl4: { node: self, country: NL }\n    nl5: { node: self, country: NL }\n"
	for _, tc := range []struct {
		name, svc, want string
	}{
		{"list", "exits: [nl, nl2, nl3]", ""},
		{"both", "exit: nl, exits: [nl2]", "smartdns.services.streamtv: set exit or exits, not both"},
		{"both same", "exit: nl, exits: [nl]", "set exit or exits, not both"},
		{"none", "enabled: true", "smartdns.services.streamtv.exits: is required"},
		{"empty list", "exits: []", "smartdns.services.streamtv.exits: is required"},
		{"too many", "exits: [nl, nl2, nl3, nl4, nl5]", "smartdns.services.streamtv.exits: at most 4 exits, got 5"},
		{"duplicate", "exits: [nl, nl2, nl]", `smartdns.services.streamtv.exits[2]: duplicate exit "nl"`},
		{"unknown", "exits: [nl, de]", `smartdns.services.streamtv.exits[1]: unknown exit "de"`},
		{"country", "exits: [nl, here]", "smartdns.services.streamtv.exits[1]: country GB differs from NL of exits[0]"},
	} {
		y := strings.Replace(sdBase, exits, more, 1)
		y = strings.Replace(y, "exit: nl, catalog", tc.svc+", catalog", 1)
		c, err := Parse([]byte(y))
		if err != nil {
			t.Fatalf("%s: parse: %v", tc.name, err)
		}
		err = c.Validate()
		switch {
		case tc.want == "" && err != nil:
			t.Errorf("%s: %v", tc.name, err)
		case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
			t.Errorf("%s: got %v, want %q", tc.name, err, tc.want)
		}
	}
}

func TestSmartDNSExitNormalised(t *testing.T) {
	c, err := Parse([]byte(sdBase))
	if err != nil {
		t.Fatal(err)
	}
	svc := c.SmartDNS.Services["streamtv"]
	if svc.Exit != "" || strings.Join(svc.Exits, ",") != "nl" {
		t.Errorf("exit not normalised into exits: %+v", svc)
	}
	// A config built in code without loading still has a usable list.
	if l := (SmartDNSService{Exit: "nl"}).ExitList(); strings.Join(l, ",") != "nl" {
		t.Errorf("ExitList %v", l)
	}
	if d := c.SmartDNS.FailbackDuration(); d != DefaultSmartDNSFailbackAfter {
		t.Errorf("failback default %s", d)
	}
}

func TestSmartDNSFailbackBounds(t *testing.T) {
	for _, tc := range []struct {
		val  string
		want string
	}{
		{"0s", ""},
		{"30s", ""},
		{"1h", ""},
		{"61m", "smartdns.failback_after: must be between 0s and 1h0m0s"},
		{"-1s", "smartdns.failback_after"},
	} {
		y := strings.Replace(sdBase, "  enabled: true\n", "  enabled: true\n  failback_after: "+tc.val+"\n", 1)
		c, err := Parse([]byte(y))
		if err != nil {
			t.Fatalf("%s: parse: %v", tc.val, err)
		}
		err = c.Validate()
		switch {
		case tc.want == "" && err != nil:
			t.Errorf("%s: %v", tc.val, err)
		case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
			t.Errorf("%s: got %v, want %q", tc.val, err, tc.want)
		}
		if tc.want == "" && c.SmartDNS.FailbackAfter == nil {
			t.Errorf("%s: not parsed", tc.val)
		}
	}
	y := strings.Replace(sdBase, "  enabled: true\n", "  enabled: true\n  failback_after: 0s\n", 1)
	c, _ := Parse([]byte(y))
	if d := c.SmartDNS.FailbackDuration(); d != 0 {
		t.Errorf("failback 0s gave %s", d)
	}
}

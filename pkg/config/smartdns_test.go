// SPDX-License-Identifier: Apache-2.0

package config

import (
	"strings"
	"testing"
)

const sdBase = `version: 1
tunnels:
  home: { site: connector, listen_port: 51820, transit: 10.100.1.0/30, smartdns: '{"site":"home"}' }
  udm: { site: router, listen_port: 51821, transit: 10.100.2.0/30, subnets: [192.168.0.0/24] }
smartdns:
  exit:
    country: nl
    sites: [home]
    checks:
      - { domains: [stream.example], host: tv.stream.example, path: /v1/location, field: countryCode, cache_buster: cb }
`

func TestSmartDNSNodeExitValid(t *testing.T) {
	c, err := Parse([]byte(sdBase))
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	e := c.SmartDNS.Exit
	if e.Country != "NL" || strings.Join(e.Upstream, ",") != "1.1.1.1,9.9.9.9" {
		t.Errorf("not normalised: %+v", e)
	}
	if s := c.SmartDNSExitSites(); len(s) != 1 || s[0] != "home" {
		t.Errorf("exit sites %v", s)
	}
	if a, _ := c.TransitSiteAddr("home"); a.String() != "10.100.1.2" {
		t.Errorf("site transit address %v", a)
	}
}

func TestSmartDNSNodeExitValidation(t *testing.T) {
	for _, tc := range []struct{ name, old, new, want string }{
		{"bad country", "country: nl", "country: Netherlands", "smartdns.exit.country"},
		{"unknown site", "sites: [home]", "sites: [away]", `smartdns.exit.sites[0]: unknown tunnel "away"`},
		{"router site", "sites: [home]", "sites: [udm]", `smartdns.exit.sites[0]: tunnel "udm" is not a connector site`},
		{"bad check path", "path: /v1/location", `path: "/v1 x"`, "smartdns.exit.checks[0].path"},
		{"blob on router", "subnets: [192.168.0.0/24] }", `subnets: [192.168.0.0/24], smartdns: '{}' }`, "tunnels.udm.smartdns: only connector sites run Smart DNS"},
		{"blob not json", `smartdns: '{"site":"home"}'`, `smartdns: 'nope'`, "tunnels.home.smartdns: must be a signed Smart DNS config"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			y := strings.Replace(sdBase, tc.old, tc.new, 1)
			if y == sdBase {
				t.Fatalf("replacement %q not found", tc.old)
			}
			c, err := Parse([]byte(y))
			if err != nil {
				t.Fatal(err)
			}
			err = c.Validate()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want %q, got %v", tc.want, err)
			}
		})
	}
}

func validSite() *SmartDNSSite {
	return &SmartDNSSite{
		Listen:        "192.168.1.5",
		FailbackAfter: "2m",
		Services: map[string]SmartDNSSiteService{
			"npo": {Domains: []string{"NPO.nl.", "npostart.nl"}, Exits: []string{"nl-vps", "nl-vpn"}},
		},
		Exits: map[string]SmartDNSSiteExit{
			"nl-vps": {At: ExitAtNode, Node: "nod_ams", Country: "nl"},
			"nl-vpn": {At: ExitAtConnector, Country: "NL", VPN: "-----BEGIN AGE ENCRYPTED FILE-----"},
		},
	}
}

func TestSmartDNSSiteValid(t *testing.T) {
	s := validSite()
	s.Normalize()
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
	if s.Services["npo"].Domains[0] != "npo.nl" || s.Exits["nl-vps"].Country != "NL" || len(s.Upstream) != 2 {
		t.Errorf("not normalised: %+v", s)
	}
	if s.FailbackDuration().String() != "2m0s" || s.ListenAddr().String() != "192.168.1.5" {
		t.Errorf("failback %v listen %v", s.FailbackDuration(), s.ListenAddr())
	}
}

func TestSmartDNSSiteValidation(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(s *SmartDNSSite)
		want string
	}{
		{"public listen", func(s *SmartDNSSite) { s.Listen = "203.0.113.5" }, "listen: 203.0.113.5 is not a private address"},
		{"bad failback", func(s *SmartDNSSite) { s.FailbackAfter = "2h" }, "failback_after"},
		{"unknown exit", func(s *SmartDNSSite) {
			s.Services["npo"] = SmartDNSSiteService{Domains: []string{"npo.nl"}, Exits: []string{"de"}}
		}, `services.npo.exits[0]: unknown exit "de"`},
		{"mixed countries", func(s *SmartDNSSite) {
			e := s.Exits["nl-vpn"]
			e.Country = "DE"
			s.Exits["nl-vpn"] = e
		}, "services.npo.exits[1]: country DE differs from NL"},
		{"vpn on node", func(s *SmartDNSSite) {
			e := s.Exits["nl-vps"]
			e.VPN = "x"
			s.Exits["nl-vps"] = e
		}, "exits.nl-vps.vpn: nodes egress from their own IP"},
		{"connector without vpn", func(s *SmartDNSSite) { s.Exits["nl-vpn"] = SmartDNSSiteExit{At: ExitAtConnector, Country: "NL"} }, "exits.nl-vpn.vpn: is required"},
		{"operator refused", func(s *SmartDNSSite) { s.Exits["nl-vpn"] = SmartDNSSiteExit{At: ExitAtOperator, Country: "NL"} }, "exits.nl-vpn.at: operator exits are not offered"},
		{"two exits on one node", func(s *SmartDNSSite) {
			s.Exits["nl-vpn"] = SmartDNSSiteExit{At: ExitAtNode, Node: "nod_ams", Country: "NL"}
		}, "a node has one exit"},
		{"duplicate domain", func(s *SmartDNSSite) {
			s.Services["npo2"] = SmartDNSSiteService{Domains: []string{"npo.nl"}, Exits: []string{"nl-vpn"}}
		}, `"npo.nl" is already routed by service "npo"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := validSite()
			tc.edit(s)
			s.Normalize()
			err := s.Validate()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want %q, got %v", tc.want, err)
			}
		})
	}
}

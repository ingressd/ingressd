// SPDX-License-Identifier: Apache-2.0

package config

import (
	"slices"
	"testing"
)

func TestTunnelRoutes(t *testing.T) {
	c := mustParse(t, `
version: 1
edge: { acme: { ca: internal } }
tunnels:
  home: { site: router, listen_port: 51820, transit: 10.100.1.0/24 }
  lab:  { site: router, listen_port: 51821, transit: 10.100.2.0/24, subnets: [10.0.5.0/24] }
pools:
  web:
    origins:
      - { name: a, tunnel: home, address: http://192.168.0.17:8080 }
      - { name: b, tunnel: home, address: http://192.168.0.18 }
      - { name: c, tunnel: lab, address: http://10.0.5.9:80 }
apps:
  web: { hosts: [web.example.com], pool: web }
  nas: { hosts: [nas.example.com], origin: "http://192.168.0.17:5000", tunnel: home }
  dns: { hosts: [dns.example.com], origin: "http://pihole.lan:80", tunnel: home }
  lab: { hosts: [lab.example.com], origin: "http://10.0.6.1:80", tunnel: lab }
l4:
  game: { preset: minecraft_java, target: { tunnel: home, address: 192.168.0.40 } }
`)
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	// Published addresses only, deduplicated and sorted; hostnames skipped.
	if got, want := c.TunnelRoutes("home"), []string{"192.168.0.17/32", "192.168.0.18/32", "192.168.0.40/32"}; !slices.Equal(got, want) {
		t.Errorf("home routes = %v, want %v", got, want)
	}
	// Subnets are kept; addresses they cover are not repeated.
	if got, want := c.TunnelRoutes("lab"), []string{"10.0.5.0/24", "10.0.6.1/32"}; !slices.Equal(got, want) {
		t.Errorf("lab routes = %v, want %v", got, want)
	}
	if got := c.TunnelRoutes("missing"); len(got) != 0 {
		t.Errorf("unknown tunnel routes = %v", got)
	}
}

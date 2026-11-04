// SPDX-License-Identifier: Apache-2.0

package config

import (
	"strings"
	"testing"
)

const keyA = "eEvqkSJVw/7cGUEcJXmeHiNFDLBGOz8GpScshecvNHU="
const keyB = "YIY5Ngq/mQ8sj1Zz9wVbeKE8OYbXnClgSIsD6d7Ix2I="

const multiPopYAML = `
version: 1
edge:
  public_ipv4: 203.0.113.10
  acme: { ca: internal }
tunnels:
  home:
    site: connector
    listen_port: 51823
    transit: 100.64.0.4/30
    public_key: "` + keyA + `"
    fallback_ws: true
    siblings:
      - node: nod_b
        endpoint: node-b.example.net:51822
        edge_public_key: "` + keyB + `"
        transit: 100.64.0.8/30
        ws_url: wss://node-b.example.net/.ingressd/tunnel/home
      - node: nod_c
        endpoint: 198.51.100.7:51820
        edge_public_key: "` + keyA + `"
        transit: 100.64.0.0/30
  lab:
    site: router
    vendor: unifi
    listen_port: 51824
    transit: 100.64.0.68/30
smartdns:
  enabled: true
`

func TestMultiPopTransitsValid(t *testing.T) {
	c := mustParse(t, multiPopYAML)
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	s := c.Tunnels["home"].Siblings
	if len(s) != 2 || s[0].Node != "nod_b" || s[0].EdgePublicKey != keyB || s[0].Transit != "100.64.0.8/30" ||
		s[0].WSURL != "wss://node-b.example.net/.ingressd/tunnel/home" || s[1].Endpoint != "198.51.100.7:51820" {
		t.Fatalf("siblings: %+v", s)
	}
	// The Smart DNS resolver listens on each /30's edge address (.1).
	var got []string
	for _, a := range c.SmartDNSListen() {
		got = append(got, a.String())
	}
	if strings.Join(got, ",") != "100.64.0.5,100.64.0.69" {
		t.Errorf("smart DNS listen = %v", got)
	}
}

func TestSiblingValidation(t *testing.T) {
	cases := []struct{ name, from, to, want string }{
		{"bad endpoint", "node-b.example.net:51822", "node-b.example.net", "siblings[0].endpoint"},
		{"bad port", "node-b.example.net:51822", "node-b.example.net:0", "siblings[0].endpoint"},
		{"bad key", `edge_public_key: "` + keyB + `"`, `edge_public_key: "abc"`, "siblings[0].edge_public_key"},
		{"too small", "transit: 100.64.0.8/30", "transit: 100.64.0.8/31", "must be /30 or larger"},
		{"overlaps own", "transit: 100.64.0.8/30", "transit: 100.64.0.4/30", "overlaps tunnels.home"},
		{"overlaps other tunnel", "transit: 100.64.0.8/30", "transit: 100.64.0.68/30", "overlaps tunnels.lab"},
		{"overlaps sibling", "transit: 100.64.0.0/30", "transit: 100.64.0.8/29", "overlaps tunnels.home.siblings[0]"},
		{"host bits", "transit: 100.64.0.8/30", "transit: 100.64.0.9/30", "host bits"},
		{"bad ws", "wss://node-b.example.net/.ingressd/tunnel/home", "https://node-b.example.net/", "ws_url"},
		{"duplicate node", "node: nod_c", "node: nod_b", "listed twice"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			y := strings.Replace(multiPopYAML, tc.from, tc.to, 1)
			if y == multiPopYAML {
				t.Fatal("replacement did not apply")
			}
			err := mustParse(t, y).Validate()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want error containing %q, got %v", tc.want, err)
			}
		})
	}
}

// SPDX-License-Identifier: Apache-2.0

package tunnel

import (
	"strings"
	"testing"

	"github.com/ingressd/ingressd/internal/secrets"
	"github.com/ingressd/ingressd/pkg/config"
)

func TestSiteConfig(t *testing.T) {
	cfg, err := config.Parse([]byte(`
version: 1
edge: { public_ipv4: 203.0.113.10, admin: { hostname: edge.example.com }, acme: { ca: internal } }
tunnels:
  home: { site: router, vendor: unifi, listen_port: 51820, transit: 10.100.1.0/24 }
  lab:  { site: router, listen_port: 51821, transit: 10.100.2.0/24, site_dns: 192.168.1.1 }
`))
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	st := secrets.NewMemory(nil)
	if _, err := EnsureKeys(cfg, st); err != nil {
		t.Fatal(err)
	}
	keys := Keys{Cfg: cfg, Store: st}

	text, err := SiteConfig(cfg, keys, "home", SiteOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"Address = 10.100.1.2/24\n",
		"DNS = 1.1.1.1\n", // UniFi's importer requires a DNS line
		"Endpoint = edge.example.com:51820\n",
		"AllowedIPs = 10.100.1.0/24\n",
		"PersistentKeepalive = 25\n",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("home config missing %q:\n%s", want, text)
		}
	}

	lab, _ := SiteConfig(cfg, keys, "lab", SiteOptions{})
	if !strings.Contains(lab, "DNS = 192.168.1.1\n") {
		t.Errorf("site_dns not used:\n%s", lab)
	}

	// The plain wg format (for `wg setconf`) must not carry wg-quick keys.
	plain, _ := SiteConfig(cfg, keys, "home", SiteOptions{Format: FormatWG})
	for _, bad := range []string{"Address", "DNS", "MTU"} {
		if strings.Contains(plain, bad+" =") {
			t.Errorf("wg format contains %s:\n%s", bad, plain)
		}
	}
}

// A multi-PoP router site gets one config per node: the /30 attachment
// transit (edge .1, site .2) as the only AllowedIPs, the node's endpoint
// and port. Siblings never appear in this node's config.
func TestSiteConfigMultiPopTransit(t *testing.T) {
	cfg, err := config.Parse([]byte(`
version: 1
edge: { public_ipv4: 203.0.113.10, admin: { hostname: node-a.example.net }, acme: { ca: internal } }
tunnels:
  home:
    site: router
    vendor: pfsense
    listen_port: 51823
    transit: 100.64.0.4/30
    siblings:
      - { node: nod_b, endpoint: "node-b.example.net:51822", edge_public_key: "eEvqkSJVw/7cGUEcJXmeHiNFDLBGOz8GpScshecvNHU=", transit: 100.64.0.8/30 }
`))
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	st := secrets.NewMemory(nil)
	if _, err := EnsureKeys(cfg, st); err != nil {
		t.Fatal(err)
	}
	text, err := SiteConfig(cfg, Keys{Cfg: cfg, Store: st}, "home", SiteOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"Address = 100.64.0.6/30\n",
		"Endpoint = node-a.example.net:51823\n",
		"AllowedIPs = 100.64.0.4/30\n",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("config missing %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "100.64.0.8") || strings.Contains(text, "node-b") {
		t.Errorf("sibling leaked into this node's site config:\n%s", text)
	}
}

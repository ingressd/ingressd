// SPDX-License-Identifier: Apache-2.0

package config

import (
	"strings"
	"testing"
	"time"
)

const baseYAML = `
version: 1
edge:
  public_ipv4: 203.0.113.10
  acme: { ca: internal }
tunnels:
  home:
    site: router
    listen_port: 51820
    transit: 10.100.1.0/24
    subnets: [192.168.0.0/24]
pools:
  web:
    origins:
      - { name: a, tunnel: home, address: http://192.168.0.17:8080 }
apps:
  web:
    hosts: [web.example.com]
    pool: web
`

func mustParse(t *testing.T, s string) *Config {
	t.Helper()
	c, err := Parse([]byte(s))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func office(subnet, virtualPrefix string) Tunnel {
	return Tunnel{
		Type:          TunnelWireGuard,
		Site:          SiteConnector,
		ListenPort:    51821,
		Transit:       "10.100.2.0/24",
		Subnets:       []string{subnet},
		VirtualPrefix: virtualPrefix,
	}
}

func TestExampleConfigIsValid(t *testing.T) {
	c, err := Load("../../examples/config.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("example config is invalid:\n%v", err)
	}
}

func TestParseRejectsUnknownFields(t *testing.T) {
	if _, err := Parse([]byte("version: 1\nbogus: true\n")); err == nil {
		t.Fatal("expected error for unknown field")
	}
}

func TestParseRejectsEmpty(t *testing.T) {
	if _, err := Parse(nil); err == nil {
		t.Fatal("expected error for empty config")
	}
}

func TestDefaults(t *testing.T) {
	c := mustParse(t, baseYAML)
	if got := c.Tunnels["home"].Keepalive; got != 25 {
		t.Errorf("keepalive = %d, want 25", got)
	}
	p := c.Pools["web"]
	if p.Steering != "round_robin" || p.Failback != FailbackAuto {
		t.Errorf("pool defaults = %q/%q", p.Steering, p.Failback)
	}
	o := p.Origins[0]
	if o.Weight != 1 || o.Priority != 1 || o.State != OriginActive {
		t.Errorf("origin defaults = %+v", o)
	}
}

func TestHealthDefaults(t *testing.T) {
	c := mustParse(t, strings.Replace(baseYAML, "    origins:", "    health: {}\n    origins:", 1))
	h := c.Pools["web"].Health
	if h.Type != HealthHTTP || h.Path != "/" || time.Duration(h.Interval) != 10*time.Second || h.ExpectStatus[0] != 200 {
		t.Errorf("health defaults = %+v", h)
	}
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(c *Config)
		wantErr string
	}{
		{"base config is valid", func(c *Config) {}, ""},
		{"unknown pool", func(c *Config) {
			a := c.Apps["web"]
			a.Pool = "nope"
			c.Apps["web"] = a
		}, `unknown pool "nope"`},
		{"pool and origin together", func(c *Config) {
			a := c.Apps["web"]
			a.Origin = "http://192.168.0.5"
			c.Apps["web"] = a
		}, "either pool or origin, not both"},
		{"neither pool nor origin", func(c *Config) {
			a := c.Apps["web"]
			a.Pool = ""
			c.Apps["web"] = a
		}, "either pool or origin is required"},
		{"origin shorthand", func(c *Config) {
			c.Apps["blog"] = App{Hosts: []string{"blog.example.com"}, Origin: "http://192.168.0.20:3000", Tunnel: "home"}
		}, ""},
		{"duplicate host", func(c *Config) {
			c.Apps["other"] = App{Hosts: []string{"web.example.com"}, Pool: "web"}
		}, `already served by app "other"`},
		{"wildcard host", func(c *Config) {
			c.Apps["lab"] = App{Hosts: []string{"*.lab.example.com"}, Pool: "web"}
		}, ""},
		{"uppercase host", func(c *Config) {
			c.Apps["web"] = App{Hosts: []string{"Web.Example.com"}, Pool: "web"}
		}, "invalid hostname"},
		{"custom headers", func(c *Config) {
			a := c.Apps["web"]
			a.Headers = &Headers{Request: &HeaderOps{Set: map[string]string{"X-Forwarded-Proto": "https"}, Delete: []string{"X-Debug-*"}},
				Response: &HeaderOps{Set: map[string]string{"Cache-Control": "no-store"}}}
			c.Apps["web"] = a
		}, ""},
		{"header value with a placeholder", func(c *Config) {
			a := c.Apps["web"]
			a.Headers = &Headers{Response: &HeaderOps{Set: map[string]string{"X-Leak": "{file./etc/shadow}"}}}
			c.Apps["web"] = a
		}, "must not contain { or }"},
		{"header value with a newline", func(c *Config) {
			a := c.Apps["web"]
			a.Headers = &Headers{Request: &HeaderOps{Set: map[string]string{"X-A": "a\r\nX-B: b"}}}
			c.Apps["web"] = a
		}, "control characters"},
		{"invalid header name", func(c *Config) {
			a := c.Apps["web"]
			a.Headers = &Headers{Request: &HeaderOps{Set: map[string]string{"{env.SECRET}": "x"}}}
			c.Apps["web"] = a
		}, "invalid header name"},
		{"overlapping subnets without virtual prefix", func(c *Config) {
			c.Tunnels["office"] = office("192.168.0.0/24", "")
		}, "set virtual_prefix on both tunnels"},
		{"overlapping subnets with virtual prefixes", func(c *Config) {
			home := c.Tunnels["home"]
			home.VirtualPrefix = "10.201.0.0/24"
			c.Tunnels["home"] = home
			c.Tunnels["office"] = office("192.168.0.0/24", "10.202.0.0/24")
		}, ""},
		{"virtual prefix size mismatch", func(c *Config) {
			home := c.Tunnels["home"]
			home.VirtualPrefix = "10.201.0.0/16"
			c.Tunnels["home"] = home
		}, "must be the same size"},
		{"virtual prefixes overlap", func(c *Config) {
			home := c.Tunnels["home"]
			home.VirtualPrefix = "10.201.0.0/24"
			c.Tunnels["home"] = home
			c.Tunnels["office"] = office("192.168.0.0/24", "10.201.0.0/24")
		}, "overlaps tunnels.home.virtual_prefix"},
		{"duplicate listen port", func(c *Config) {
			o := office("10.0.1.0/24", "")
			o.ListenPort = 51820
			c.Tunnels["office"] = o
		}, `already used by tunnel "home"`},
		{"transit overlaps subnet", func(c *Config) {
			home := c.Tunnels["home"]
			home.Transit = "192.168.0.0/24"
			c.Tunnels["home"] = home
		}, "overlaps subnet"},
		{"subnet with host bits", func(c *Config) {
			home := c.Tunnels["home"]
			home.Subnets = []string{"192.168.0.1/24"}
			c.Tunnels["home"] = home
		}, "host bits set"},
		{"origin outside tunnel subnets is routed individually", func(c *Config) {
			c.Pools["web"].Origins[0].Address = "http://10.9.9.9:8080"
		}, ""},
		{"origin outside a remapped tunnel's subnet", func(c *Config) {
			home := c.Tunnels["home"]
			home.VirtualPrefix = "10.201.0.0/24"
			c.Tunnels["home"] = home
			c.Pools["web"].Origins[0].Address = "http://10.9.9.9:8080"
		}, "which is remapped"},
		{"tunnel without subnets", func(c *Config) {
			home := c.Tunnels["home"]
			home.Subnets = nil
			c.Tunnels["home"] = home
		}, ""},
		{"same address on two tunnels", func(c *Config) {
			home := c.Tunnels["home"]
			home.Subnets = nil
			c.Tunnels["home"] = home
			o := office("", "")
			o.Subnets = nil
			c.Tunnels["office"] = o
			c.Apps["nas"] = App{Hosts: []string{"nas.example.com"}, Origin: "http://192.168.0.17:5000", Tunnel: "office"}
		}, `reached through both tunnel "home"`},
		{"published address inside a transit network", func(c *Config) {
			c.Pools["web"].Origins[0].Address = "http://10.100.1.9:8080"
		}, "which the edge uses itself"},
		{"published edge address of a router tunnel", func(c *Config) {
			c.Pools["web"].Origins[0].Address = "http://10.100.1.1:8080"
		}, "which the edge uses itself"},
		{"published site address of a connector tunnel", func(c *Config) {
			c.Tunnels["office"] = office("10.1.1.0/24", "")
			c.Apps["nas"] = App{Hosts: []string{"nas.example.com"}, Origin: "http://10.100.2.2:5000", Tunnel: "office"}
		}, "which the edge uses itself"},
		{"IPv6 tunnelled origin", func(c *Config) {
			c.Pools["web"].Origins[0].Address = "http://[fd00::17]:8080"
		}, "must use IPv4"},
		{"unknown tunnel", func(c *Config) {
			c.Pools["web"].Origins[0].Tunnel = "nope"
		}, `unknown tunnel "nope"`},
		{"direct origin", func(c *Config) {
			c.Pools["web"].Origins[0].Tunnel = ""
			c.Pools["web"].Origins[0].Address = "https://198.51.100.7"
		}, ""},
		{"origin with path", func(c *Config) {
			c.Pools["web"].Origins[0].Address = "http://192.168.0.17:8080/app"
		}, "must be http(s)://host[:port]"},
		{"bad steering", func(c *Config) {
			p := c.Pools["web"]
			p.Steering = "fastest"
			c.Pools["web"] = p
		}, "pools.web.steering"},
		{"duplicate origin name", func(c *Config) {
			p := c.Pools["web"]
			p.Origins = append(p.Origins, p.Origins[0])
			c.Pools["web"] = p
		}, `duplicate origin name "a"`},
		{"health timeout not shorter than interval", func(c *Config) {
			p := c.Pools["web"]
			p.Health = &HealthCheck{Type: HealthHTTP, Path: "/", Interval: Duration(time.Second), Timeout: Duration(time.Second), UnhealthyAfter: 1, HealthyAfter: 1}
			c.Pools["web"] = p
		}, "shorter than interval"},
		{"bad admin exposure", func(c *Config) {
			c.Edge.Admin.Exposure = "everyone"
		}, "edge.admin.exposure"},
		{"tunnel name too long", func(c *Config) {
			c.Tunnels["a-very-long-name"] = office("10.0.1.0/24", "")
		}, "at most 12 characters"},
		{"public CA without email", func(c *Config) {
			c.Edge.ACME.CA = "letsencrypt"
		}, ""},
		{"redirect from foreign host", func(c *Config) {
			a := c.Apps["web"]
			a.Redirects = []Redirect{{From: "other.example.com", To: "web.example.com", Code: 301}}
			c.Apps["web"] = a
		}, "must be one of the app's hosts"},
		{"bad max body", func(c *Config) {
			a := c.Apps["web"]
			a.Proxy = &Proxy{MaxBody: "lots"}
			c.Apps["web"] = a
		}, "invalid size"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := mustParse(t, baseYAML)
			tt.mutate(c)
			err := c.Validate()
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("want error containing %q, got: %v", tt.wantErr, err)
			}
		})
	}
}

func TestServedHostnamesMustConvert(t *testing.T) {
	base := func(host string) string {
		return `
version: 1
edge: { acme: { ca: internal } }
apps:
  web: { hosts: ["` + host + `"], origin: "http://192.0.2.10:80" }
`
	}
	for host, ok := range map[string]bool{
		"web.example.com":       true,
		"xn--bcher-kva.example": true,
		"*.xn--bcher-kva.test":  true,
		"xn--0.example.com":     false,
		"*.xn--0.example.com":   false,
	} {
		c, err := Parse([]byte(base(host)))
		if err != nil {
			t.Fatal(err)
		}
		if err := c.Validate(); (err == nil) != ok {
			t.Errorf("%s: Validate = %v", host, err)
		}
	}
}

func TestOtherDomainsNeedOnlyLabelSyntax(t *testing.T) {
	if !validHostname("xn--0.example.com", false) {
		t.Error("label syntax check changed")
	}
}

func TestRouterSiteAddressPublished(t *testing.T) {
	c := mustParse(t, baseYAML)
	c.Pools["web"].Origins[0].Address = "http://10.100.1.2:8080"
	if err := c.Validate(); err != nil {
		t.Fatalf("a router's own tunnel address was refused: %v", err)
	}
}

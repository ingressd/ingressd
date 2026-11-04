// SPDX-License-Identifier: Apache-2.0

package config

import (
	"strconv"
	"strings"
	"testing"
	"time"
)

const l4YAML = baseYAML + `
l4:
  fivem:
    preset: fivem
    target: { tunnel: home, address: 192.168.0.40 }
    access: login_to_play
    login_to_play: { policy: friends, portal_host: play.example.com }
  mc:
    preset: minecraft_java
    target: { tunnel: home, address: 192.168.0.41 }
`

func TestL4Defaults(t *testing.T) {
	c := mustParse(t, l4YAML)
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	f := c.L4["fivem"]
	if strings.Join(f.Listen, ",") != "30120/tcp,30120/udp" || f.Mode != L4ModeTransparent || f.Target.Port != 30120 {
		t.Errorf("fivem defaults = %+v", f)
	}
	if f.ProxyProtocol != "none" || f.Engine() != L4EngineNFT {
		t.Errorf("fivem proxy protocol = %q, engine %s", f.ProxyProtocol, f.Engine())
	}
	if time.Duration(f.LoginToPlay.TTL) != DefaultLoginToPlayTTL {
		t.Errorf("ttl = %v", f.LoginToPlay.TTL)
	}
	m := c.L4["mc"]
	if m.Mode != L4ModeProxy || m.ProxyProtocol != "v2" || m.Engine() != L4EngineCaddy || m.Access != L4AccessPublic {
		t.Errorf("minecraft defaults = %+v", m)
	}
	if got := c.LoginToPlayHosts(); len(got) != 1 || got[0] != "play.example.com" {
		t.Errorf("LoginToPlayHosts = %v", got)
	}
}

func TestL4PresetProxyProtocolOnlyInProxyMode(t *testing.T) {
	c := mustParse(t, strings.Replace(l4YAML, "    target: { tunnel: home, address: 192.168.0.41 }",
		"    target: { tunnel: home, address: 192.168.0.41 }\n    mode: transparent", 1))
	if pp := c.L4["mc"].ProxyProtocol; pp != "none" {
		t.Errorf("transparent minecraft got proxy_protocol %q", pp)
	}
}

func TestValidateL4(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(s *L4Service, c *Config)
		wantErr string
	}{
		{"valid", func(s *L4Service, c *Config) {}, ""},
		{"conflicts with HTTPS", func(s *L4Service, c *Config) { s.Listen = []string{"443/tcp"} }, `port 443/tcp is already used by HTTPS`},
		{"conflicts with HTTP/3", func(s *L4Service, c *Config) { s.Listen = []string{"443/udp"} }, `already used by HTTP/3`},
		{"conflicts with ssh", func(s *L4Service, c *Config) { s.Listen = []string{"22/tcp"} }, `already used by edge.ssh_port`},
		{"conflicts with WireGuard", func(s *L4Service, c *Config) { s.Listen = []string{"51820/udp"} }, `already used by tunnel "home"`},
		{"same port number, other protocol is fine", func(s *L4Service, c *Config) { s.Listen = []string{"51820/tcp"} }, ""},
		{"conflicts with other service", func(s *L4Service, c *Config) { s.Listen = []string{"25565/tcp"} }, `already used by l4 service`},
		{"duplicate listen", func(s *L4Service, c *Config) { s.Listen = []string{"1000/udp", "1000/udp"} }, "duplicate port"},
		{"bad listen", func(s *L4Service, c *Config) { s.Listen = []string{"30120"} }, "must be <port>/tcp or <port>/udp"},
		{"address outside remapped tunnel", func(s *L4Service, c *Config) {
			s.Target.Address = "10.9.9.9"
			home := c.Tunnels["home"]
			home.VirtualPrefix = "10.201.0.0/24"
			c.Tunnels["home"] = home
		}, `not inside the subnets of tunnel "home"`},
		{"hostname target", func(s *L4Service, c *Config) { s.Target.Address = "game.lan" }, "must be an IPv4 address"},
		{"unknown tunnel", func(s *L4Service, c *Config) { s.Target.Tunnel = "nope" }, `unknown tunnel "nope"`},
		{"bad mode", func(s *L4Service, c *Config) { s.Mode = "nat" }, "must be proxy or transparent"},
		{"proxy protocol on udp", func(s *L4Service, c *Config) {
			s.Mode, s.ProxyProtocol = L4ModeProxy, "v2"
		}, "only applies to TCP"},
		{"proxy protocol in transparent mode", func(s *L4Service, c *Config) {
			s.Listen, s.ProxyProtocol = []string{"30120/tcp"}, "v1"
		}, "requires mode proxy"},
		{"login_to_play missing", func(s *L4Service, c *Config) { s.LoginToPlay = nil }, "is required with access login_to_play"},
		{"login_to_play on public", func(s *L4Service, c *Config) { s.Access = L4AccessPublic }, "only applies with access login_to_play"},
		{"portal host is an app host", func(s *L4Service, c *Config) { s.LoginToPlay.PortalHost = "web.example.com" }, "already served by an app"},
		{"allowlist entries", func(s *L4Service, c *Config) { s.Allowlist = []string{"198.51.100.7", "10.0.0.0/8"} }, ""},
		{"bad allowlist", func(s *L4Service, c *Config) { s.Allowlist = []string{"10.0.0.1/8"} }, "host bits set"},
		{"allowlist on public", func(s *L4Service, c *Config) {
			s.Access, s.LoginToPlay, s.Allowlist = L4AccessPublic, nil, []string{"10.0.0.0/8"}
		}, "only applies with access allowlist"},
		{"bad rate", func(s *L4Service, c *Config) { s.Limits = &L4Limits{NewConnRate: "30 per second"} }, "invalid rate"},
		{"good limits", func(s *L4Service, c *Config) { s.Limits = &L4Limits{ConnPerIP: 10, NewConnRate: "100/m"} }, ""},
		{"remapped tunnel uses real address", func(s *L4Service, c *Config) {
			home := c.Tunnels["home"]
			home.VirtualPrefix = "10.201.0.0/24"
			c.Tunnels["home"] = home
		}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := mustParse(t, l4YAML)
			s := c.L4["fivem"]
			lp := *s.LoginToPlay
			s.LoginToPlay = &lp
			tt.mutate(&s, c)
			c.L4["fivem"] = s
			err := c.Validate()
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error = %v, want %q", err, tt.wantErr)
			}
		})
	}
}

func TestParseRate(t *testing.T) {
	for in, want := range map[string]string{"30/s": "30/second", "100/m": "100/minute", "5/hour": "5/hour"} {
		n, unit, err := ParseRate(in)
		if err != nil {
			t.Errorf("%s: %v", in, err)
			continue
		}
		if got := strconv.Itoa(n) + "/" + unit; got != want {
			t.Errorf("%s = %s, want %s", in, got, want)
		}
	}
	for _, bad := range []string{"", "30", "0/s", "x/s", "30/d"} {
		if _, _, err := ParseRate(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

// With an external portal (access.portal_url) players sign in there, so
// login_to_play needs no portal host on the node.
func TestL4LoginToPlayExternalPortal(t *testing.T) {
	y := strings.Replace(l4YAML, ", portal_host: play.example.com", "", 1)
	c := mustParse(t, y)
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "login_to_play.portal_host: is required") {
		t.Fatalf("without a portal: %v", err)
	}
	c = mustParse(t, y+"access: { portal_url: https://auth.ingressd.test/a/org_1, session_key: secret://k, jwt_key: secret://j }\n")
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	if got := c.LoginToPlayHosts(); len(got) != 0 {
		t.Errorf("LoginToPlayHosts = %v", got)
	}
}

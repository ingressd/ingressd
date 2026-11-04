// SPDX-License-Identifier: Apache-2.0

package render

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/ingressd/ingressd/internal/secrets"
	"github.com/ingressd/ingressd/pkg/config"
)

func TestMachineHost(t *testing.T) {
	cfg, err := config.Parse([]byte(testConfig))
	if err != nil {
		t.Fatal(err)
	}
	opts := Options{AdminListen: "unix//x", ControlSocket: "/run/ingressd/control.sock"}
	render := func(machine string) map[string]any {
		t.Helper()
		opts.MachineHost = machine
		p, err := Render(cfg, secrets.NewMemory(map[string]string{"cf": "CF-TOKEN"}), fakeKeys{}, opts)
		if err != nil {
			t.Fatal(err)
		}
		var m map[string]any
		_ = json.Unmarshal(p.Caddy, &m)
		return m
	}
	hosts := func(m map[string]any) []string {
		r := m["apps"].(map[string]any)["http"].(map[string]any)["servers"].(map[string]any)["edge"].(map[string]any)["routes"].([]any)[0].(map[string]any)
		var out []string
		for _, h := range r["match"].([]any)[0].(map[string]any)["host"].([]any) {
			out = append(out, h.(string))
		}
		return out
	}
	m := render("203.0.113.10")
	if !slices.Contains(hosts(m), "203.0.113.10") {
		t.Errorf("control hosts %v lack the machine IP", hosts(m))
	}
	pols := m["apps"].(map[string]any)["tls"].(map[string]any)["automation"].(map[string]any)["policies"].([]any)
	first, _ := json.Marshal(pols[0])
	if !strings.Contains(string(first), `"subjects":["203.0.113.10"]`) || !strings.Contains(string(first), `"module":"internal"`) {
		t.Errorf("first TLS policy = %s", first)
	}
	if _, ok := m["apps"].(map[string]any)["pki"]; !ok {
		t.Error("pki app missing")
	}

	m = render("node1.example.net")
	if !slices.Contains(hosts(m), "node1.example.net") {
		t.Errorf("control hosts %v lack the machine hostname", hosts(m))
	}
	pols = m["apps"].(map[string]any)["tls"].(map[string]any)["automation"].(map[string]any)["policies"].([]any)
	if b, _ := json.Marshal(pols[0]); strings.Contains(string(b), "subjects") {
		t.Errorf("hostname must use the default ACME policy: %s", b)
	}
	// An app that claims the host wins.
	m = render("web.example.com")
	if slices.Contains(hosts(m), "web.example.com") {
		t.Error("machine host shadowed an app host")
	}
}

// An app on the admin hostname serves the site; the node keeps /.ingressd/.
func TestAdminHostSharedWithApp(t *testing.T) {
	cfg, err := config.Parse([]byte(testConfig))
	if err != nil {
		t.Fatal(err)
	}
	cfg.Edge.Admin.Hostname = cfg.Apps[firstApp(cfg)].Hosts[0]
	host := cfg.Edge.Admin.Hostname
	routes := controlRoutes(cfg, Options{ControlSocket: "/run/ingressd/control.sock"})
	b, _ := json.Marshal(routes)
	if !strings.Contains(string(b), `{"host":["`+host+`"],"path":["/.ingressd/*","/.homeedge/*"]}` /* legacy homeedge name, remove after 2027-01 */) {
		t.Errorf("admin host shared with an app must keep only /.ingressd/: %s", b)
	}
	for _, r := range routes {
		m := r["match"].([]obj)[0]
		if _, hasPath := m["path"]; !hasPath && slices.Contains(m["host"].([]string), host) {
			t.Errorf("admin host still takes every path: %s", b)
		}
	}
}

// edge.admin.exposure limits the admin hostname, except the machine
// endpoints connectors use from anywhere (golden: testdata/admin-*.json).
func TestAdminExposure(t *testing.T) {
	for _, tt := range []struct{ exposure, file string }{
		{config.ExposurePublic, "admin-public.json"},
		{config.ExposureIPAllowlist, "admin-ip-allowlist.json"},
		{config.ExposureTunnelOnly, "admin-tunnel-only.json"},
	} {
		cfg, err := config.Parse([]byte(testConfig))
		if err != nil {
			t.Fatal(err)
		}
		cfg.Edge.Admin = config.Admin{Hostname: "edge.example.net", Exposure: tt.exposure, IPAllowlist: []string{"198.51.100.7/32", "2001:db8::/48"}}
		if err := cfg.Validate(); err != nil {
			t.Fatal(err)
		}
		b, _ := json.MarshalIndent(controlRoutes(cfg, Options{ControlSocket: "/run/ingressd/control.sock"}), "", "  ")
		golden(t, tt.file, string(b)+"\n")
	}
	// No allowed client at all: only the machine endpoints and the 403.
	cfg, _ := config.Parse([]byte(testConfig))
	cfg.Edge.Admin = config.Admin{Hostname: "edge.example.net", Exposure: config.ExposureIPAllowlist}
	b, _ := json.Marshal(controlRoutes(cfg, Options{ControlSocket: "/run/ingressd/control.sock"}))
	if strings.Contains(string(b), "remote_ip") || !strings.Contains(string(b), `"status_code":403`) {
		t.Errorf("empty allowlist: %s", b)
	}
}

func firstApp(cfg *config.Config) string {
	for name, a := range cfg.Apps {
		if len(a.Hosts) > 0 {
			return name
		}
	}
	return ""
}

// SPDX-License-Identifier: Apache-2.0

package render

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/ingressd/ingressd/internal/pki"
	"github.com/ingressd/ingressd/internal/secrets"
	"github.com/ingressd/ingressd/pkg/config"
)

func testCAPEM(t *testing.T) string {
	t.Helper()
	ca, err := pki.Init(secrets.NewMemory(nil), "Test CA", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return string(ca.OriginTrustPEM())
}

const tlsTestConfig = `
version: 1
edge:
  acme: { ca: internal }
certificates:
  origin_ca: { enabled: true }
tunnels:
  home:
    site: router
    listen_port: 51820
    transit: 10.100.1.0/24
    subnets: [192.168.0.0/24]
    virtual_prefix: 10.201.0.0/24
apps:
  strict:
    hosts: [strict.example.com]
    origin: https://192.168.0.17:8443
    tunnel: home
    tls: { origin: strict, mtls: true }
  named:
    hosts: [named.example.com]
    origin: https://192.168.0.17:8443
    tunnel: home
    tls: { origin: strict, verify_with: public, server_name: nas.example.com }
  custom:
    hosts: [custom.example.com]
    origin: https://192.168.0.17:8443
    tunnel: home
    tls: { origin: strict, verify_with: "custom:my_ca" }
  full:
    hosts: [full.example.com]
    origin: https://192.168.0.17:8443
    tunnel: home
  plain:
    hosts: [plain.example.com]
    origin: http://192.168.0.17:8080
    tunnel: home
`

func renderTLSConfig(t *testing.T, rt *config.OriginTLSRuntime) (map[string]map[string]any, error) {
	t.Helper()
	return renderTLSApps(t, rt, "")
}

// renderTLSApps renders each app's transport TLS (only one app if only is
// set), in name order so errors are deterministic.
func renderTLSApps(t *testing.T, rt *config.OriginTLSRuntime, only string) (map[string]map[string]any, error) {
	t.Helper()
	cfg, err := config.Parse([]byte(tlsTestConfig))
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	cfg.Certificates.OriginCA.Runtime = rt
	out := map[string]map[string]any{}
	for _, name := range sortedKeys(cfg.Apps) {
		app := cfg.Apps[name]
		if only != "" && name != only {
			continue
		}
		rp, err := reverseProxy(cfg, app)
		if err != nil {
			return nil, err
		}
		b, _ := json.Marshal(rp["transport"])
		var tr map[string]any
		_ = json.Unmarshal(b, &tr)
		tc, _ := tr["tls"].(map[string]any)
		out[name] = tc
	}
	return out, nil
}

func TestOriginTLS(t *testing.T) {
	pemCA := testCAPEM(t)
	got, err := renderTLSConfig(t, &config.OriginTLSRuntime{
		TrustPEM:       pemCA,
		ClientCertFile: "/var/lib/ingressd/pki/edge-client-1.crt",
		ClientKeyFile:  "/var/lib/ingressd/pki/edge-client-1.key",
		CustomCAs:      map[string]string{"my_ca": pemCA + pemCA},
	})
	if err != nil {
		t.Fatal(err)
	}
	js := func(v any) string { b, _ := json.Marshal(v); return string(b) }

	s := js(got["strict"])
	for _, want := range []string{
		`"provider":"inline"`, `"trusted_ca_certs":["MII`,
		`"client_certificate_file":"/var/lib/ingressd/pki/edge-client-1.crt"`,
		`"client_certificate_key_file":"/var/lib/ingressd/pki/edge-client-1.key"`,
		`"server_name":"192.168.0.17"`, // remapped tunnel: verify the real address
	} {
		if !strings.Contains(s, want) {
			t.Errorf("strict tls missing %s: %s", want, s)
		}
	}
	if strings.Contains(s, "insecure") {
		t.Errorf("strict must verify: %s", s)
	}
	if s := js(got["named"]); s != `{"server_name":"nas.example.com"}` {
		t.Errorf("public verify = %s", s)
	}
	if n := len(got["custom"]["ca"].(map[string]any)["trusted_ca_certs"].([]any)); n != 2 {
		t.Errorf("custom CA bundle has %d certs, want 2", n)
	}
	if s := js(got["full"]); s != `{"insecure_skip_verify":true}` {
		t.Errorf("full = %s", s)
	}
	if got["plain"] != nil {
		t.Errorf("plain http origin has tls: %v", got["plain"])
	}
}

func TestOriginTLSMissingMaterial(t *testing.T) {
	if _, err := renderTLSApps(t, nil, "strict"); err == nil || !strings.Contains(err.Error(), "origin CA is not initialized") {
		t.Fatalf("err = %v", err)
	}
	_, err := renderTLSApps(t, &config.OriginTLSRuntime{TrustPEM: testCAPEM(t)}, "strict")
	if err == nil || !strings.Contains(err.Error(), "client certificate") {
		t.Fatalf("err = %v", err)
	}
	// The full Render path surfaces the error with the app name.
	cfg, _ := config.Parse([]byte(tlsTestConfig))
	if _, err := Render(cfg, secrets.NewMemory(nil), fakeKeys{}, Options{}); err == nil || !strings.Contains(err.Error(), "app ") {
		t.Fatalf("Render err = %v", err)
	}
}

// SPDX-License-Identifier: Apache-2.0

package config

import (
	"strings"
	"testing"
)

const tlsYAML = `
version: 1
edge:
  acme: { ca: internal }
certificates:
  origin_ca: { enabled: %ENABLED% }
tunnels:
  home:
    site: router
    listen_port: 51820
    transit: 10.100.1.0/24
    subnets: [192.168.0.0/24]
apps:
  web:
    hosts: [web.example.com]
    origin: %ORIGIN%
    tunnel: home
    tls: %TLS%
`

func tlsConfig(t *testing.T, enabled, origin, tls string) *Config {
	t.Helper()
	s := strings.NewReplacer("%ENABLED%", enabled, "%ORIGIN%", origin, "%TLS%", tls).Replace(tlsYAML)
	return mustParse(t, s)
}

func TestValidateTLS(t *testing.T) {
	const https, http = "https://192.168.0.17:8443", "http://192.168.0.17:8080"
	tests := []struct {
		name, enabled, origin, tls string
		wantErr                    string
	}{
		{"strict origin_ca", "true", https, "{ origin: strict, mtls: true }", ""},
		{"full", "false", https, "{ origin: full, server_name: web.internal }", ""},
		{"off", "false", http, "{ origin: off }", ""},
		{"strict public", "false", https, "{ origin: strict, verify_with: public }", ""},
		{"strict custom", "false", https, "{ origin: strict, verify_with: 'custom:my_ca' }", ""},
		{"server name ip", "false", https, "{ origin: strict, server_name: 192.168.0.17 }", ""},
		{"default from scheme", "true", https, "{ mtls: true }", ""},
		{"bad mode", "false", https, "{ origin: tight }", "must be off, full or strict"},
		{"off with https", "false", https, "{ origin: off }", "off requires http://"},
		{"strict with http", "false", http, "{ origin: strict }", "strict requires https://"},
		{"origin_ca disabled", "false", https, "{ origin: strict, verify_with: origin_ca }", "requires certificates.origin_ca.enabled"},
		{"verify_with on full", "true", https, "{ origin: full, verify_with: public }", "only applies to origin: strict"},
		{"bad verify_with", "true", https, "{ origin: strict, verify_with: magic }", "must be origin_ca, public or custom"},
		{"bad custom secret", "true", https, "{ origin: strict, verify_with: 'custom:Bad Name' }", "invalid secret name"},
		{"mtls on http", "true", http, "{ mtls: true }", "mtls: requires https://"},
		{"mtls without CA", "false", https, "{ origin: full, mtls: true }", "requires certificates.origin_ca.enabled"},
		{"server_name on off", "false", http, "{ server_name: x.example.com }", "only applies to origin: full or strict"},
		{"bad server_name", "false", https, "{ origin: full, server_name: 'Bad_Name!' }", "invalid hostname"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tlsConfig(t, tt.enabled, tt.origin, tt.tls).Validate()
			switch {
			case tt.wantErr == "" && err != nil:
				t.Fatalf("unexpected error: %v", err)
			case tt.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErr)):
				t.Fatalf("error = %v, want %q", err, tt.wantErr)
			}
		})
	}
}

func TestEffectiveOriginTLS(t *testing.T) {
	c := tlsConfig(t, "true", "https://192.168.0.17:8443", "{ origin: strict }")
	got := c.EffectiveOriginTLS(c.Apps["web"])
	if got.Origin != OriginTLSStrict || got.VerifyWith != VerifyOriginCA {
		t.Errorf("strict with CA enabled = %+v", got)
	}
	c = tlsConfig(t, "false", "https://192.168.0.17:8443", "{ origin: strict }")
	if got := c.EffectiveOriginTLS(c.Apps["web"]); got.VerifyWith != VerifyPublic {
		t.Errorf("strict without CA = %+v", got)
	}
	app := c.Apps["web"]
	app.TLS = nil
	if got := c.EffectiveOriginTLS(app); got.Origin != OriginTLSFull {
		t.Errorf("https default = %q, want full", got.Origin)
	}
	app.Origin = "http://192.168.0.17:80"
	if got := c.EffectiveOriginTLS(app); got.Origin != OriginTLSOff {
		t.Errorf("http default = %q, want off", got.Origin)
	}
	if c.Certificates.OriginCA.CommonName != DefaultOriginCAName {
		t.Errorf("common_name default = %q", c.Certificates.OriginCA.CommonName)
	}
}

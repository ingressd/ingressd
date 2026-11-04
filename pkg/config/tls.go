// SPDX-License-Identifier: Apache-2.0

package config

import (
	"net/netip"
	"net/url"
	"strings"

	"github.com/ingressd/ingressd/internal/secrets"
)

// Origin TLS modes: how the edge talks to an app's origins.
const (
	OriginTLSOff    = "off"    // plain HTTP (inside the WireGuard tunnel)
	OriginTLSFull   = "full"   // HTTPS without certificate verification
	OriginTLSStrict = "strict" // HTTPS, certificate verified

	VerifyOriginCA = "origin_ca"
	VerifyPublic   = "public"
	// VerifyCustomPrefix is followed by the name of a secret holding one or
	// more PEM CA certificates: custom:<secret>.
	VerifyCustomPrefix = "custom:"

	DefaultOriginCAName = "ingressd Origin CA"
)

// OriginCA is the edge's private CA for origin server certificates and the
// edge's own mTLS client certificate (see internal/pki).
type OriginCA struct {
	Enabled    bool   `yaml:"enabled"`
	CommonName string `yaml:"common_name"`

	// Runtime is filled in by pki.Ensure before rendering; it is never read
	// from or written to config.yaml.
	Runtime *OriginTLSRuntime `yaml:"-"`
}

// OriginTLSRuntime is key material the renderer needs for origin TLS. It
// holds only public certificates and file paths, never private keys.
type OriginTLSRuntime struct {
	// TrustPEM are the CA certificates origin_ca verification trusts (the
	// current origin intermediate).
	TrustPEM string
	// ClientCertFile and ClientKeyFile are the edge's mTLS client
	// certificate (chain) and key, readable by the edge process.
	ClientCertFile, ClientKeyFile string
	// CustomCAs maps a secret name to its PEM contents, for custom:<secret>.
	CustomCAs map[string]string
}

// AppTLS configures TLS between the edge and an app's origins.
type AppTLS struct {
	// Origin is off, full or strict. Empty means off for http:// origins
	// and full for https:// origins.
	Origin string `yaml:"origin"`
	// VerifyWith (strict only) is origin_ca, public or custom:<secret>.
	// Default: origin_ca when certificates.origin_ca is enabled, else public.
	VerifyWith string `yaml:"verify_with"`
	// ServerName overrides the name sent in SNI and verified (full/strict).
	ServerName string `yaml:"server_name"`
	// MTLS makes the edge present its Origin CA client certificate
	// ("authenticated origin pulls").
	MTLS bool `yaml:"mtls"`
}

// CustomCASecret returns the secret name of a custom:<secret> verify_with.
func (t AppTLS) CustomCASecret() (string, bool) {
	return strings.CutPrefix(t.VerifyWith, VerifyCustomPrefix)
}

// EffectiveOriginTLS returns the app's TLS settings with defaults filled in
// from its origins' scheme and the Origin CA setting.
func (c *Config) EffectiveOriginTLS(app App) AppTLS {
	var t AppTLS
	if app.TLS != nil {
		t = *app.TLS
	}
	if t.Origin == "" {
		t.Origin = OriginTLSOff
		if c.appScheme(app) == "https" {
			t.Origin = OriginTLSFull
		}
	}
	if t.Origin == OriginTLSStrict && t.VerifyWith == "" {
		t.VerifyWith = VerifyPublic
		if c.Certificates.OriginCA.Enabled {
			t.VerifyWith = VerifyOriginCA
		}
	}
	return t
}

// appScheme is the scheme of the app's origins ("" if unknown or mixed;
// mixed pools are a separate validation error).
func (c *Config) appScheme(app App) string {
	addrs := []string{app.Origin}
	if app.Pool != "" {
		addrs = nil
		for _, o := range c.Pools[app.Pool].Origins {
			addrs = append(addrs, o.Address)
		}
	}
	scheme := ""
	for _, a := range addrs {
		u, err := url.Parse(a)
		if err != nil {
			continue
		}
		if scheme != "" && u.Scheme != scheme {
			return ""
		}
		scheme = u.Scheme
	}
	return scheme
}

func (c *Config) applyTLSDefaults() {
	if oc := &c.Certificates.OriginCA; oc.CommonName == "" {
		oc.CommonName = DefaultOriginCAName
	}
}

func (c *Config) validateTLS(v *validator) {
	if len(c.Certificates.OriginCA.CommonName) > 64 {
		v.add("certificates.origin_ca.common_name", "must be at most 64 characters")
	}
	for _, name := range sortedKeys(c.Apps) {
		app := c.Apps[name]
		if app.TLS == nil {
			continue
		}
		p := "apps." + name + ".tls"
		t := c.EffectiveOriginTLS(app)
		scheme := c.appScheme(app)
		switch t.Origin {
		case OriginTLSOff:
			if scheme == "https" {
				v.add(p+".origin", "off requires http:// origins (use full or strict for https://)")
			}
		case OriginTLSFull, OriginTLSStrict:
			if scheme == "http" {
				v.add(p+".origin", "%s requires https:// origins", t.Origin)
			}
		default:
			v.add(p+".origin", "must be off, full or strict; got %q", t.Origin)
		}
		if app.TLS.VerifyWith != "" && t.Origin != OriginTLSStrict {
			v.add(p+".verify_with", "only applies to origin: strict")
		}
		if t.Origin == OriginTLSStrict {
			switch sec, custom := t.CustomCASecret(); {
			case t.VerifyWith == VerifyOriginCA:
				if !c.Certificates.OriginCA.Enabled {
					v.add(p+".verify_with", "origin_ca requires certificates.origin_ca.enabled")
				}
			case t.VerifyWith == VerifyPublic:
			case custom:
				if !secrets.ValidName(sec) {
					v.add(p+".verify_with", "invalid secret name %q in custom:<secret>", sec)
				}
			default:
				v.add(p+".verify_with", "must be origin_ca, public or custom:<secret>; got %q", t.VerifyWith)
			}
		}
		if s := t.ServerName; s != "" {
			if t.Origin == OriginTLSOff {
				v.add(p+".server_name", "only applies to origin: full or strict")
			} else if !validServerName(s) {
				v.add(p+".server_name", "invalid hostname %q", s)
			}
		}
		if t.MTLS {
			if t.Origin == OriginTLSOff {
				v.add(p+".mtls", "requires https:// origins (origin: full or strict)")
			}
			if !c.Certificates.OriginCA.Enabled {
				v.add(p+".mtls", "requires certificates.origin_ca.enabled (the client certificate comes from the Origin CA)")
			}
		}
	}
}

// validServerName accepts an IP address or a (possibly single-label) DNS name.
func validServerName(s string) bool {
	if _, err := netip.ParseAddr(s); err == nil {
		return true
	}
	if s == "" || len(s) > 253 || s != strings.ToLower(s) {
		return false
	}
	for _, l := range strings.Split(s, ".") {
		if !labelRe.MatchString(l) {
			return false
		}
	}
	return true
}

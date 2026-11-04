// SPDX-License-Identifier: Apache-2.0

package pki

import (
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"software.sslmate.com/src/go-pkcs12"
)

// Bundle file names written by WriteBundle and referenced by the snippets.
const (
	FileChain    = "origin.crt"         // leaf + origin issuer
	FileKey      = "origin.key"         // only when the key was generated here
	FilePFX      = "origin.pfx"         // only when the key was generated here
	FileOriginCA = "origin-ca.pem"      // origin issuer + root
	FileClientCA = "edge-client-ca.pem" // edge-client issuer + root (for mTLS)
	FileRoot     = "ingressd-root.crt"  // root alone (Windows certificate stores)
	FileClientIs = "edge-client-issuer.crt"
)

// PFX encodes the certificate, chain and key as PKCS#12 (AES-256, PBKDF2).
// An empty password is allowed but most importers prefer one.
func (i *Issued) PFX(root []byte, password string) ([]byte, error) {
	if i.Key == nil {
		return nil, errors.New("no private key (certificate was issued from a CSR)")
	}
	chain := []*x509.Certificate{i.Issuer}
	if root != nil {
		rs, err := ParseCertsPEM(root)
		if err != nil {
			return nil, err
		}
		chain = append(chain, rs...)
	}
	return pkcs12.Modern.Encode(i.Key, i.Cert, chain, password)
}

// WriteBundle writes the PEM chain, key, PFX and CA bundles into dir and
// returns the paths written.
func (ca *CA) WriteBundle(dir string, i *Issued, pfxPassword string) ([]string, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	type file struct {
		name string
		data func() ([]byte, error)
		mode os.FileMode
	}
	files := []file{
		{FileChain, func() ([]byte, error) { return i.ChainPEM(), nil }, 0o644},
		{FileOriginCA, func() ([]byte, error) { return ca.OriginCABundlePEM(), nil }, 0o644},
		{FileClientCA, func() ([]byte, error) { return ca.ClientCABundlePEM(), nil }, 0o644},
		{FileRoot, func() ([]byte, error) { return CertPEM(ca.Root), nil }, 0o644},
		{FileClientIs, func() ([]byte, error) { return CertPEM(ca.ClientCA), nil }, 0o644},
	}
	if i.Key != nil {
		files = append(files,
			file{FileKey, i.KeyPEM, 0o600},
			file{FilePFX, func() ([]byte, error) { return i.PFX(CertPEM(ca.Root), pfxPassword) }, 0o600})
	}
	var written []string
	for _, f := range files {
		b, err := f.data()
		if err != nil {
			return written, fmt.Errorf("%s: %w", f.name, err)
		}
		p := filepath.Join(dir, f.name)
		if err := os.WriteFile(p, b, f.mode); err != nil {
			return written, err
		}
		written = append(written, p)
	}
	return written, nil
}

// Servers lists the web servers Snippet knows.
var Servers = []string{"nginx", "caddy", "traefik", "apache", "iis"}

// Snippet returns origin server configuration for one of Servers. dir is
// where the bundle files live on the origin; with mtls the snippet also
// requires the edge's client certificate.
func Snippet(server, dir string, mtls bool) (string, error) {
	if dir == "" {
		dir = "/etc/ssl/ingressd"
	}
	p := func(f string) string { return strings.TrimSuffix(dir, "/") + "/" + f }
	if server == "iis" {
		p = func(f string) string { return strings.TrimSuffix(dir, `\`) + `\` + f }
	}
	var b strings.Builder
	w := func(format string, a ...any) { fmt.Fprintf(&b, format+"\n", a...) }
	switch server {
	case "nginx":
		w("# nginx: inside the server { } block that the edge proxies to")
		w("listen 443 ssl;")
		w("ssl_certificate     %s;", p(FileChain))
		w("ssl_certificate_key %s;", p(FileKey))
		if mtls {
			w("# Authenticated origin pulls: only accept the ingressd edge")
			w("ssl_client_certificate %s;", p(FileClientCA))
			w("ssl_verify_client on;")
			w("ssl_verify_depth 2;")
		}
	case "caddy":
		w("# Caddyfile site block")
		w("https://origin.example.internal {")
		if mtls {
			w("\ttls %s %s {", p(FileChain), p(FileKey))
			w("\t\t# Authenticated origin pulls: only accept the ingressd edge")
			w("\t\tclient_auth {")
			w("\t\t\tmode require_and_verify")
			w("\t\t\ttrust_pool file %s", p(FileClientCA))
			w("\t\t}")
			w("\t}")
		} else {
			w("\ttls %s %s", p(FileChain), p(FileKey))
		}
		w("\treverse_proxy localhost:8080")
		w("}")
	case "traefik":
		w("# Traefik dynamic configuration (file provider)")
		w("tls:")
		w("  certificates:")
		w("    - certFile: %s", p(FileChain))
		w("      keyFile: %s", p(FileKey))
		if mtls {
			w("  options:")
			w("    default:")
			w("      # Authenticated origin pulls: only accept the ingressd edge")
			w("      clientAuth:")
			w("        caFiles: [%s]", p(FileClientCA))
			w("        clientAuthType: RequireAndVerifyClientCert")
		}
	case "apache":
		w("# Apache: inside <VirtualHost *:443> (mod_ssl)")
		w("SSLEngine on")
		w("SSLCertificateFile    %s", p(FileChain))
		w("SSLCertificateKeyFile %s", p(FileKey))
		if mtls {
			w("# Authenticated origin pulls: only accept the ingressd edge")
			w("SSLCACertificateFile %s", p(FileClientCA))
			w("SSLVerifyClient require")
			w("SSLVerifyDepth 2")
		}
	case "iis":
		w("# IIS (PowerShell as Administrator)")
		w("$pfx = Import-PfxCertificate -FilePath '%s' -CertStoreLocation Cert:\\LocalMachine\\My -Password (Read-Host -AsSecureString 'PFX password')", p(FilePFX))
		w("New-WebBinding -Name 'Default Web Site' -Protocol https -Port 443 -SslFlags 0")
		w("(Get-WebBinding -Name 'Default Web Site' -Protocol https).AddSslCertificate($pfx.Thumbprint, 'My')")
		if mtls {
			w("# Authenticated origin pulls: trust the edge-client issuer and require client certificates")
			w("Import-Certificate -FilePath '%s' -CertStoreLocation Cert:\\LocalMachine\\Root", p(FileRoot))
			w("Import-Certificate -FilePath '%s' -CertStoreLocation Cert:\\LocalMachine\\CA", p(FileClientIs))
			w("Set-WebConfigurationProperty -PSPath IIS:\\ -Location 'Default Web Site' -Filter system.webServer/security/access -Name sslFlags -Value 'Ssl,SslRequireCert'")
			w("# This trusts client certificates chaining to the ingressd root, which signs only the")
			w("# origin issuer (server-auth certificates) and the edge-client issuer.")
		}
	default:
		return "", fmt.Errorf("unknown server %q (supported: %s)", server, strings.Join(Servers, ", "))
	}
	return b.String(), nil
}

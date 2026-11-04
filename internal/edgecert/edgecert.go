// SPDX-License-Identifier: Apache-2.0

// Package edgecert reads the public (edge) certificates Caddy keeps in its
// storage directory, for `ingressd cert list` and managed-mode status.
package edgecert

import (
	"crypto/x509"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"strings"
	"time"

	"github.com/ingressd/ingressd/internal/pki"
	"github.com/ingressd/ingressd/internal/safefs"
)

// maxCertFile bounds one certificate file read from Caddy's storage.
const maxCertFile = 1 << 20

// List reads the leaf certificates under <storage>/certificates. The
// storage directory belongs to the edge user: reads stay inside it (no
// symlinks out) and only regular files are read (see safefs).
func List(storage string) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	root, err := os.OpenRoot(storage)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer root.Close()
	err = fs.WalkDir(root.FS(), "certificates", func(p string, d fs.DirEntry, err error) error {
		if errors.Is(err, fs.ErrNotExist) {
			return fs.SkipAll
		}
		if err != nil || !d.Type().IsRegular() || !strings.HasSuffix(p, ".crt") {
			return err
		}
		b, err := safefs.ReadFile(root, p, maxCertFile)
		if err != nil {
			return err
		}
		cs, err := pki.ParseCertsPEM(b)
		if err != nil {
			return fmt.Errorf("%s: %w", p, err)
		}
		out = append(out, cs[0])
		return nil
	})
	return out, err
}

// SANs returns a certificate's DNS names and IP addresses.
func SANs(c *x509.Certificate) []string {
	s := append([]string{}, c.DNSNames...)
	for _, ip := range c.IPAddresses {
		s = append(s, ip.String())
	}
	return s
}

// IssuerName is the issuer's common name, or its organisation.
func IssuerName(c *x509.Certificate) string {
	if c.Issuer.CommonName != "" {
		return c.Issuer.CommonName
	}
	return strings.Join(c.Issuer.Organization, ",")
}

// Covers reports whether c is valid for host (exact, wildcard SAN, or IP).
// A wildcard host ("*.example.com") is covered only by the same wildcard.
func Covers(c *x509.Certificate, host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if ip := net.ParseIP(host); ip != nil {
		for _, a := range c.IPAddresses {
			if a.Equal(ip) {
				return true
			}
		}
		return false
	}
	for _, n := range c.DNSNames {
		n = strings.ToLower(n)
		if n == host {
			return true
		}
		if suf, ok := strings.CutPrefix(n, "*."); ok && !strings.HasPrefix(host, "*.") {
			if label, rest, found := strings.Cut(host, "."); found && label != "" && rest == suf {
				return true
			}
		}
	}
	return false
}

// Best returns the certificate covering host with the latest expiry, or nil.
func Best(certs []*x509.Certificate, host string) *x509.Certificate {
	var best *x509.Certificate
	for _, c := range certs {
		if Covers(c, host) && (best == nil || c.NotAfter.After(best.NotAfter)) {
			best = c
		}
	}
	return best
}

// Valid reports whether c is within its validity period at now.
func Valid(c *x509.Certificate, now time.Time) bool {
	return c != nil && !now.Before(c.NotBefore) && now.Before(c.NotAfter)
}

// InternalCARoot returns the PEM of Caddy's internal ("local") CA root,
// which issues certificates for bare-IP hosts and acme.ca internal.
func InternalCARoot(storage string) ([]byte, error) {
	root, err := os.OpenRoot(storage)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	return safefs.ReadFile(root, "pki/authorities/local/root.crt", maxCertFile)
}

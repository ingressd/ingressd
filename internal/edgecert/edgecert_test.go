// SPDX-License-Identifier: Apache-2.0

package edgecert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func certPEM(t *testing.T, name string) []byte {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name}, DNSNames: []string{name},
		NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// The storage dir is the edge user's: List never follows symlinks out of it.
func TestListIgnoresSymlinks(t *testing.T) {
	storage, outside := t.TempDir(), t.TempDir()
	dir := filepath.Join(storage, "certificates", "acme")
	os.MkdirAll(dir, 0o700)
	os.WriteFile(filepath.Join(dir, "a.example.crt"), certPEM(t, "a.example"), 0o600)
	os.WriteFile(filepath.Join(outside, "b.example.crt"), certPEM(t, "b.example"), 0o600)
	if err := os.Symlink(filepath.Join(outside, "b.example.crt"), filepath.Join(dir, "b.example.crt")); err != nil {
		t.Skip("symlinks unavailable:", err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "out")); err != nil {
		t.Fatal(err)
	}
	certs, err := List(storage)
	if err != nil || len(certs) != 1 || certs[0].Subject.CommonName != "a.example" {
		t.Fatalf("List = %v, %v", certs, err)
	}
	if certs, err := List(filepath.Join(storage, "missing")); err != nil || certs != nil {
		t.Fatalf("missing storage: %v, %v", certs, err)
	}
}

func TestCovers(t *testing.T) {
	c := &x509.Certificate{DNSNames: []string{"a.example.com", "*.w.example.com"}, IPAddresses: []net.IP{net.ParseIP("203.0.113.10")}}
	for host, want := range map[string]bool{
		"a.example.com": true, "A.example.com.": true, "b.example.com": false,
		"x.w.example.com": true, "y.x.w.example.com": false, "w.example.com": false,
		"*.w.example.com": true, "203.0.113.10": true, "203.0.113.11": false,
	} {
		if got := Covers(c, host); got != want {
			t.Errorf("Covers(%q) = %v", host, got)
		}
	}
	now := time.Now()
	old := &x509.Certificate{DNSNames: []string{"a.example.com"}, NotBefore: now.Add(-48 * time.Hour), NotAfter: now.Add(-time.Hour)}
	cur := &x509.Certificate{DNSNames: []string{"a.example.com"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}
	if b := Best([]*x509.Certificate{old, cur}, "a.example.com"); b != cur || !Valid(b, now) || Valid(old, now) {
		t.Error("Best/Valid")
	}
	if Best([]*x509.Certificate{old}, "z.example.com") != nil {
		t.Error("Best for an uncovered host")
	}
}

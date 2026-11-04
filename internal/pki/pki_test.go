// SPDX-License-Identifier: Apache-2.0

package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
	"software.sslmate.com/src/go-pkcs12"

	"github.com/ingressd/ingressd/internal/secrets"
	"github.com/ingressd/ingressd/pkg/config"
)

func newCA(t *testing.T) (*CA, *secrets.Store) {
	t.Helper()
	st := secrets.NewMemory(nil)
	ca, err := Init(st, "Test Origin CA", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return ca, st
}

func pool(t *testing.T, pemData []byte) *x509.CertPool {
	t.Helper()
	p := x509.NewCertPool()
	if !p.AppendCertsFromPEM(pemData) {
		t.Fatal("no certs in pool")
	}
	return p
}

func verifyServer(t *testing.T, ca *CA, i *Issued, name string) error {
	t.Helper()
	_, err := i.Cert.Verify(x509.VerifyOptions{
		DNSName:   name,
		Roots:     pool(t, ca.OriginTrustPEM()),
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	return err
}

func TestInitAndLoad(t *testing.T) {
	ca, st := newCA(t)
	if ca.Root.PublicKeyAlgorithm != x509.ECDSA || ca.Root.PublicKey.(*ecdsa.PublicKey).Curve != elliptic.P384() {
		t.Error("root is not ECDSA P-384")
	}
	if d := time.Until(ca.Root.NotAfter); d < 19*year {
		t.Errorf("root validity %v, want ~20y", d)
	}
	for _, c := range []*x509.Certificate{ca.Origin, ca.ClientCA} {
		if err := c.CheckSignatureFrom(ca.Root); err != nil || !c.IsCA {
			t.Errorf("%s: not a CA signed by root: %v", c.Subject.CommonName, err)
		}
	}
	loaded, err := Load(st)
	if err != nil {
		t.Fatal(err)
	}
	if !loaded.Origin.Equal(ca.Origin) || !loaded.ClientCA.Equal(ca.ClientCA) {
		t.Error("loaded CA differs")
	}
	if _, err := Load(secrets.NewMemory(nil)); err != ErrNotInitialized {
		t.Errorf("Load(empty) = %v", err)
	}
	if _, created, err := LoadOrInit(st, "x"); err != nil || created {
		t.Errorf("LoadOrInit on existing CA: created=%v err=%v", created, err)
	}
}

func TestIssue(t *testing.T) {
	ca, _ := newCA(t)
	for _, kt := range []string{KeyECDSAP256, KeyRSA2048} {
		i, err := ca.Issue(IssueRequest{SANs: []string{"nas.home.arpa", "192.168.0.17"}, KeyType: kt}, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		if err := verifyServer(t, ca, i, "nas.home.arpa"); err != nil {
			t.Errorf("%s: verify: %v", kt, err)
		}
		if err := verifyServer(t, ca, i, "192.168.0.17"); err != nil {
			t.Errorf("%s: verify IP: %v", kt, err)
		}
		if d := time.Until(i.Cert.NotAfter); d < 14*year {
			t.Errorf("default validity %v, want ~15y", d)
		}
		// Not usable as a client certificate.
		if _, err := i.Cert.Verify(x509.VerifyOptions{Roots: pool(t, ca.ClientCABundlePEM()), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err == nil {
			t.Error("origin certificate verifies as an edge client")
		}
		pfx, err := i.PFX(CertPEM(ca.Root), "pw")
		if err != nil {
			t.Fatal(err)
		}
		_, cert, chain, err := pkcs12.DecodeChain(pfx, "pw")
		if err != nil || !cert.Equal(i.Cert) || len(chain) != 2 {
			t.Errorf("PFX round trip: err=%v chain=%d", err, len(chain))
		}
	}
	if _, err := ca.Issue(IssueRequest{SANs: []string{"bad name"}}, time.Now()); err == nil {
		t.Error("invalid SAN accepted")
	}
	if _, err := ca.Issue(IssueRequest{SANs: []string{"a.example"}, KeyType: "dsa"}, time.Now()); err == nil {
		t.Error("invalid key type accepted")
	}
	i, err := ca.Issue(IssueRequest{SANs: []string{"a.example"}, Days: 30}, time.Now())
	if err != nil || time.Until(i.Cert.NotAfter) > 31*24*time.Hour {
		t.Errorf("--days not honoured: %v", err)
	}
}

func TestSignCSR(t *testing.T) {
	ca, _ := newCA(t)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:     pkix.Name{CommonName: "app.internal"},
		DNSNames:    []string{"app.internal"},
		IPAddresses: []net.IP{net.ParseIP("10.0.0.5")},
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	csr := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
	i, err := ca.SignCSR(csr, []string{"extra.internal"}, 0, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if i.Key != nil || i.KeyType != "csr:ecdsa-p256" {
		t.Errorf("key=%v type=%q", i.Key, i.KeyType)
	}
	if !i.Cert.PublicKey.(*ecdsa.PublicKey).Equal(&key.PublicKey) {
		t.Error("certificate does not carry the CSR's key")
	}
	for _, n := range []string{"app.internal", "10.0.0.5", "extra.internal"} {
		if err := verifyServer(t, ca, i, n); err != nil {
			t.Errorf("verify %s: %v", n, err)
		}
	}
	der[len(der)-1] ^= 0xff
	bad := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
	if _, err := ca.SignCSR(bad, nil, 0, time.Now()); err == nil {
		t.Error("tampered CSR accepted")
	}
}

func TestRotateOriginRevokesOldCerts(t *testing.T) {
	ca, st := newCA(t)
	i, _ := ca.Issue(IssueRequest{SANs: []string{"a.example"}}, time.Now())
	if err := ca.RotateOrigin(st, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := verifyServer(t, ca, i, "a.example"); err == nil {
		t.Error("certificate from the old issuer still verifies after rotation")
	}
	j, _ := ca.Issue(IssueRequest{SANs: []string{"a.example"}}, time.Now())
	if err := verifyServer(t, ca, j, "a.example"); err != nil {
		t.Error(err)
	}
}

func TestEdgeClient(t *testing.T) {
	ca, st := newCA(t)
	now := time.Now()
	changed, err := ca.EnsureEdgeClient(st, "edge1", now)
	if err != nil || !changed {
		t.Fatalf("first EnsureEdgeClient: %v %v", changed, err)
	}
	if _, err := ca.EdgeClient.Verify(x509.VerifyOptions{
		Roots:         pool(t, CertPEM(ca.Root)),
		Intermediates: pool(t, CertPEM(ca.ClientCA)),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		t.Errorf("edge client does not verify: %v", err)
	}
	if changed, _ := ca.EnsureEdgeClient(st, "edge1", now); changed {
		t.Error("fresh client cert was rotated")
	}
	serial := ca.EdgeClient.SerialNumber
	if changed, _ := ca.EnsureEdgeClient(st, "edge1", now.Add(EdgeClientLife-EdgeClientRenew+time.Hour)); !changed {
		t.Error("client cert near expiry was not rotated")
	}
	if ca.EdgeClient.SerialNumber.Cmp(serial) == 0 {
		t.Error("serial unchanged after rotation")
	}
	chain, key, err := ca.EdgeClientPEM()
	if err != nil || len(chain) == 0 || !strings.Contains(string(key), "PRIVATE KEY") {
		t.Fatalf("EdgeClientPEM: %v", err)
	}
}

func TestInventory(t *testing.T) {
	ca, st := newCA(t)
	dir := t.TempDir()
	inv, err := LoadInventory(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !inv.SyncCA(ca) {
		t.Error("SyncCA on empty inventory reported no change")
	}
	if inv.SyncCA(ca) {
		t.Error("SyncCA without changes reported a change")
	}
	i, _ := ca.Issue(IssueRequest{SANs: []string{"a.example"}}, time.Now())
	r := inv.Add(i, time.Now())
	if err := inv.Save(dir); err != nil {
		t.Fatal(err)
	}
	inv, err = LoadInventory(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(inv.Certificates) != 1 || inv.Certificates[0].Status(inv, time.Now()) != "active" {
		t.Fatalf("inventory = %+v", inv.Certificates)
	}
	if _, err := inv.Revoke(strings.ToUpper(r.Serial[:10]), time.Now()); err != nil {
		t.Fatalf("revoke by prefix: %v", err)
	}
	if _, err := inv.Revoke(r.Serial, time.Now()); err == nil {
		t.Error("double revoke accepted")
	}
	if got := inv.Certificates[0].Status(inv, time.Now()); got != "revoked" {
		t.Errorf("status = %q", got)
	}
	_ = ca.RotateOrigin(st, time.Now())
	if !inv.SyncCA(ca) || len(inv.CA.RetiredIssuers) != 1 {
		t.Errorf("rotation not recorded: %+v", inv.CA.RetiredIssuers)
	}
	b, _ := os.ReadFile(filepath.Join(dir, InventoryFile))
	if strings.Contains(string(b), "PRIVATE") {
		t.Error("inventory contains key material")
	}
}

func TestSnippets(t *testing.T) {
	for _, s := range Servers {
		plain, err := Snippet(s, "", false)
		if err != nil {
			t.Fatal(err)
		}
		withMTLS, _ := Snippet(s, "", true)
		if len(withMTLS) <= len(plain) {
			t.Errorf("%s: mtls snippet adds nothing", s)
		}
		if s != "iis" && !strings.Contains(withMTLS, FileClientCA) {
			t.Errorf("%s: mtls snippet does not reference %s", s, FileClientCA)
		}
	}
	if _, err := Snippet("lighttpd", "", false); err == nil {
		t.Error("unknown server accepted")
	}
}

func TestWriteBundle(t *testing.T) {
	ca, _ := newCA(t)
	i, _ := ca.Issue(IssueRequest{SANs: []string{"a.example"}}, time.Now())
	dir := t.TempDir()
	files, err := ca.WriteBundle(dir, i, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 7 {
		t.Errorf("wrote %d files: %v", len(files), files)
	}
	chain, _ := os.ReadFile(filepath.Join(dir, FileChain))
	if cs, err := ParseCertsPEM(chain); err != nil || len(cs) != 2 {
		t.Errorf("chain: %v", err)
	}
}

func TestEnsure(t *testing.T) {
	cfg, err := config.Parse([]byte(`
version: 1
edge: { acme: { ca: internal } }
certificates: { origin_ca: { enabled: true } }
apps:
  a:
    hosts: [a.example.com]
    origin: https://10.0.0.1:443
    tls: { origin: strict, verify_with: "custom:my_ca", mtls: true }
`))
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	id, _ := age.GenerateX25519Identity()
	st, err := secrets.Open(filepath.Join(dir, "secrets.age"), id)
	if err != nil {
		t.Fatal(err)
	}
	opts := EnsureOptions{ConfigDir: dir, StateDir: dir}
	if err := Ensure(cfg, st, opts); err == nil || !strings.Contains(err.Error(), "my_ca") {
		t.Fatalf("missing custom CA: %v", err)
	}
	other, _ := Init(secrets.NewMemory(nil), "Other", time.Now())
	_ = st.Set("my_ca", string(other.OriginCABundlePEM()))
	if err := Ensure(cfg, st, opts); err != nil {
		t.Fatal(err)
	}
	rt := cfg.Certificates.OriginCA.Runtime
	if rt.TrustPEM == "" || rt.CustomCAs["my_ca"] == "" {
		t.Errorf("runtime = %+v", rt)
	}
	if _, err := os.Stat(rt.ClientCertFile); err != nil {
		t.Error(err)
	}
	if _, err := os.Stat(filepath.Join(dir, InventoryFile)); err != nil {
		t.Error(err)
	}
	// Persisted: a second run reuses the same CA and client certificate.
	st2, _ := secrets.Open(filepath.Join(dir, "secrets.age"), id)
	first := rt.ClientCertFile
	if err := Ensure(cfg, st2, opts); err != nil {
		t.Fatal(err)
	}
	if cfg.Certificates.OriginCA.Runtime.ClientCertFile != first {
		t.Error("client certificate re-issued on second run")
	}
}

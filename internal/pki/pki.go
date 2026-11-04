// SPDX-License-Identifier: Apache-2.0

// Package pki is the Origin CA: a private two-level PKI that issues origin
// server certificates and the edge's mTLS client certificate.
//
//	root (ECDSA P-384, 20y, signs only intermediates)
//	├── origin issuer      → origin server certificates (strict mode trusts this)
//	└── edge-client issuer → the edge's client certificate (authenticated origin pulls)
//
// All CA keys and certificates live in the age-encrypted secrets store.
// Private keys of issued origin certificates are handed to the operator and
// never stored on the edge.
package pki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"strings"
	"time"
)

// Secret names holding the CA material.
const (
	SecretRootKey       = "pki_root_key"
	SecretRootCert      = "pki_root_crt"
	SecretOriginKey     = "pki_origin_key"
	SecretOriginCert    = "pki_origin_crt"
	SecretClientCAKey   = "pki_client_ca_key"
	SecretClientCACert  = "pki_client_ca_crt"
	SecretEdgeClientKey = "pki_edge_client_key"
	SecretEdgeCliCert   = "pki_edge_client_crt"
)

// Key types for issued certificates.
const (
	KeyECDSAP256 = "ecdsa-p256"
	KeyRSA2048   = "rsa-2048"
	KeyRSA3072   = "rsa-3072"
	KeyRSA4096   = "rsa-4096"
)

// KeyTypes lists the supported key types for issued certificates.
var KeyTypes = []string{KeyECDSAP256, KeyRSA2048, KeyRSA3072, KeyRSA4096}

const (
	year             = 365 * 24 * time.Hour
	RootValidity     = 20 * year
	DefaultLeafDays  = 15 * 365
	EdgeClientLife   = 2 * year
	EdgeClientRenew  = year // rotate when less than this remains
	backdate         = time.Hour
	maxLeafDays      = 20 * 365
	edgeClientPrefix = "ingressd edge client"
)

// ErrNotInitialized means the Origin CA has not been generated yet.
var ErrNotInitialized = errors.New("origin CA is not initialized (enable certificates.origin_ca and run ingressd apply)")

// Store is the subset of secrets.Store the CA needs.
type Store interface {
	Get(name string) (string, bool)
	Set(name, value string) error
}

// CA is a loaded Origin CA.
type CA struct {
	Root, Origin, ClientCA *x509.Certificate
	rootKey, originKey     crypto.Signer
	clientCAKey            crypto.Signer
	// EdgeClient is the edge's current client certificate (may be nil
	// until EnsureEdgeClient runs).
	EdgeClient    *x509.Certificate
	edgeClientKey crypto.Signer
}

// Load reads the CA from the store. It returns ErrNotInitialized if the root
// does not exist.
func Load(st Store) (*CA, error) {
	if _, ok := st.Get(SecretRootCert); !ok {
		return nil, ErrNotInitialized
	}
	ca := &CA{}
	var err error
	if ca.Root, ca.rootKey, err = loadPair(st, SecretRootCert, SecretRootKey); err != nil {
		return nil, err
	}
	if ca.Origin, ca.originKey, err = loadPair(st, SecretOriginCert, SecretOriginKey); err != nil {
		return nil, err
	}
	if ca.ClientCA, ca.clientCAKey, err = loadPair(st, SecretClientCACert, SecretClientCAKey); err != nil {
		return nil, err
	}
	if _, ok := st.Get(SecretEdgeCliCert); ok {
		if ca.EdgeClient, ca.edgeClientKey, err = loadPair(st, SecretEdgeCliCert, SecretEdgeClientKey); err != nil {
			return nil, err
		}
	}
	return ca, nil
}

// LoadOrInit loads the CA, generating it first if it does not exist.
func LoadOrInit(st Store, commonName string) (ca *CA, created bool, err error) {
	ca, err = Load(st)
	if !errors.Is(err, ErrNotInitialized) {
		return ca, false, err
	}
	ca, err = Init(st, commonName, time.Now())
	return ca, err == nil, err
}

// Init generates a new root and both intermediates and stores them.
func Init(st Store, commonName string, now time.Time) (*CA, error) {
	rootKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		Subject:               pkix.Name{CommonName: commonName, Organization: []string{"ingressd"}},
		NotBefore:             now.Add(-backdate),
		NotAfter:              now.Add(RootValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}
	root, err := sign(tmpl, tmpl, rootKey.Public(), rootKey)
	if err != nil {
		return nil, err
	}
	ca := &CA{Root: root, rootKey: rootKey}
	if err := storePair(st, SecretRootCert, SecretRootKey, root, rootKey); err != nil {
		return nil, err
	}
	if err := ca.RotateOrigin(st, now); err != nil {
		return nil, err
	}
	if err := ca.rotateClientCA(st, now); err != nil {
		return nil, err
	}
	return ca, nil
}

// RotateOrigin replaces the origin issuer with a new key and certificate.
// Every certificate the old issuer signed stops being trusted by the edge in
// strict origin_ca mode once the new config is applied.
func (ca *CA) RotateOrigin(st Store, now time.Time) error {
	c, k, err := ca.newIntermediate("Origin Issuer", x509.ExtKeyUsageServerAuth, now)
	if err != nil {
		return err
	}
	if err := storePair(st, SecretOriginCert, SecretOriginKey, c, k); err != nil {
		return err
	}
	ca.Origin, ca.originKey = c, k
	return nil
}

func (ca *CA) rotateClientCA(st Store, now time.Time) error {
	c, k, err := ca.newIntermediate("Edge Client Issuer", x509.ExtKeyUsageClientAuth, now)
	if err != nil {
		return err
	}
	if err := storePair(st, SecretClientCACert, SecretClientCAKey, c, k); err != nil {
		return err
	}
	ca.ClientCA, ca.clientCAKey = c, k
	return nil
}

func (ca *CA) newIntermediate(role string, eku x509.ExtKeyUsage, now time.Time) (*x509.Certificate, crypto.Signer, error) {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, err := newSerial()
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: fmt.Sprintf("%s %s %s", ca.Root.Subject.CommonName, role, SerialHex(serial)[:8]), Organization: []string{"ingressd"}},
		NotBefore:             now.Add(-backdate),
		NotAfter:              ca.Root.NotAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{eku},
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	c, err := sign(tmpl, ca.Root, key.Public(), ca.rootKey)
	return c, key, err
}

// EnsureEdgeClient issues the edge's client certificate if it is missing,
// was signed by a previous issuer, or expires within EdgeClientRenew.
func (ca *CA) EnsureEdgeClient(st Store, edgeName string, now time.Time) (changed bool, err error) {
	if c := ca.EdgeClient; c != nil && c.NotAfter.Sub(now) > EdgeClientRenew && c.CheckSignatureFrom(ca.ClientCA) == nil {
		return false, nil
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return false, err
	}
	serial, err := newSerial()
	if err != nil {
		return false, err
	}
	cn := edgeClientPrefix
	if edgeName != "" {
		cn += " " + edgeName
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn, Organization: []string{"ingressd"}},
		NotBefore:    now.Add(-backdate),
		NotAfter:     minTime(now.Add(EdgeClientLife), ca.ClientCA.NotAfter),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	c, err := sign(tmpl, ca.ClientCA, key.Public(), ca.clientCAKey)
	if err != nil {
		return false, err
	}
	if err := storePair(st, SecretEdgeCliCert, SecretEdgeClientKey, c, key); err != nil {
		return false, err
	}
	ca.EdgeClient, ca.edgeClientKey = c, key
	return true, nil
}

// EdgeClientPEM returns the edge client certificate chain and key as PEM.
func (ca *CA) EdgeClientPEM() (chain, key []byte, err error) {
	if ca.EdgeClient == nil {
		return nil, nil, errors.New("edge client certificate not issued")
	}
	key, err = KeyPEM(ca.edgeClientKey)
	return append(CertPEM(ca.EdgeClient), CertPEM(ca.ClientCA)...), key, err
}

// OriginTrustPEM is what the edge trusts in strict origin_ca mode: only the
// current origin issuer, so rotating it revokes everything it signed.
func (ca *CA) OriginTrustPEM() []byte { return CertPEM(ca.Origin) }

// OriginCABundlePEM is the origin issuer plus root, for third parties that
// want to verify origin certificates.
func (ca *CA) OriginCABundlePEM() []byte {
	return append(CertPEM(ca.Origin), CertPEM(ca.Root)...)
}

// ClientCABundlePEM is what an origin trusts to require the edge's client
// certificate: the edge-client issuer plus root.
func (ca *CA) ClientCABundlePEM() []byte {
	return append(CertPEM(ca.ClientCA), CertPEM(ca.Root)...)
}

// IssueRequest describes an origin server certificate.
type IssueRequest struct {
	SANs    []string // DNS names and/or IP addresses
	Days    int      // validity; 0 means DefaultLeafDays
	KeyType string   // see KeyTypes; ignored when signing a CSR
}

// Issued is a newly issued origin certificate.
type Issued struct {
	Cert    *x509.Certificate
	Issuer  *x509.Certificate
	Key     crypto.Signer // nil when signed from a CSR
	KeyType string
}

// ChainPEM is the leaf followed by the origin issuer (what servers serve).
func (i *Issued) ChainPEM() []byte { return append(CertPEM(i.Cert), CertPEM(i.Issuer)...) }

// KeyPEM returns the private key as PKCS#8 PEM, or nil for CSR-based certs.
func (i *Issued) KeyPEM() ([]byte, error) {
	if i.Key == nil {
		return nil, nil
	}
	return KeyPEM(i.Key)
}

// Issue generates a key pair and an origin certificate for it.
func (ca *CA) Issue(req IssueRequest, now time.Time) (*Issued, error) {
	kt := req.KeyType
	if kt == "" {
		kt = KeyECDSAP256
	}
	key, err := GenerateKey(kt)
	if err != nil {
		return nil, err
	}
	c, err := ca.signLeaf(req, key.Public(), now)
	if err != nil {
		return nil, err
	}
	return &Issued{Cert: c, Issuer: ca.Origin, Key: key, KeyType: kt}, nil
}

// SignCSR issues an origin certificate for a PEM certificate signing
// request. The CSR's DNS/IP SANs are used, plus any in extraSANs.
func (ca *CA) SignCSR(csrPEM []byte, extraSANs []string, days int, now time.Time) (*Issued, error) {
	b, _ := pem.Decode(csrPEM)
	if b == nil || !strings.Contains(b.Type, "CERTIFICATE REQUEST") {
		return nil, errors.New("not a PEM certificate request")
	}
	csr, err := x509.ParseCertificateRequest(b.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse CSR: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("CSR signature: %w", err)
	}
	var sans []string
	sans = append(sans, csr.DNSNames...)
	for _, ip := range csr.IPAddresses {
		sans = append(sans, ip.String())
	}
	if len(sans) == 0 && csr.Subject.CommonName != "" {
		sans = append(sans, csr.Subject.CommonName)
	}
	sans = append(sans, extraSANs...)
	c, err := ca.signLeaf(IssueRequest{SANs: sans, Days: days}, csr.PublicKey, now)
	if err != nil {
		return nil, err
	}
	return &Issued{Cert: c, Issuer: ca.Origin, KeyType: "csr:" + keyTypeOf(csr.PublicKey)}, nil
}

func (ca *CA) signLeaf(req IssueRequest, pub crypto.PublicKey, now time.Time) (*x509.Certificate, error) {
	dns, ips, err := ParseSANs(req.SANs)
	if err != nil {
		return nil, err
	}
	days := req.Days
	if days == 0 {
		days = DefaultLeafDays
	}
	if days < 1 || days > maxLeafDays {
		return nil, fmt.Errorf("validity must be 1-%d days, got %d", maxLeafDays, days)
	}
	serial, err := newSerial()
	if err != nil {
		return nil, err
	}
	cn := ""
	if len(dns) > 0 {
		cn = dns[0]
	} else {
		cn = ips[0].String()
	}
	ku := x509.KeyUsageDigitalSignature
	if _, ok := pub.(*rsa.PublicKey); ok {
		ku |= x509.KeyUsageKeyEncipherment
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    now.Add(-backdate),
		NotAfter:     minTime(now.Add(time.Duration(days)*24*time.Hour), ca.Origin.NotAfter),
		KeyUsage:     ku,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     dns,
		IPAddresses:  ips,
	}
	return sign(tmpl, ca.Origin, pub, ca.originKey)
}

// ParseSANs splits SANs into DNS names and IP addresses, validating them.
func ParseSANs(sans []string) ([]string, []net.IP, error) {
	var dns []string
	var ips []net.IP
	seen := map[string]bool{}
	for _, s := range sans {
		s = strings.ToLower(strings.TrimSpace(s))
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		if ip := net.ParseIP(s); ip != nil {
			ips = append(ips, ip)
			continue
		}
		if !validDNSName(s) {
			return nil, nil, fmt.Errorf("invalid SAN %q (want a DNS name, *.wildcard or IP address)", s)
		}
		dns = append(dns, s)
	}
	if len(dns)+len(ips) == 0 {
		return nil, nil, errors.New("at least one SAN is required")
	}
	return dns, ips, nil
}

func validDNSName(s string) bool {
	s = strings.TrimPrefix(s, "*.")
	if s == "" || len(s) > 253 {
		return false
	}
	for _, l := range strings.Split(s, ".") {
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
		for _, r := range l {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
				return false
			}
		}
	}
	return true
}

// GenerateKey creates a private key of one of KeyTypes.
func GenerateKey(keyType string) (crypto.Signer, error) {
	switch keyType {
	case KeyECDSAP256:
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case KeyRSA2048:
		return rsa.GenerateKey(rand.Reader, 2048)
	case KeyRSA3072:
		return rsa.GenerateKey(rand.Reader, 3072)
	case KeyRSA4096:
		return rsa.GenerateKey(rand.Reader, 4096)
	}
	return nil, fmt.Errorf("unsupported key type %q (use %s)", keyType, strings.Join(KeyTypes, ", "))
}

func keyTypeOf(pub crypto.PublicKey) string {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		return "ecdsa-" + strings.ToLower(strings.ReplaceAll(k.Curve.Params().Name, "-", ""))
	case *rsa.PublicKey:
		return fmt.Sprintf("rsa-%d", k.N.BitLen())
	}
	return fmt.Sprintf("%T", pub)
}

// SerialHex formats a serial number as lowercase hex.
func SerialHex(n *big.Int) string { return hex.EncodeToString(n.Bytes()) }

// NormalizeSerial accepts hex serials with or without colons, any case.
func NormalizeSerial(s string) string {
	return strings.TrimLeft(strings.ToLower(strings.ReplaceAll(strings.TrimPrefix(s, "0x"), ":", "")), "0")
}

func newSerial() (*big.Int, error) {
	// 127 bits keeps the DER encoding positive and within 16 bytes.
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return nil, err
	}
	return n.Add(n, big.NewInt(1)), nil
}

func sign(tmpl, parent *x509.Certificate, pub crypto.PublicKey, key crypto.Signer) (*x509.Certificate, error) {
	if tmpl.SerialNumber == nil {
		s, err := newSerial()
		if err != nil {
			return nil, err
		}
		tmpl.SerialNumber = s
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, key)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

// CertPEM encodes a certificate as PEM.
func CertPEM(c *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
}

// KeyPEM encodes a private key as PKCS#8 PEM.
func KeyPEM(k crypto.Signer) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// ParseCertsPEM parses every CERTIFICATE block in b.
func ParseCertsPEM(b []byte) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	for {
		var blk *pem.Block
		blk, b = pem.Decode(b)
		if blk == nil {
			break
		}
		if blk.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	if len(out) == 0 {
		return nil, errors.New("no PEM certificates found")
	}
	return out, nil
}

func storePair(st Store, certName, keyName string, c *x509.Certificate, k crypto.Signer) error {
	kp, err := KeyPEM(k)
	if err != nil {
		return err
	}
	if err := st.Set(keyName, string(kp)); err != nil {
		return err
	}
	return st.Set(certName, string(CertPEM(c)))
}

func loadPair(st Store, certName, keyName string) (*x509.Certificate, crypto.Signer, error) {
	cp, ok1 := st.Get(certName)
	kp, ok2 := st.Get(keyName)
	if !ok1 || !ok2 {
		return nil, nil, fmt.Errorf("origin CA secret %s/%s is missing", certName, keyName)
	}
	certs, err := ParseCertsPEM([]byte(cp))
	if err != nil {
		return nil, nil, fmt.Errorf("%s: %w", certName, err)
	}
	b, _ := pem.Decode([]byte(kp))
	if b == nil {
		return nil, nil, fmt.Errorf("%s: not PEM", keyName)
	}
	k, err := x509.ParsePKCS8PrivateKey(b.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("%s: %w", keyName, err)
	}
	s, ok := k.(crypto.Signer)
	if !ok {
		return nil, nil, fmt.Errorf("%s: unsupported key", keyName)
	}
	return certs[0], s, nil
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

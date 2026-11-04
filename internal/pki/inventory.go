// SPDX-License-Identifier: Apache-2.0

package pki

import (
	"bytes"
	"crypto/x509"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// InventoryFile is the git-tracked Origin CA inventory in the config dir.
const InventoryFile = "pki-inventory.yaml"

const inventoryHeader = "# Origin CA inventory, managed by ingressd (ingressd cert origin ...).\n" +
	"# Certificates and serials only: private keys are never stored here.\n"

// Inventory records the CA and every origin certificate it has issued.
type Inventory struct {
	CA           CAInfo   `yaml:"ca"`
	Certificates []Record `yaml:"certificates"`
}

// CAInfo describes the current CA certificates.
type CAInfo struct {
	Root         *CertInfo `yaml:"root,omitempty"`
	OriginIssuer *CertInfo `yaml:"origin_issuer,omitempty"`
	ClientIssuer *CertInfo `yaml:"client_issuer,omitempty"`
	EdgeClient   *CertInfo `yaml:"edge_client,omitempty"`
	// RetiredIssuers are origin issuers replaced by revoke --rotate; the edge
	// no longer trusts certificates they signed.
	RetiredIssuers []CertInfo `yaml:"retired_issuers,omitempty"`
}

type CertInfo struct {
	Serial    string    `yaml:"serial"`
	Subject   string    `yaml:"subject"`
	NotBefore time.Time `yaml:"not_before"`
	NotAfter  time.Time `yaml:"not_after"`
}

// Record is one issued origin certificate.
type Record struct {
	Serial    string     `yaml:"serial"`
	SANs      []string   `yaml:"sans"`
	KeyType   string     `yaml:"key_type"`
	NotBefore time.Time  `yaml:"not_before"`
	NotAfter  time.Time  `yaml:"not_after"`
	IssuedBy  string     `yaml:"issued_by"` // issuer serial
	IssuedAt  time.Time  `yaml:"issued_at"`
	Revoked   bool       `yaml:"revoked,omitempty"`
	RevokedAt *time.Time `yaml:"revoked_at,omitempty"`
}

// Status is "active", "revoked", "expired" or "untrusted" (signed by a
// retired issuer).
func (r Record) Status(inv *Inventory, now time.Time) string {
	switch {
	case r.Revoked:
		return "revoked"
	case now.After(r.NotAfter):
		return "expired"
	case inv.CA.OriginIssuer != nil && r.IssuedBy != inv.CA.OriginIssuer.Serial:
		return "untrusted"
	}
	return "active"
}

func certInfo(c *x509.Certificate) *CertInfo {
	if c == nil {
		return nil
	}
	return &CertInfo{
		Serial:    SerialHex(c.SerialNumber),
		Subject:   c.Subject.CommonName,
		NotBefore: c.NotBefore.UTC().Truncate(time.Second),
		NotAfter:  c.NotAfter.UTC().Truncate(time.Second),
	}
}

// LoadInventory reads the inventory from configDir; a missing file yields an
// empty inventory.
func LoadInventory(configDir string) (*Inventory, error) {
	inv := &Inventory{}
	b, err := os.ReadFile(filepath.Join(configDir, InventoryFile))
	if errors.Is(err, fs.ErrNotExist) {
		return inv, nil
	}
	if err != nil {
		return nil, err
	}
	if err := yaml.Unmarshal(b, inv); err != nil {
		return nil, fmt.Errorf("parse %s: %w", InventoryFile, err)
	}
	return inv, nil
}

// Save writes the inventory to configDir.
func (inv *Inventory) Save(configDir string) error {
	var buf bytes.Buffer
	buf.WriteString(inventoryHeader)
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(inv); err != nil {
		return err
	}
	p := filepath.Join(configDir, InventoryFile)
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, buf.Bytes(), 0o640); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

// SyncCA updates the CA section from ca, moving a replaced origin issuer to
// RetiredIssuers. It reports whether anything changed.
func (inv *Inventory) SyncCA(ca *CA) bool {
	next := CAInfo{
		Root:           certInfo(ca.Root),
		OriginIssuer:   certInfo(ca.Origin),
		ClientIssuer:   certInfo(ca.ClientCA),
		EdgeClient:     certInfo(ca.EdgeClient),
		RetiredIssuers: inv.CA.RetiredIssuers,
	}
	if old := inv.CA.OriginIssuer; old != nil && old.Serial != next.OriginIssuer.Serial &&
		(inv.CA.Root == nil || inv.CA.Root.Serial == next.Root.Serial) {
		next.RetiredIssuers = append(next.RetiredIssuers, *old)
	}
	if inv.CA.Root != nil && inv.CA.Root.Serial != next.Root.Serial {
		next.RetiredIssuers = nil // a new root: the old history is meaningless
	}
	cur, _ := yaml.Marshal(inv.CA)
	nb, _ := yaml.Marshal(next)
	inv.CA = next
	return !bytes.Equal(cur, nb)
}

// Add records an issued certificate.
func (inv *Inventory) Add(i *Issued, now time.Time) Record {
	var sans []string
	sans = append(sans, i.Cert.DNSNames...)
	for _, ip := range i.Cert.IPAddresses {
		sans = append(sans, ip.String())
	}
	r := Record{
		Serial:    SerialHex(i.Cert.SerialNumber),
		SANs:      sans,
		KeyType:   i.KeyType,
		NotBefore: i.Cert.NotBefore.UTC().Truncate(time.Second),
		NotAfter:  i.Cert.NotAfter.UTC().Truncate(time.Second),
		IssuedBy:  SerialHex(i.Issuer.SerialNumber),
		IssuedAt:  now.UTC().Truncate(time.Second),
	}
	inv.Certificates = append(inv.Certificates, r)
	return r
}

// Find returns the record with the given serial (any hex formatting).
func (inv *Inventory) Find(serial string) (*Record, error) {
	want := NormalizeSerial(serial)
	var found *Record
	for i := range inv.Certificates {
		r := &inv.Certificates[i]
		n := NormalizeSerial(r.Serial)
		if n == want {
			return r, nil
		}
		// Allow unambiguous prefixes, like git.
		if len(want) >= 6 && strings.HasPrefix(n, want) {
			if found != nil {
				return nil, fmt.Errorf("serial prefix %q is ambiguous", serial)
			}
			found = r
		}
	}
	if found == nil {
		return nil, fmt.Errorf("no certificate with serial %q in the inventory", serial)
	}
	return found, nil
}

// Revoke marks a certificate revoked.
func (inv *Inventory) Revoke(serial string, now time.Time) (*Record, error) {
	r, err := inv.Find(serial)
	if err != nil {
		return nil, err
	}
	if r.Revoked {
		return r, fmt.Errorf("certificate %s is already revoked", r.Serial)
	}
	t := now.UTC().Truncate(time.Second)
	r.Revoked, r.RevokedAt = true, &t
	return r, nil
}

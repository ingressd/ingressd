// SPDX-License-Identifier: Apache-2.0

package release

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// BuildOptions describe a release when its manifest is generated.
type BuildOptions struct {
	Version      string
	Channel      string // default stable
	MinSupported string
	Security     bool
	NotesURL     string
	PublishedAt  time.Time // default now
}

// BuildManifest hashes every regular file in dir (except the manifest, the
// checksum files and their signatures) into a manifest.
func BuildManifest(dir string, o BuildOptions) (*Manifest, error) {
	m := &Manifest{Version: o.Version, Channel: o.Channel, MinSupported: o.MinSupported, Security: o.Security,
		NotesURL: o.NotesURL, PublishedAt: o.PublishedAt, Assets: map[string]string{}}
	if m.Channel == "" {
		m.Channel = ChannelStable
	}
	if m.PublishedAt.IsZero() {
		m.PublishedAt = time.Now().UTC().Truncate(time.Second)
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	for _, e := range ents {
		name := e.Name()
		if !e.Type().IsRegular() || strings.HasPrefix(name, ".") || skipAsset(name) {
			continue
		}
		sum, err := fileSHA256(filepath.Join(dir, name))
		if err != nil {
			return nil, err
		}
		m.Assets[name] = sum
	}
	return m, m.Validate()
}

func skipAsset(name string) bool {
	switch name {
	case ManifestFile, ManifestSigFile, SumsFile, SumsSigFile:
		return true
	}
	return strings.HasSuffix(name, ".minisig")
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// Encode returns the manifest as written to release.json.
func (m *Manifest) Encode() []byte {
	b, _ := json.MarshalIndent(m, "", "  ")
	return append(b, '\n')
}

// SumsFileContent renders SHA256SUMS ("<sha256>  <name>" per line, sorted)
// for the manifest's assets plus extra files (name → sha256).
func SumsFileContent(sums map[string]string) []byte {
	names := make([]string, 0, len(sums))
	for n := range sums {
		names = append(names, n)
	}
	sort.Strings(names)
	var b strings.Builder
	for _, n := range names {
		fmt.Fprintf(&b, "%s  %s\n", sums[n], n)
	}
	return []byte(b.String())
}

// WriteRelease writes release.json into dir, then SHA256SUMS covering every
// asset and release.json, and, when sk is not nil, both signatures. It is
// what scripts/releasetool and the tests use; CI signs with the minisign
// CLI instead (same files).
func WriteRelease(dir string, m *Manifest, sk *SecretKey) error {
	mb := m.Encode()
	if err := os.WriteFile(filepath.Join(dir, ManifestFile), mb, 0o644); err != nil { //nolint:gosec // G306: published release files (manifest, sums, signatures)
		return err
	}
	sums := map[string]string{}
	for n, s := range m.Assets {
		sums[n] = s
	}
	h := sha256.Sum256(mb)
	sums[ManifestFile] = hex.EncodeToString(h[:])
	sb := SumsFileContent(sums)
	if err := os.WriteFile(filepath.Join(dir, SumsFile), sb, 0o644); err != nil { //nolint:gosec // G306: published release files (manifest, sums, signatures)
		return err
	}
	if sk == nil {
		return nil
	}
	tc := TrustedComment(m.Version)
	if err := os.WriteFile(filepath.Join(dir, ManifestSigFile), sk.Sign(mb, tc), 0o644); err != nil { //nolint:gosec // G306: published release files (manifest, sums, signatures)
		return err
	}
	return os.WriteFile(filepath.Join(dir, SumsSigFile), sk.Sign(sb, tc), 0o644) //nolint:gosec // G306: published release files (manifest, sums, signatures)
}

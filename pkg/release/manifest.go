// SPDX-License-Identifier: Apache-2.0

package release

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Release asset names next to the binaries.
const (
	ManifestFile    = "release.json"
	ManifestSigFile = "release.json.minisig"
	SumsFile        = "SHA256SUMS"
	SumsSigFile     = "SHA256SUMS.minisig"
)

// Channels.
const ChannelStable = "stable"

// GitHubRepo is the project's release repository.
const GitHubRepo = "ingressd/ingressd"

// GitHubDownloadBase returns the asset base URL of a GitHub release.
func GitHubDownloadBase(repo, version string) string {
	if repo == "" {
		repo = GitHubRepo
	}
	return "https://github.com/" + repo + "/releases/download/" + version
}

// Manifest is release.json, published (and minisign-signed as
// release.json.minisig) with every release. Assets maps each release file
// name to its SHA-256 (hex), so a verified manifest alone is enough to
// verify any binary of the release.
type Manifest struct {
	Version     string    `json:"version"`
	PublishedAt time.Time `json:"published_at"`
	Channel     string    `json:"channel"`
	// MinSupported is the oldest version still supported: older
	// installations must update, and nodes refuse to install anything
	// below it.
	MinSupported string `json:"min_supported,omitempty"`
	// Security marks a release that fixes a security issue (orgs with the
	// "security only" update policy install it automatically).
	Security bool              `json:"security"`
	NotesURL string            `json:"notes_url,omitempty"`
	Assets   map[string]string `json:"assets"`
}

// Validate checks the fields a consumer relies on.
func (m *Manifest) Validate() error {
	if _, ok := Parse(m.Version); !ok {
		return fmt.Errorf("manifest: version %q is not a release version", m.Version)
	}
	if m.Channel == "" {
		return errors.New("manifest: channel is empty")
	}
	if m.MinSupported != "" {
		if _, ok := Parse(m.MinSupported); !ok {
			return fmt.Errorf("manifest: min_supported %q is not a release version", m.MinSupported)
		}
	}
	if len(m.Assets) == 0 {
		return errors.New("manifest: no assets")
	}
	for name, sum := range m.Assets {
		if name == "" || strings.ContainsAny(name, `/\`) || strings.HasPrefix(name, ".") {
			return fmt.Errorf("manifest: bad asset name %q", name)
		}
		if b, err := hex.DecodeString(sum); err != nil || len(b) != 32 {
			return fmt.Errorf("manifest: bad sha256 for %s", name)
		}
	}
	return nil
}

// Asset returns the SHA-256 of a release file.
func (m *Manifest) Asset(name string) (string, bool) {
	s, ok := m.Assets[name]
	return strings.ToLower(s), ok
}

// Supports reports whether version is at or above MinSupported (true when
// either is not comparable).
func (m *Manifest) Supports(version string) bool {
	if m.MinSupported == "" {
		return true
	}
	c, ok := CompareStrings(version, m.MinSupported)
	return !ok || c >= 0
}

// TrustedComment is what release signatures carry as trusted comment.
func TrustedComment(version string) string { return "ingressd " + version }

// VerifyManifest checks a release.json signature against the minisign
// public key and returns the parsed, validated manifest. A placeholder key
// (no signing key configured yet) never verifies anything.
func VerifyManifest(publicKey string, manifest, sig []byte) (*Manifest, error) {
	if IsPlaceholderKey(publicKey) {
		return nil, ErrNoSigningKey
	}
	if len(sig) == 0 {
		return nil, errors.New("release manifest is not signed")
	}
	pk, err := ParsePublicKey(publicKey)
	if err != nil {
		return nil, err
	}
	if _, err := pk.Verify(manifest, sig); err != nil {
		return nil, fmt.Errorf("release manifest signature: %w", err)
	}
	var m Manifest
	if err := json.Unmarshal(manifest, &m); err != nil {
		return nil, fmt.Errorf("release manifest: %w", err)
	}
	if err := m.Validate(); err != nil {
		return nil, err
	}
	return &m, nil
}

// SPDX-License-Identifier: Apache-2.0

package release

import (
	"errors"
	"os"
	"strings"
)

// ReleasePublicKey is the minisign public key that signs releases
// (release.json and SHA256SUMS): the ingressd release key, key ID
// 9CAEBE74F1A98BC2. Rotating it: see "Release signing key" in
// docs/CI-SECURITY.md.
const ReleasePublicKey = "RWTCi6nxdL6unHcK5KWP/DTr/NFJSt1EEN48LJTlNVJHGkPs9/Ax00gl"

// PlaceholderPublicKey is the key shipped before a signing key existed (no
// known private key). Builds still trusting it verify nothing: the panel
// reports "release signing key not configured", nodes refuse remote updates
// and connectors never self-update; they need one manual update.
const PlaceholderPublicKey = placeholderPublicKey

const placeholderPublicKey = "RWQqa1S8C4VC8rwtwCjF3oAV2CwXczCHK6/39M880TWSYWJj0cgePXQt"

// PublicKeyEnv overrides the built-in key (self-built releases signed with
// your own key, and tests). Whoever can set a service's environment is
// root on that machine anyway.
const PublicKeyEnv = "INGRESSD_RELEASE_PUBLIC_KEY"

// ErrNoSigningKey: the trusted key is still the placeholder.
var ErrNoSigningKey = errors.New("no release signing key is configured (the built-in key is a placeholder): releases cannot be verified")

// TrustedPublicKey returns the key releases are verified with: the
// PublicKeyEnv override, else ReleasePublicKey.
func TrustedPublicKey() string {
	if k := strings.TrimSpace(os.Getenv(PublicKeyEnv)); k != "" {
		return k
	}
	return ReleasePublicKey
}

// VerifySums checks a release's SHA256SUMS against its minisign signature
// (SHA256SUMS.minisig) with TrustedPublicKey and returns the trusted
// comment. The installers call it through the binaries' hidden
// `verify-sums` command when the minisign CLI is not installed.
func VerifySums(sums, sig []byte) (string, error) {
	key := TrustedPublicKey()
	if IsPlaceholderKey(key) {
		return "", ErrNoSigningKey
	}
	pk, err := ParsePublicKey(key)
	if err != nil {
		return "", err
	}
	return pk.Verify(sums, sig)
}

// IsPlaceholderKey reports whether key is the placeholder (or empty).
func IsPlaceholderKey(key string) bool {
	key = strings.TrimSpace(key)
	return key == "" || strings.Contains(key, placeholderPublicKey)
}

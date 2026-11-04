// SPDX-License-Identifier: Apache-2.0

package upgrade

import "github.com/ingressd/ingressd/pkg/release"

// Minisign verification lives in pkg/release (shared with the panel and
// the connector); these aliases keep this package's API.
type PublicKey = release.PublicKey

// ParsePublicKey parses a minisign public key.
func ParsePublicKey(s string) (PublicKey, error) { return release.ParsePublicKey(s) }

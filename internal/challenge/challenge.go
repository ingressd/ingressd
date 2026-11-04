// SPDX-License-Identifier: Apache-2.0

// Package challenge manages the control-plane side of the bot challenge
// (edge_challenge): the HMAC key that signs challenge tokens and clearance
// cookies.
package challenge

import (
	"crypto/rand"
	"encoding/hex"

	"github.com/ingressd/ingressd/internal/secrets"
	"github.com/ingressd/ingressd/pkg/config"
)

// EnsureKey generates the challenge HMAC key in the secrets store if any app
// needs the bot challenge and the key does not exist yet. It reports whether
// the store changed (and must be saved).
func EnsureKey(cfg *config.Config, st *secrets.Store) (bool, error) {
	if _, ok := st.Get(config.ChallengeKeySecret); ok {
		return false, nil
	}
	needed := false
	for _, a := range cfg.Apps {
		needed = needed || cfg.NeedsChallenge(a)
	}
	if !needed {
		return false, nil
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return false, err
	}
	return true, st.Set(config.ChallengeKeySecret, hex.EncodeToString(b))
}

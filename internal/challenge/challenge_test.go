// SPDX-License-Identifier: Apache-2.0

package challenge

import (
	"testing"

	"github.com/ingressd/ingressd/internal/secrets"
	"github.com/ingressd/ingressd/pkg/config"
)

func TestEnsureKey(t *testing.T) {
	cfg := &config.Config{Apps: map[string]config.App{"web": {}}}
	st := secrets.NewMemory(nil)
	if changed, err := EnsureKey(cfg, st); err != nil || changed {
		t.Fatalf("no challenge configured: changed=%v err=%v", changed, err)
	}
	cfg.Apps["web"] = config.App{BotChallenge: &config.BotChallenge{Mode: config.ChallengeAlways}}
	changed, err := EnsureKey(cfg, st)
	if err != nil || !changed {
		t.Fatalf("first ensure: changed=%v err=%v", changed, err)
	}
	k, _ := st.Get(config.ChallengeKeySecret)
	if len(k) != 64 {
		t.Fatalf("key = %q, want 64 hex chars", k)
	}
	if changed, _ := EnsureKey(cfg, st); changed {
		t.Fatal("second ensure changed the store")
	}
}

// SPDX-License-Identifier: Apache-2.0

package nodeagent

import (
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/ingressd/ingressd/internal/connector"
	"github.com/ingressd/ingressd/internal/secrets"
	"github.com/ingressd/ingressd/internal/tunnel"
	"github.com/ingressd/ingressd/pkg/config"
)

// edgePublicKeys returns this node's WireGuard public key per tunnel, read
// from the secrets store (keys not generated yet are missing).
func (a *Agent) edgePublicKeys(cfg *config.Config) map[string]string {
	out := map[string]string{}
	if a.o.Pipeline == nil {
		return out
	}
	_ = a.o.Pipeline.WithSecrets(func(st *secrets.Store) error {
		for name := range cfg.Tunnels {
			if v, ok := st.Get(tunnel.EdgeKeyName(name)); ok {
				if k, err := wgtypes.ParseKey(v); err == nil {
					out[name] = k.PublicKey().String()
				}
			}
		}
		return nil
	})
	return out
}

// connectorKey is the connector public key this node accepts for a tunnel:
// the one enrolled here, else the configured public_key.
func connectorKey(cfg *config.Config, cs *connector.State, name string) string {
	if cs != nil {
		if c := cs.Connectors[name]; c != nil && c.PublicKey != "" {
			return c.PublicKey
		}
	}
	return cfg.Tunnels[name].PublicKey
}

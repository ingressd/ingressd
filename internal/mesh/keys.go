// SPDX-License-Identifier: Apache-2.0

// Package mesh runs the node side of the org mesh: the ix-mesh WireGuard
// interface is rendered and applied by the normal pipeline (see
// internal/render/smartdns.go); this package owns the mesh key, the mesh
// HTTP API (reachable only from mesh peers), peer health probing and status.
package mesh

import (
	"fmt"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/ingressd/ingressd/internal/secrets"
	"github.com/ingressd/ingressd/pkg/config"
)

// EnsureKey generates the mesh private key (secret wg-mesh-node) if it is
// missing and reports whether the store changed. The node agent calls it
// before hello (to send the public key); the apply pipeline calls it when a
// mesh is configured.
func EnsureKey(st *secrets.Store) (bool, error) {
	if _, ok := st.Get(config.MeshKeySecret); ok {
		return false, nil
	}
	k, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return false, err
	}
	return true, st.Set(config.MeshKeySecret, k.String())
}

// PublicKey returns the mesh public key, or an error if no key exists yet.
func PublicKey(st *secrets.Store) (string, error) {
	v, ok := st.Get(config.MeshKeySecret)
	if !ok {
		return "", fmt.Errorf("mesh key %s is missing", config.MeshKeySecret)
	}
	k, err := wgtypes.ParseKey(v)
	if err != nil {
		return "", fmt.Errorf("mesh key: %w", err)
	}
	return k.PublicKey().String(), nil
}

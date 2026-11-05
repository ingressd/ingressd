// SPDX-License-Identifier: Apache-2.0

package smartdns

import (
	"fmt"

	"github.com/ingressd/ingressd/internal/mesh"
	"github.com/ingressd/ingressd/internal/render"
	"github.com/ingressd/ingressd/internal/secrets"
	"github.com/ingressd/ingressd/internal/smartdns/wgconf"
	"github.com/ingressd/ingressd/pkg/config"
)

// Prepare creates what rendering the mesh and VPN exits needs (apply
// pipeline, before render): the mesh key, and the keys of each VPN exit's
// .conf stored as their own secrets so plan diffs redact them. It reports
// whether st changed.
func Prepare(cfg *config.Config, st *secrets.Store) (bool, error) {
	changed := false
	if cfg.Mesh != nil {
		ch, err := mesh.EnsureKey(st)
		if err != nil {
			return false, err
		}
		changed = ch
	}
	set := func(name, v string) error {
		if old, ok := st.Get(name); ok && old == v {
			return nil
		}
		changed = true
		return st.Set(name, v)
	}
	for _, name := range cfg.VPNExits() {
		e, _, _ := cfg.SmartDNSExit(name)
		ref := e.VPN
		text, err := st.Resolve(ref)
		if err != nil {
			return changed, fmt.Errorf("smartdns.exits.%s.vpn: %w", name, err)
		}
		wc, err := wgconf.Parse(text)
		if err != nil {
			return changed, fmt.Errorf("smartdns.exits.%s.vpn (%s): %w", name, ref, err)
		}
		if err := set(render.VPNKeySecret(name), wc.PrivateKey); err != nil {
			return changed, err
		}
		if wc.Peer.PresharedKey != "" {
			if err := set(render.VPNPSKSecret(name), wc.Peer.PresharedKey); err != nil {
				return changed, err
			}
		}
	}
	return changed, nil
}

// SPDX-License-Identifier: Apache-2.0

package render

import (
	"cmp"
	"slices"

	"github.com/ingressd/ingressd/pkg/config"
)

// OriginTarget is one active origin of an app as the edge reaches it: the
// same dial address the rendered reverse_proxy uses (tunnel remapping
// applied), so control-plane clients such as the crawler bypass the public
// edge but still go through the tunnel.
type OriginTarget struct {
	Name   string
	Dial   string // host:port
	Scheme string // http or https
}

// OriginTargets lists an app's active origins, in priority order.
func OriginTargets(cfg *config.Config, app config.App) ([]OriginTarget, error) {
	pool := poolFor(cfg, app)
	var origins []config.Origin
	for _, o := range pool.Origins {
		if o.State == config.OriginActive {
			origins = append(origins, o)
		}
	}
	slices.SortStableFunc(origins, func(a, b config.Origin) int { return cmp.Compare(a.Priority, b.Priority) })
	var out []OriginTarget
	for _, o := range origins {
		dial, scheme, err := dialAddress(cfg, o)
		if err != nil {
			return nil, err
		}
		out = append(out, OriginTarget{Name: o.Name, Dial: dial, Scheme: scheme})
	}
	return out, nil
}

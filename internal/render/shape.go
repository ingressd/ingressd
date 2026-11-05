// SPDX-License-Identifier: Apache-2.0

package render

import "github.com/ingressd/ingressd/pkg/config"

// Shape caps one realm's bandwidth on this node (realms.<r>.shape). The
// ingress of each of the realm's tunnels (origin to edge: what the edge
// will serve) is redirected to the realm's IFB, whose HTB class holds the
// whole realm to the rate. Egress into each tunnel (edge to origin) gets its
// own HTB at the same rate: a per-tunnel cap rather than a per-realm one,
// since that direction is small for typical sites.
type Shape struct {
	Realm    string   `json:"realm"`
	IFB      string   `json:"ifb"`
	RateMbit int      `json:"rate_mbit"`
	Tunnels  []string `json:"tunnels"`
}

func renderShapes(cfg *config.Config) []Shape {
	var out []Shape
	for _, name := range sortedKeys(cfg.Realms) {
		r := cfg.Realms[name]
		if r.Shape == nil {
			continue
		}
		var ifs []string
		for _, t := range cfg.RealmTunnels(name) {
			ifs = append(ifs, config.InterfaceName(t))
		}
		if len(ifs) == 0 {
			continue
		}
		out = append(out, Shape{Realm: name, IFB: config.RealmIFBName(name), RateMbit: r.Shape.RateMbit, Tunnels: ifs})
	}
	return out
}

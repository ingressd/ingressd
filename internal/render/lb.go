// SPDX-License-Identifier: Apache-2.0

package render

import (
	"time"

	"github.com/ingressd/ingressd/pkg/config"
)

// DialAddress returns host:port for an origin as reached from the edge (the
// virtual address for remapped tunnels) and the origin's scheme. Health
// checks use it so they probe exactly what Caddy dials.
func DialAddress(cfg *config.Config, o config.Origin) (dial, scheme string, err error) {
	return dialAddress(cfg, o)
}

// proxiedOrigins returns the origins to render as upstreams. Named pools
// keep draining origins (edge_tiered serves their existing sticky sessions
// but gives them no new ones); the single-origin shorthand has no state.
func proxiedOrigins(app config.App, pool config.Pool) []config.Origin {
	var out []config.Origin
	for _, o := range pool.Origins {
		if o.State == config.OriginActive || (app.Pool != "" && o.State == config.OriginDraining) {
			out = append(out, o)
		}
	}
	return out
}

// tieredSelection is the edge_tiered selection policy for a named pool:
// priority tiers, steering within a tier, stickiness, and runtime health,
// drain and override state from the edge_state app (pushed by
// internal/health). Upstream metadata is matched by dial address.
func tieredSelection(cfg *config.Config, name string, pool config.Pool, origins []config.Origin) (obj, error) {
	var ups []obj
	for _, o := range origins {
		dial, _, err := dialAddress(cfg, o)
		if err != nil {
			return nil, err
		}
		u := obj{"dial": dial, "origin": o.Name, "priority": o.Priority, "weight": o.Weight}
		if o.State != config.OriginActive {
			u["state"] = o.State
		}
		ups = append(ups, u)
	}
	sel := obj{"policy": "edge_tiered", "pool": name, "steering": pool.Steering, "upstreams": ups}
	if s := pool.Sticky; s != nil {
		st := obj{"cookie": s.Cookie}
		if s.TTL > 0 {
			st["ttl"] = time.Duration(s.TTL).String()
		}
		sel["sticky"] = st
	}
	return sel, nil
}

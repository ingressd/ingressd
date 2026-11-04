// SPDX-License-Identifier: Apache-2.0

package observe

import (
	"time"

	"github.com/ingressd/ingressd/internal/tunnel"
	"github.com/ingressd/ingressd/pkg/config"
)

// TunnelCollector exports WireGuard state for every configured tunnel.
// cfg returns the current config (nil before the first apply).
func TunnelCollector(cfg func() *config.Config) Collector {
	return func(x *Exposition) {
		c := cfg()
		if c == nil || len(c.Tunnels) == 0 {
			return
		}
		sts, err := tunnel.ReadStatus(c)
		if err != nil {
			return
		}
		now := time.Now()
		for _, s := range sts {
			up := 0.0
			if s.Healthy(now) {
				up = 1
			}
			x.Gauge("ingressd_tunnel_up", "1 if the tunnel had a recent handshake.", up, "tunnel", s.Tunnel)
			if !s.LastHandshake.IsZero() {
				x.Gauge("ingressd_tunnel_handshake_age_seconds", "Seconds since the last WireGuard handshake.",
					now.Sub(s.LastHandshake).Seconds(), "tunnel", s.Tunnel)
			}
			x.Counter("ingressd_tunnel_receive_bytes_total", "Bytes received from the site.", float64(s.RxBytes), "tunnel", s.Tunnel)
			x.Counter("ingressd_tunnel_transmit_bytes_total", "Bytes sent to the site.", float64(s.TxBytes), "tunnel", s.Tunnel)
		}
	}
}

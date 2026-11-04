// SPDX-License-Identifier: Apache-2.0

package render

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/ingressd/ingressd/internal/connector/proto"
	"github.com/ingressd/ingressd/pkg/config"
)

// connectorInputRules admits the connector control port (plain HTTP,
// authenticated by WireGuard) from each connector tunnel's site address to
// its edge address, on that tunnel's interface only.
func connectorInputRules(cfg *config.Config) string {
	var b strings.Builder
	for _, name := range sortedKeys(cfg.Tunnels) {
		t := cfg.Tunnels[name]
		if t.Site != config.SiteConnector {
			continue
		}
		p, err := netip.ParsePrefix(t.Transit)
		if err != nil {
			continue
		}
		fmt.Fprintf(&b, "\t\tiifname %q ip saddr %s ip daddr %s tcp dport %d accept\n",
			config.InterfaceName(name), SiteAddr(p), EdgeAddr(p), proto.TunnelControlPort)
	}
	return b.String()
}

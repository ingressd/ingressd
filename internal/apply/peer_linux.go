// SPDX-License-Identifier: Apache-2.0

//go:build linux

package apply

import (
	"net"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/ingressd/ingressd/internal/render"
)

// meshPeerExtras sets the fields only mesh and VPN peers use: a configured
// endpoint (resolved now; an unresolvable hostname is skipped so the peer
// can still reach us), keepalive and preshared key.
func meshPeerExtras(pc *wgtypes.PeerConfig, p render.Peer) error {
	if p.Endpoint != "" {
		// Prefer IPv4 (most nodes have it); an IPv6-only endpoint still
		// works on a dual-stack node. VPN exits re-resolve names at
		// runtime too (smartdns endpoint refresh).
		if ua, err := net.ResolveUDPAddr("udp4", p.Endpoint); err == nil {
			pc.Endpoint = ua
		} else if ua, err := net.ResolveUDPAddr("udp", p.Endpoint); err == nil {
			pc.Endpoint = ua
		}
	}
	if p.Keepalive > 0 {
		ka := time.Duration(p.Keepalive) * time.Second
		pc.PersistentKeepaliveInterval = &ka
	}
	if p.PresharedKey != "" {
		k, err := wgtypes.ParseKey(p.PresharedKey)
		if err != nil {
			return err
		}
		pc.PresharedKey = &k
	}
	return nil
}

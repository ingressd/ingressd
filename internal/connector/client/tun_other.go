// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package client

import (
	"errors"
	"log/slog"
	"net/netip"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// DefaultInterface is the TUN-mode interface name.
const DefaultInterface = "ingressd0"

func openTUN(*State, wgtypes.Key, *slog.Logger) (link, error) {
	return nil, errors.New("tun mode is only supported on Linux; use --mode netstack")
}

func probeMTU(l link, _ netip.Addr, _ *slog.Logger) int { return l.MTU() }

func reapplyNFT(*State, int, *slog.Logger) {}

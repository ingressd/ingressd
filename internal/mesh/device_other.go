// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package mesh

import (
	"errors"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// WGDevice is only supported on Linux.
func WGDevice(string) (*wgtypes.Device, error) {
	return nil, errors.New("WireGuard status needs Linux")
}

// WGConfigure is only supported on Linux.
func WGConfigure(string, wgtypes.Config) error {
	return errors.New("WireGuard configuration needs Linux")
}

// SPDX-License-Identifier: Apache-2.0

//go:build linux

package mesh

import (
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// WGDevice reads a WireGuard interface's state through wgctrl.
func WGDevice(name string) (*wgtypes.Device, error) {
	c, err := wgctrl.New()
	if err != nil {
		return nil, err
	}
	defer c.Close()
	return c.Device(name)
}

// WGConfigure changes a WireGuard interface through wgctrl.
func WGConfigure(name string, cfg wgtypes.Config) error {
	c, err := wgctrl.New()
	if err != nil {
		return err
	}
	defer c.Close()
	return c.ConfigureDevice(name, cfg)
}

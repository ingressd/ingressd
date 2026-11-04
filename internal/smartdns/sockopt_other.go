// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package smartdns

import (
	"errors"
	"syscall"
)

// egressControl: VPN egress needs Linux (SO_MARK, SO_BINDTODEVICE).
func egressControl(ifname string, _ int) func(network, address string, c syscall.RawConn) error {
	if ifname == "" {
		return nil
	}
	return func(string, string, syscall.RawConn) error { return errors.New("VPN egress needs Linux") }
}

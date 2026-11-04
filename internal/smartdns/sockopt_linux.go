// SPDX-License-Identifier: Apache-2.0

//go:build linux

package smartdns

import (
	"syscall"

	"golang.org/x/sys/unix"
)

// egressControl returns a dialer Control function that marks sockets with
// mark (selecting the VPN routing table) and binds them to ifname, so they
// can only ever leave through the VPN interface: if the interface or its
// routes are gone, connecting fails instead of using the main route.
func egressControl(ifname string, mark int) func(network, address string, c syscall.RawConn) error {
	if ifname == "" {
		return nil
	}
	return func(_, _ string, c syscall.RawConn) error {
		var serr error
		err := c.Control(func(fd uintptr) {
			if serr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, mark); serr != nil {
				return
			}
			serr = unix.BindToDevice(int(fd), ifname)
		})
		if err != nil {
			return err
		}
		return serr
	}
}

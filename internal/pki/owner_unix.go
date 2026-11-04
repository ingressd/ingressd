// SPDX-License-Identifier: Apache-2.0

//go:build unix

package pki

import (
	"errors"
	"io/fs"
	"os"
	"syscall"
)

// copyOwner gives dst the owner and group of ref, if ref exists and we are
// allowed to (root). The edge runs as its own user and must read dst.
func copyOwner(ref, dst string) error {
	fi, err := os.Stat(ref)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || os.Geteuid() != 0 {
		return nil
	}
	return os.Chown(dst, int(st.Uid), int(st.Gid))
}

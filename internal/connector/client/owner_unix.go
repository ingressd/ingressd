// SPDX-License-Identifier: Apache-2.0

//go:build unix

package client

import (
	"errors"
	"io/fs"
	"os"
	"syscall"
)

// matchOwner gives path the owner of like, when run as root.
func matchOwner(path, like string) error {
	if os.Geteuid() != 0 {
		return nil
	}
	fi, err := os.Stat(like)
	if errors.Is(err, fs.ErrNotExist) {
		return nil // enrolling: the state file is written next
	}
	if err != nil {
		return err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}
	return os.Chown(path, int(st.Uid), int(st.Gid))
}

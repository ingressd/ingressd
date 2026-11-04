// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package controlsrv

import (
	"fmt"
	"io/fs"
	"os"
)

// shareSocket is the portable fallback for development builds: the control
// plane only runs on Linux (see share_linux.go). It refuses symlinks, but
// cannot close the race between the check and the change. (Windows does not
// report AF_UNIX socket files as fs.ModeSocket, so the type is not checked.)
func shareSocket(path string, gid int) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if fi.Mode()&(fs.ModeSymlink|fs.ModeDir) != 0 {
		return fmt.Errorf("%s is not a socket", path)
	}
	if err := os.Chmod(path, 0o660); err != nil {
		return err
	}
	if gid < 0 {
		return nil
	}
	return os.Lchown(path, -1, gid)
}

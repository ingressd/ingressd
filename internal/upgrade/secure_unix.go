// SPDX-License-Identifier: Apache-2.0

//go:build unix

package upgrade

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

// A state directory may be a symbolic link on Unix (e.g. to a volume); the
// modes and owner checks below follow it.
const linksTrusted = true

// restrict removes group and other access from path when this account
// owns it (a directory or file owned by someone else is left alone: root
// may keep the state on a shared path deliberately).
func restrict(path string, dir bool) error {
	fi, err := os.Stat(path)
	if err != nil {
		return err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || int(st.Uid) != os.Geteuid() || fi.Mode().Perm()&0o077 == 0 {
		return nil
	}
	mode := os.FileMode(0o600)
	if dir {
		mode = 0o700
	}
	return os.Chmod(path, fi.Mode().Perm()&mode)
}

// openTrusted opens path for reading when it is a regular file (not a
// symbolic link) owned by root or this process's user and not writable by
// group or others. The checks use the open file, so they describe the
// file read.
func openTrusted(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	fi, err := f.Stat()
	if err == nil {
		err = trustedFile(path, fi)
	}
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	return f, nil
}

func trustedFile(path string, fi os.FileInfo) error {
	if !fi.Mode().IsRegular() {
		return errors.Join(errUntrusted, fmt.Errorf("%s is not a regular file", path))
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.Join(errUntrusted, fmt.Errorf("%s: no owner", path))
	}
	if st.Uid != 0 && int(st.Uid) != os.Geteuid() {
		return errors.Join(errUntrusted, fmt.Errorf("%s is owned by uid %d, not root or this user", path, st.Uid))
	}
	if fi.Mode().Perm()&0o022 != 0 {
		return errors.Join(errUntrusted, fmt.Errorf("%s is writable by group or others (mode %v)", path, fi.Mode().Perm()))
	}
	return nil
}

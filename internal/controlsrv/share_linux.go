// SPDX-License-Identifier: Apache-2.0

package controlsrv

import (
	"fmt"
	"strconv"

	"golang.org/x/sys/unix"
)

// shareSocket sets mode 0660 and (gid >= 0) the group of the socket at path
// without following symlinks: the entry is opened O_PATH|O_NOFOLLOW, checked
// to be a socket, and changed through that descriptor. A symlink or any other
// file the edge swapped in is refused, so root never chmods or chowns a file
// outside the run directory.
func shareSocket(path string, gid int) error {
	fd, err := unix.Open(path, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	defer unix.Close(fd)
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFSOCK {
		return fmt.Errorf("%s is not a socket", path)
	}
	// fchmod does not work on O_PATH descriptors (and fchmodat ignores
	// AT_SYMLINK_NOFOLLOW before Linux 6.6); /proc/self/fd/N resolves to the
	// inode opened above, not to whatever path names now.
	if err := unix.Chmod("/proc/self/fd/"+strconv.Itoa(fd), 0o660); err != nil {
		return fmt.Errorf("chmod %s: %w", path, err)
	}
	if gid < 0 {
		return nil
	}
	if err := unix.Fchownat(fd, "", -1, gid, unix.AT_EMPTY_PATH); err != nil {
		return fmt.Errorf("chown %s: %w", path, err)
	}
	return nil
}

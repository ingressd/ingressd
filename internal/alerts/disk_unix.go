// SPDX-License-Identifier: Apache-2.0

//go:build unix

package alerts

import "golang.org/x/sys/unix"

// DiskUsage returns free space available to unprivileged users and the
// filesystem size for the filesystem holding path.
func DiskUsage(path string) (Disk, error) {
	var st unix.Statfs_t
	if err := unix.Statfs(path, &st); err != nil {
		return Disk{}, err
	}
	var s unix.Stat_t
	_ = unix.Stat(path, &s)
	return Disk{
		Free:   st.Bavail * uint64(st.Bsize),
		Total:  st.Blocks * uint64(st.Bsize),
		Device: uint64(s.Dev),
	}, nil
}

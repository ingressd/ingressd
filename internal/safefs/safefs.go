// SPDX-License-Identifier: Apache-2.0

// Package safefs reads and writes files in directories that a less trusted
// process can also write, without being redirected by symlinks: root reads
// Caddy's storage (owned by the edge user) and restores config from
// untrusted git bundles.
package safefs

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
)

var (
	// ErrTooLarge is returned by ReadFile for a file over its size limit.
	ErrTooLarge = errors.New("file too large")
	// ErrNotRegular is returned for a symlink, directory, FIFO or device.
	ErrNotRegular = errors.New("not a regular file")
)

// ReadFile reads name below root. The os.Root keeps symlinks from leading
// outside it; anything but a regular file (a FIFO that would block, a
// device) is refused. max > 0 caps the size (ErrTooLarge).
func ReadFile(root *os.Root, name string, max int64) ([]byte, error) {
	f, err := root.OpenFile(name, os.O_RDONLY|oNonblock, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s: %w", name, ErrNotRegular)
	}
	if max <= 0 {
		return io.ReadAll(f)
	}
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, fmt.Errorf("%s: %w", name, ErrTooLarge)
	}
	return b, nil
}

// WriteFile replaces path with data via a temporary file in the same
// directory and a rename. An existing symlink (or other non-regular file)
// at path is refused, and the rename never writes through one that appears
// after the check.
func WriteFile(path string, data []byte, perm fs.FileMode) error {
	if fi, err := os.Lstat(path); err == nil && !fi.Mode().IsRegular() {
		return fmt.Errorf("%s: %w", path, ErrNotRegular)
	} else if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

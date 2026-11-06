// SPDX-License-Identifier: Apache-2.0

package client

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/ingressd/ingressd/internal/upgrade"
)

// Pre-rename names. A connector installed before the rename keeps its
// enrolment: its state moves to the new directory on first start, and
// install-service replaces the old service.
const (
	legacyServiceName = "homeedge-connector"     // legacy homeedge name, remove after 2027-01
	legacyLaunchd     = "com.homeedge.connector" // legacy homeedge name, remove after 2027-01
)

// LegacyStatePath returns where a pre-rename connector kept the state file
// that path now names ("" when path does not use the current directory
// name).
func LegacyStatePath(path string) string {
	dir, file := filepath.Split(path)
	d := filepath.Clean(dir)
	if filepath.Base(d) != ServiceName {
		return ""
	}
	return filepath.Join(filepath.Dir(d), legacyServiceName, file)
}

// MigrateState returns the state path to use. When path does not exist but
// the pre-rename location does, the old state directory's files are moved
// to path's directory; if they cannot be moved (another filesystem, e.g. a
// container volume still mounted at the old path), the old path is used in
// place.
func MigrateState(path string) string {
	if _, err := os.Stat(path); !errors.Is(err, fs.ErrNotExist) {
		return path
	}
	old := LegacyStatePath(path)
	if old == "" {
		return path
	}
	if _, err := os.Stat(old); err != nil {
		return path
	}
	oldDir, newDir := filepath.Dir(old), filepath.Dir(path)
	_ = upgrade.SecureDir(oldDir)
	if err := os.Rename(oldDir, newDir); err == nil {
		return path
	}
	// The new directory may already exist, made by someone else.
	if err := upgrade.SecureDir(newDir); err != nil {
		return old
	}
	ents, err := os.ReadDir(oldDir)
	if err != nil {
		return old
	}
	// Move the state file last: until it moves, the old path stays valid.
	var moved []string
	base := filepath.Base(old)
	for _, e := range ents {
		if e.Name() == base || e.IsDir() {
			continue
		}
		if os.Rename(filepath.Join(oldDir, e.Name()), filepath.Join(newDir, e.Name())) == nil {
			moved = append(moved, e.Name())
		}
	}
	if err := os.Rename(old, path); err != nil {
		for _, n := range moved { // put the rest back so the old path stays whole
			_ = os.Rename(filepath.Join(newDir, n), filepath.Join(oldDir, n))
		}
		return old
	}
	_ = os.Remove(oldDir) // only when empty
	return path
}

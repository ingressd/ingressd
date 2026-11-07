// SPDX-License-Identifier: Apache-2.0

package client

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// A new directory that already exists is made private before the state
// moves into it.
func TestMigrateStateIntoExistingDirectory(t *testing.T) {
	root := t.TempDir()
	oldDir, newDir := filepath.Join(root, legacyServiceName), filepath.Join(root, ServiceName)
	for _, d := range []string{oldDir, newDir} {
		if err := os.Mkdir(d, 0o755); err != nil { //nolint:gosec // mirrors the legacy directory mode
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(oldDir, "connector.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(newDir, "connector.json")
	if got := MigrateState(path); got != path {
		t.Fatalf("got %s", got)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(newDir); err != nil || (runtime.GOOS != "windows" && fi.Mode().Perm()&0o077 != 0) {
		t.Errorf("%v %v", fi.Mode(), err)
	}
}

func TestMigrateState(t *testing.T) {
	root := t.TempDir()
	oldDir := filepath.Join(root, legacyServiceName)
	if err := os.MkdirAll(oldDir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"connector.json", "status.json"} {
		if err := os.WriteFile(filepath.Join(oldDir, f), []byte(f), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	newPath := filepath.Join(root, ServiceName, "connector.json")
	if LegacyStatePath(newPath) != filepath.Join(oldDir, "connector.json") {
		t.Fatalf("legacy path %q", LegacyStatePath(newPath))
	}
	if got := MigrateState(newPath); got != newPath {
		t.Fatalf("MigrateState = %q, want %q", got, newPath)
	}
	for _, f := range []string{"connector.json", "status.json"} {
		if b, err := os.ReadFile(filepath.Join(root, ServiceName, f)); err != nil || string(b) != f {
			t.Fatalf("%s not moved: %v", f, err)
		}
	}
	if _, err := os.Stat(oldDir); err == nil {
		t.Fatal("old directory left behind")
	}
	// Already migrated (or fresh): unchanged.
	if got := MigrateState(newPath); got != newPath {
		t.Fatalf("second MigrateState = %q", got)
	}
	other := filepath.Join(root, "custom", "c.json")
	if got := MigrateState(other); got != other {
		t.Fatalf("custom path changed: %q", got)
	}
}

func TestMigrateStateIntoExistingDir(t *testing.T) {
	root := t.TempDir()
	oldDir := filepath.Join(root, legacyServiceName)
	newDir := filepath.Join(root, ServiceName)
	_ = os.MkdirAll(oldDir, 0o700)
	_ = os.MkdirAll(filepath.Join(newDir, "sub"), 0o700) // not empty: no dir rename
	_ = os.WriteFile(filepath.Join(oldDir, "connector.json"), []byte("x"), 0o600)
	newPath := filepath.Join(newDir, "connector.json")
	if got := MigrateState(newPath); got != newPath {
		t.Fatalf("MigrateState = %q", got)
	}
	if b, _ := os.ReadFile(newPath); string(b) != "x" {
		t.Fatal("state not moved")
	}
}

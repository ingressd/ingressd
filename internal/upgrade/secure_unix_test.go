// SPDX-License-Identifier: Apache-2.0

//go:build unix

package upgrade

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadTrustedPlanUnix(t *testing.T) {
	dir := t.TempDir()
	p := &Plan{ID: "upg_ok", WorkDir: dir, Created: time.Now()}
	path, err := p.Save()
	if err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 {
		t.Fatalf("plan mode %v", fi.Mode().Perm())
	}
	if err := os.Chmod(path, 0o622); err != nil { //nolint:gosec // G302: the test needs a group-writable file
		t.Fatal(err)
	}
	if _, err := LoadTrustedPlan(path); err == nil {
		t.Fatal("group-writable plan accepted")
	}
	_ = os.Chmod(path, 0o600)
	if _, err := LoadTrustedPlan(path); err != nil {
		t.Fatal(err)
	}
	if os.Geteuid() == 0 {
		if err := os.Chown(path, 65534, 65534); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadTrustedPlan(path); err == nil {
			t.Fatal("plan owned by nobody accepted")
		}
	}
}

func TestSecureDirUnix(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	if err := os.MkdirAll(filepath.Join(dir, "upgrade"), 0o755); err != nil {
		t.Fatal(err)
	}
	f := filepath.Join(dir, "connector.json")
	if err := os.WriteFile(f, []byte("{}"), 0o644); err != nil { //nolint:gosec // G306: the test needs a world-readable file
		t.Fatal(err)
	}
	if err := SecureDir(dir); err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]os.FileMode{dir: 0o700, filepath.Join(dir, "upgrade"): 0o700, f: 0o600} {
		if fi, _ := os.Stat(path); fi.Mode().Perm() != want {
			t.Errorf("%s: mode %v, want %v", path, fi.Mode().Perm(), want)
		}
	}
}

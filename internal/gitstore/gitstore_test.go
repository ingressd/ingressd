// SPDX-License-Identifier: Apache-2.0

package gitstore

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestCommitLogShow(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	r := Repo{Dir: t.TempDir()}
	if err := r.Init(); err != nil {
		t.Fatal(err)
	}
	if err := r.Init(); err != nil {
		t.Fatal("second Init:", err)
	}
	if entries, err := r.Log(5); err != nil || len(entries) != 0 {
		t.Fatalf("empty Log = %v, %v", entries, err)
	}

	f := filepath.Join(r.Dir, "config.yaml")
	os.WriteFile(f, []byte("version: 1\n"), 0o600)
	rev1, err := r.Commit("Alex", "first", "config.yaml")
	if err != nil || rev1 == "" {
		t.Fatalf("Commit = %q, %v", rev1, err)
	}
	if rev, err := r.Commit("Alex", "no-op", "config.yaml"); err != nil || rev != "" {
		t.Fatalf("no-op Commit = %q, %v", rev, err)
	}
	os.WriteFile(f, []byte("version: 2\n"), 0o600)
	rev2, err := r.Commit("Sam <sam@example.com>", "second", "config.yaml")
	if err != nil {
		t.Fatal(err)
	}

	entries, err := r.Log(5)
	if err != nil || len(entries) != 2 || entries[0].Subject != "second" || entries[0].Author != "Sam" {
		t.Fatalf("Log = %+v, %v", entries, err)
	}
	old, err := r.Show(rev1, "config.yaml")
	if err != nil || string(old) != "version: 1\n" {
		t.Fatalf("Show = %q, %v", old, err)
	}
	d, err := r.Diff(rev1, rev2, "config.yaml")
	if err != nil || !strings.Contains(d, "+version: 2") {
		t.Fatalf("Diff = %q, %v", d, err)
	}
	if _, err := r.Show("--output=/tmp/x", "config.yaml"); err == nil {
		t.Fatal("accepted option-like revision")
	}
}

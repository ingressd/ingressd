// SPDX-License-Identifier: Apache-2.0

package upgrade

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// A file someone pre-created under the old fixed temporary name is neither
// written into nor renamed into place, and SecureDir removes it once stale.
func TestWriteIgnoresPlantedTemp(t *testing.T) {
	dir := t.TempDir()
	planted := filepath.Join(dir, PlanFile+".tmp")
	if err := os.WriteFile(planted, []byte(`{"id":"evil"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	p := &Plan{ID: "upg_ok", To: "v1.1.0", WorkDir: dir, Created: time.Now()}
	path, err := p.Save()
	if err != nil {
		t.Fatal(err)
	}
	got, err := LoadTrustedPlan(path)
	if err != nil || got.ID != "upg_ok" {
		t.Fatalf("plan = %+v, %v", got, err)
	}
	if b, _ := os.ReadFile(planted); string(b) != `{"id":"evil"}` {
		t.Fatalf("planted temp file was written into: %q", b)
	}
	old := time.Now().Add(-time.Hour)
	_ = os.Chtimes(planted, old, old)
	if err := SecureDir(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(planted); !os.IsNotExist(err) {
		t.Fatalf("stale temp file kept: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("plan removed: %v", err)
	}
	ents, _ := os.ReadDir(dir)
	for _, e := range ents {
		if e.Name() != PlanFile {
			t.Errorf("leftover %s", e.Name())
		}
	}
}

func TestLoadTrustedPlanRefusesLink(t *testing.T) {
	dir := t.TempDir()
	p := &Plan{ID: "upg_ok", WorkDir: dir, Created: time.Now()}
	path, err := p.Save()
	if err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.json")
	if err := os.Symlink(path, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if _, err := LoadTrustedPlan(link); err == nil {
		t.Fatal("plan behind a symbolic link accepted")
	}
}

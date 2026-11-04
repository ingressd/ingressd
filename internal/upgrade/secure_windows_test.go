// SPDX-License-Identifier: Apache-2.0

package upgrade

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// readDACL returns path's DACL entries (SIDs, masks, flags) and whether it
// is protected.
func readDACL(t *testing.T, path string) (map[string]windows.ACCESS_ALLOWED_ACE, bool) {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	ctl, _, err := sd.Control()
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		t.Fatalf("no DACL: %v", err)
	}
	out := map[string]windows.ACCESS_ALLOWED_ACE{}
	for i := range uint32(dacl.AceCount) {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			t.Fatal(err)
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			t.Fatalf("%s: unexpected ACE type %d", path, ace.Header.AceType)
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		out[sid.String()] = *ace
	}
	return out, ctl&windows.SE_DACL_PROTECTED != 0
}

func TestSecureDirWindows(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ingressd-connector")
	// An existing install: a directory and files with inherited ACLs.
	if err := os.MkdirAll(filepath.Join(dir, "upgrade"), 0o700); err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(dir, "connector.json")
	if err := os.WriteFile(state, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := SecureDir(dir); err != nil {
		t.Fatal(err)
	}
	self, err := processUser()
	if err != nil {
		t.Fatal(err)
	}
	system, _ := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	admins, _ := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	want := map[string]bool{system.String(): true, admins.String(): true, self.String(): true}

	// A file created afterwards inherits the directory's DACL.
	later := filepath.Join(dir, "upgrade", PlanFile)
	if err := WriteFileAtomic(later, []byte("{}")); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{dir, filepath.Join(dir, "upgrade"), state, later} {
		aces, protected := readDACL(t, path)
		if path != later && !protected {
			t.Errorf("%s: DACL not protected", path)
		}
		if len(aces) != len(want) {
			t.Errorf("%s: %d ACEs, want %d (%v)", path, len(aces), len(want), aces)
		}
		for sid, ace := range aces {
			if !want[sid] {
				t.Errorf("%s: unexpected ACE for %s", path, sid)
			}
			if ace.Mask&fileAllAccess != fileAllAccess {
				t.Errorf("%s: %s has mask %#x, not full control", path, sid, ace.Mask)
			}
		}
	}
	if _, err := LoadTrustedPlan(later); err != nil {
		t.Fatalf("plan written by this account refused: %v", err)
	}

	// A junction planted below the directory is removed, not followed.
	target := t.TempDir()
	j := filepath.Join(dir, "upgrade", "junction")
	if err := createJunction(j, target); err != nil {
		t.Logf("no junction: %v", err)
	} else {
		if err := SecureDir(dir); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Lstat(j); !os.IsNotExist(err) {
			t.Errorf("junction kept: %v", err)
		}
		if _, err := os.Stat(target); err != nil {
			t.Errorf("junction target removed: %v", err)
		}
	}
}

// fileAllAccess is FILE_ALL_ACCESS ("FA" in SDDL).
const fileAllAccess = 0x1f01ff

func createJunction(link, target string) error {
	out, err := exec.Command("cmd", "/c", "mklink", "/J", link, target).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, out)
	}
	return nil
}

func TestTrustedOwner(t *testing.T) {
	users, _ := windows.CreateWellKnownSid(windows.WinBuiltinUsersSid)
	system, _ := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if trustedOwner(users) {
		t.Error("BUILTIN\\Users trusted as owner")
	}
	if !trustedOwner(system) {
		t.Error("SYSTEM not trusted as owner")
	}
}

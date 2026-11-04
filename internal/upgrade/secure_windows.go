// SPDX-License-Identifier: Apache-2.0

package upgrade

import (
	"errors"
	"fmt"
	"os"
	"sync"

	"golang.org/x/sys/windows"
)

// A state directory must itself be a directory on Windows: a junction or
// symbolic link could point it anywhere.
const linksTrusted = false

var (
	selfOnce sync.Once
	selfSID  *windows.SID
	selfErr  error
)

// processUser is the account this process runs as (SYSTEM for the
// service).
func processUser() (*windows.SID, error) {
	selfOnce.Do(func() {
		u, err := windows.GetCurrentProcessToken().GetTokenUser()
		if err != nil {
			selfErr = err
			return
		}
		selfSID, selfErr = u.User.Sid.Copy()
	})
	return selfSID, selfErr
}

// privateDACL grants full control to SYSTEM, Administrators and the
// account running this process (when it is neither), inherited by
// everything created below a directory. "P" protects it: nothing from
// %ProgramData% (which lets Users read and create) is inherited.
func privateDACL(container bool) (*windows.ACL, error) {
	self, err := processUser()
	if err != nil {
		return nil, err
	}
	flags := ""
	if container {
		flags = "OICI"
	}
	sddl := fmt.Sprintf("D:P(A;%[1]s;FA;;;SY)(A;%[1]s;FA;;;BA)", flags)
	if !self.IsWellKnown(windows.WinLocalSystemSid) && !self.IsWellKnown(windows.WinBuiltinAdministratorsSid) {
		sddl += fmt.Sprintf("(A;%s;FA;;;%s)", flags, self.String())
	}
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return nil, err
	}
	dacl, _, err := sd.DACL()
	return dacl, err
}

// trustedOwner reports whether sid may own a file the helper acts on:
// SYSTEM, Administrators, or the account running this process.
func trustedOwner(sid *windows.SID) bool {
	if sid == nil {
		return false
	}
	if sid.IsWellKnown(windows.WinLocalSystemSid) || sid.IsWellKnown(windows.WinBuiltinAdministratorsSid) {
		return true
	}
	self, err := processUser()
	return err == nil && sid.Equals(self)
}

// restrict replaces path's DACL with privateDACL and, when its owner is
// not trusted (someone pre-created it), takes ownership: an owner can
// always rewrite the DACL.
func restrict(path string, dir bool) error {
	dacl, err := privateDACL(dir)
	if err != nil {
		return err
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		return err
	}
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return err
	}
	if trustedOwner(owner) {
		return nil
	}
	self, err := processUser()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION, self, nil, nil, nil)
}

// openTrusted opens path for reading when it is a regular file (not a
// link) owned by SYSTEM, Administrators or this process's account. The
// owner is read from the open handle, so it describes the file read.
func openTrusted(path string) (*os.File, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	sd, err := windows.GetSecurityInfo(windows.Handle(f.Fd()), windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err == nil {
		var owner *windows.SID
		if owner, _, err = sd.Owner(); err == nil && !trustedOwner(owner) {
			err = fmt.Errorf("%s is owned by %s, not SYSTEM, Administrators or this account", path, sidName(owner))
		}
	}
	if err != nil {
		_ = f.Close()
		return nil, errors.Join(errUntrusted, err)
	}
	return f, nil
}

func sidName(sid *windows.SID) string {
	if sid == nil {
		return "nobody"
	}
	if acct, dom, _, err := sid.LookupAccount(""); err == nil {
		return dom + `\` + acct
	}
	return sid.String()
}

// SPDX-License-Identifier: Apache-2.0

package client

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"

	"github.com/ingressd/ingressd/internal/connector/proto"
)

func setDACL(t *testing.T, path, sddl string) {
	t.Helper()
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		t.Fatal(err)
	}
}

func TestUsersCanWrite(t *testing.T) {
	dir := t.TempDir()
	for sddl, want := range map[string]bool{
		"D:P(A;;FA;;;SY)(A;;FA;;;BA)":               false,
		"D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FRFX;;;BU)": false,
		"D:P(A;;FA;;;SY)(A;;FA;;;OW)(A;;FA;;;BU)":   true,
		"D:P(A;;FA;;;OW)(A;;FW;;;AU)":               true,
		"D:P(A;;FA;;;OW)(A;;GA;;;WD)":               true,
		"D:P(A;;FA;;;OW)(A;IO;FA;;;BU)":             false,
	} {
		// Keep access for the test account so the next round can run.
		self, err := processSID()
		if err != nil {
			t.Fatal(err)
		}
		setDACL(t, dir, strings.Replace(sddl, "D:P", "D:P(A;;FA;;;"+self+")", 1))
		if got := usersCanWrite(dir); got != want {
			t.Errorf("%s: %v", sddl, got)
		}
	}
	setDACL(t, dir, "D:P(A;;FA;;;WD)")
}

func processSID() (string, error) {
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return "", err
	}
	return u.User.Sid.String(), nil
}

func TestCheckServicePath(t *testing.T) {
	root := t.TempDir()
	t.Setenv("USERPROFILE", filepath.Join(root, "home"))
	t.Setenv("TEMP", "")
	t.Setenv("TMP", "")
	t.Setenv("LOCALAPPDATA", "")
	t.Setenv("APPDATA", "")
	t.Setenv("PUBLIC", "")
	t.Setenv("SystemDrive", "")
	if err := checkServicePath(filepath.Join(root, "home", "Downloads", "ingressd-connector.exe")); err == nil {
		t.Error("a binary in a profile was accepted")
	}

	dir := filepath.Join(root, "bin")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	exe := filepath.Join(dir, "ingressd-connector.exe")
	if err := os.WriteFile(exe, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	self, err := processSID()
	if err != nil {
		t.Fatal(err)
	}
	private := "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;" + self + ")"
	setDACL(t, dir, private)
	setDACL(t, exe, private)
	if err := checkServicePath(exe); err != nil {
		t.Errorf("private folder: %v", err)
	}
	setDACL(t, dir, private+"(A;;FA;;;BU)")
	if err := checkServicePath(exe); err == nil {
		t.Error("a folder users can write was accepted")
	}
	setDACL(t, dir, private)
	setDACL(t, exe, private+"(A;;FA;;;AU)")
	if err := checkServicePath(exe); err == nil {
		t.Error("a binary users can write was accepted")
	}
}

func TestInsideDir(t *testing.T) {
	for _, tc := range []struct {
		path, dir string
		want      bool
	}{
		{`C:\Users\a\x.exe`, `C:\Users`, true},
		{`c:\users\a\x.exe`, `C:\Users`, true},
		{`C:\Users2\x.exe`, `C:\Users`, false},
		{`C:\Program Files\ingressd\x.exe`, `C:\Users`, false},
		{`D:\Users\x.exe`, `C:\Users`, false},
	} {
		if got := insideDir(tc.path, tc.dir); got != tc.want {
			t.Errorf("%s in %s: %v", tc.path, tc.dir, got)
		}
	}
}

// Enrolling into a directory that already exists makes it private first.
func TestEnrollSecuresExistingDirectory(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(proto.EnrollResponse{Credential: "cred", Config: proto.TunnelConfig{Tunnel: "home", Address: "100.64.0.6/30", Revision: "r1"}})
	}))
	defer ts.Close()
	dir := filepath.Join(t.TempDir(), "ingressd-connector")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	self, err := processSID()
	if err != nil {
		t.Fatal(err)
	}
	setDACL(t, dir, "D:P(A;;FA;;;"+self+")(A;OICI;FA;;;BU)")
	if !usersCanWrite(dir) {
		t.Fatal("setup: directory is private already")
	}
	st, err := Enroll(context.Background(), filepath.Join(dir, "connector.json"), EnrollOptions{EdgeURL: ts.URL, Token: "t", Mode: ModeNetstack, Insecure: true})
	if err != nil {
		t.Fatal(err)
	}
	if st.Tunnel() != "home" || usersCanWrite(dir) || usersCanWrite(filepath.Join(dir, "connector.json")) {
		t.Errorf("tunnel %q, dir writable %v", st.Tunnel(), usersCanWrite(dir))
	}
}

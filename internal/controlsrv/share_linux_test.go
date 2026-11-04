// SPDX-License-Identifier: Apache-2.0

package controlsrv

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestShareSocketRefusesSymlink(t *testing.T) {
	dir := t.TempDir()
	victim := filepath.Join(dir, "victim")
	if err := os.WriteFile(victim, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "control.sock")
	if err := os.Symlink(victim, link); err != nil {
		t.Fatal(err)
	}
	if err := shareSocket(link, os.Getgid()); err == nil {
		t.Fatal("shareSocket followed a symlink")
	}
	if fi, _ := os.Stat(victim); fi.Mode().Perm() != 0o600 {
		t.Fatalf("victim mode changed to %v", fi.Mode().Perm())
	}
	if err := shareSocket(victim, -1); err == nil {
		t.Fatal("shareSocket accepted a regular file")
	}
}

func TestListenSharesSocket(t *testing.T) {
	path := filepath.Join(t.TempDir(), "control.sock")
	// A stale symlink in its place is replaced, not followed.
	if err := os.Symlink("/etc/passwd", path); err != nil {
		t.Fatal(err)
	}
	ln, err := Listen(path)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	fi, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Type() != os.ModeSocket || fi.Mode().Perm() != 0o660 {
		t.Fatalf("socket mode %v", fi.Mode())
	}
	c, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
}

// SPDX-License-Identifier: Apache-2.0

package safefs

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestReadFile(t *testing.T) {
	dir := t.TempDir()
	outside := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(outside, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "ok"), []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if b, err := ReadFile(root, "ok", 5); err != nil || string(b) != "hello" {
		t.Fatalf("ReadFile = %q, %v", b, err)
	}
	if _, err := ReadFile(root, "ok", 4); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("over the limit: %v", err)
	}
	if _, err := ReadFile(root, ".", 0); err == nil {
		t.Fatal("read a directory")
	}
	if runtime.GOOS == "windows" {
		return // symlinks need privileges
	}
	if err := os.Symlink(outside, filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	if b, err := ReadFile(root, "link", 0); err == nil {
		t.Fatalf("followed a symlink out of the root: %q", b)
	}
}

func TestWriteFileReplacesSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks need privileges")
	}
	dir := t.TempDir()
	victim := filepath.Join(t.TempDir(), "victim")
	if err := os.WriteFile(victim, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "config.yaml")
	if err := os.Symlink(victim, p); err != nil {
		t.Fatal(err)
	}
	if err := WriteFile(p, []byte("new"), 0o640); err == nil {
		t.Fatal("WriteFile accepted a symlink")
	}
	if b, _ := os.ReadFile(victim); string(b) != "keep" {
		t.Fatalf("victim overwritten: %q", b)
	}
	os.Remove(p)
	if err := WriteFile(p, []byte("new"), 0o640); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Lstat(p)
	if err != nil || !fi.Mode().IsRegular() || fi.Mode().Perm() != 0o640 {
		t.Fatalf("written file: %v %v", fi, err)
	}
}

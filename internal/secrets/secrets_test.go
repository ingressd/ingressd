// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "age.key")
	if err := GenerateIdentity(keyPath); err != nil {
		t.Fatal(err)
	}
	if err := GenerateIdentity(keyPath); err == nil {
		t.Fatal("GenerateIdentity overwrote an existing key")
	}
	id, err := LoadIdentity(keyPath)
	if err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(dir, "secrets.age")
	s, err := Open(path, id)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Set("dns_token", "abcdef123456"); err != nil {
		t.Fatal(err)
	}
	if err := s.Set("Bad Name", "x"); err == nil {
		t.Fatal("accepted invalid name")
	}
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}

	raw, _ := os.ReadFile(path)
	if strings.Contains(string(raw), "abcdef123456") {
		t.Fatal("secret stored in plaintext")
	}

	s2, err := Open(path, id)
	if err != nil {
		t.Fatal(err)
	}
	if v, err := s2.Resolve("secret://dns_token"); err != nil || v != "abcdef123456" {
		t.Fatalf("Resolve = %q, %v", v, err)
	}
	if v, _ := s2.Resolve("plain"); v != "plain" {
		t.Fatalf("plain value changed: %q", v)
	}
	if _, err := s2.Resolve("secret://missing"); err == nil {
		t.Fatal("missing secret resolved")
	}
	if got := s2.Redact(`{"token":"abcdef123456"}`); got != `{"token":"«secret:dns_token»"}` {
		t.Fatalf("Redact = %s", got)
	}
}

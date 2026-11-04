// SPDX-License-Identifier: Apache-2.0

package nodeproto

import (
	"slices"
	"testing"
)

// Expected values follow certmagic.FileStorage (filepath.Walk) behaviour.
func TestStorageListKeys(t *testing.T) {
	keys := []string{
		"certificates/acme/a.example/a.example.crt",
		"certificates/acme/a.example/a.example.key",
		"certificates/acme/b.example/b.example.crt",
		"acme/users/u.json",
		"last_clean.json",
	}
	for _, tc := range []struct {
		prefix    string
		recursive bool
		want      []string
		ok        bool
	}{
		{"certificates/acme", false, []string{"certificates/acme/a.example", "certificates/acme/b.example"}, true},
		{"certificates/acme/", false, []string{"certificates/acme/a.example", "certificates/acme/b.example"}, true},
		{"certificates", true, []string{
			"certificates/acme", "certificates/acme/a.example", "certificates/acme/a.example/a.example.crt",
			"certificates/acme/a.example/a.example.key", "certificates/acme/b.example", "certificates/acme/b.example/b.example.crt"}, true},
		{"", false, []string{"acme", "certificates", "last_clean.json"}, true},
		{"certificates/acme/a.example/a.example.crt", false, []string{}, true}, // a file: empty, no error
		{"certificates/none", false, []string{}, false},
		{"certificates/acme/a", false, []string{}, false}, // not a path prefix match
	} {
		got, ok := StorageListKeys(keys, tc.prefix, tc.recursive)
		if ok != tc.ok || !slices.Equal(got, tc.want) {
			t.Errorf("List(%q, %v) = %v, %v; want %v, %v", tc.prefix, tc.recursive, got, ok, tc.want, tc.ok)
		}
	}
	if !StorageHasChildren(keys, "certificates/acme") || StorageHasChildren(keys, "certificates/acme/a.example/a.example.crt") {
		t.Error("StorageHasChildren")
	}
}

func TestValidateStorageKey(t *testing.T) {
	for k, ok := range map[string]bool{
		"certificates/a/b.crt": true,
		"":                     false,
		"/abs":                 false,
		"a/../b":               false,
		"a//b":                 false,
		"a/":                   false,
		"a\\b":                 false,
	} {
		if err := ValidateStorageKey(k); (err == nil) != ok {
			t.Errorf("ValidateStorageKey(%q) = %v", k, err)
		}
	}
	if CleanStorageKey("/a//b/") != "a/b" || CleanStorageKey("") != "" || CleanStorageKey(".") != "" {
		t.Error("CleanStorageKey")
	}
}

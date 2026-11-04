// SPDX-License-Identifier: Apache-2.0

package access

import (
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/ingressd/ingressd/pkg/config"
)

type pathCase struct {
	Path      string `json:"path"`
	Canonical string `json:"canonical"`
	Admin     bool   `json:"admin"`
}

func loadPathCorpus(t *testing.T) []pathCase {
	t.Helper()
	b, err := os.ReadFile("testdata/pathcanon.json")
	if err != nil {
		t.Fatal(err)
	}
	var c struct{ Cases []pathCase }
	if err := json.Unmarshal(b, &c); err != nil {
		t.Fatal(err)
	}
	return c.Cases
}

func TestCanonicalPathCorpus(t *testing.T) {
	for _, tc := range loadPathCorpus(t) {
		got, err := CanonicalPath(tc.Path)
		if tc.Canonical == "" {
			if !errors.Is(err, ErrAmbiguousPath) {
				t.Errorf("CanonicalPath(%q) = %q, %v; want ErrAmbiguousPath", tc.Path, got, err)
			}
			continue
		}
		if err != nil || got != tc.Canonical {
			t.Errorf("CanonicalPath(%q) = %q, %v; want %q", tc.Path, got, err, tc.Canonical)
			continue
		}
		if m := PathRuleMatch("/admin/*", got); m != tc.Admin {
			t.Errorf("PathRuleMatch(/admin/*, %q) = %v, want %v", got, m, tc.Admin)
		}
	}
}

// An app that protects only /admin/*: no spelling of an admin path may get
// the (empty) default list.
func TestListForBypassCorpus(t *testing.T) {
	app := config.App{Paths: []config.PathRule{{Match: "/admin/*", Access: []string{"admins"}}}}
	for _, tc := range loadPathCorpus(t) {
		if tc.Canonical == "" {
			continue // edge_auth answers 400 before any policy
		}
		got := ListFor(app, tc.Path)
		if (len(got) > 0) != tc.Admin {
			t.Errorf("ListFor(%q) = %v, want admin rule %v", tc.Path, got, tc.Admin)
		}
	}
}

func TestPathRuleMatch(t *testing.T) {
	for _, tc := range []struct {
		pattern, path string
		want          bool
	}{
		{"/admin/*", "/admin/x", true},
		{"/Admin/*", "/admin/x", true},
		{"/admin*", "/administrator", true},
		{"/admin", "/admin", true},
		{"/admin", "/admin/", false},
		{"/admin/", "/admin/", true},
		{"/*", "/anything", true},
		{"/a b/*", "/a b/c", true},
		{"/api/hook", "/API/Hook", false}, // canonical paths are already lowercase
	} {
		if got := PathRuleMatch(tc.pattern, tc.path); got != tc.want {
			t.Errorf("PathRuleMatch(%q, %q) = %v, want %v", tc.pattern, tc.path, got, tc.want)
		}
	}
}

// edge_auth carries a copy of pathcanon.go; it must not drift.
func TestPathCanonInSync(t *testing.T) {
	ours, err := os.ReadFile("pathcanon.go")
	if err != nil {
		t.Fatal(err)
	}
	theirs, err := os.ReadFile("../../edge/modules/edgeauth/pathcanon.go")
	if err != nil {
		t.Skipf("edge module not checked out: %v", err)
	}
	norm := func(b []byte) string {
		s := strings.ReplaceAll(string(b), "\r\n", "\n")
		return strings.Replace(strings.Replace(s, "\npackage edgeauth\n", "\npackage X\n", 1), "\npackage access\n", "\npackage X\n", 1)
	}
	if norm(ours) != norm(theirs) {
		t.Fatal("edge/modules/edgeauth/pathcanon.go differs from pkg/access/pathcanon.go; copy it over (only the package clause may differ)")
	}
}

func FuzzCanonicalPath(f *testing.F) {
	for _, s := range []string{"/", "/admin/x", "/%2e%2e/admin", "/a/../b/", "//x"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, p string) {
		c, err := CanonicalPath(p)
		if err != nil {
			return
		}
		if !strings.HasPrefix(c, "/") || strings.Contains(c, "//") || strings.ContainsAny(c, "\\;\x00") {
			t.Fatalf("CanonicalPath(%q) = %q", p, c)
		}
		// Idempotent on its own output (when that is itself a valid escaped path).
		if c2, err := CanonicalPath(c); err == nil && !strings.Contains(c, "%") && c2 != c {
			t.Fatalf("not idempotent: %q -> %q -> %q", p, c, c2)
		}
	})
}

// SPDX-License-Identifier: Apache-2.0

package edgeauth

import (
	"encoding/json"
	"errors"
	"os"
	"testing"
)

// The corpus is shared with pkg/access (the portal side of path rules).
func TestCanonicalPathCorpus(t *testing.T) {
	b, err := os.ReadFile("../../../pkg/access/testdata/pathcanon.json")
	if err != nil {
		t.Skipf("main module not checked out: %v", err)
	}
	var c struct {
		Cases []struct {
			Path      string
			Canonical string
			Admin     bool
		}
	}
	if err := json.Unmarshal(b, &c); err != nil {
		t.Fatal(err)
	}
	for _, tc := range c.Cases {
		got, err := CanonicalPath(tc.Path)
		if tc.Canonical == "" {
			if !errors.Is(err, ErrAmbiguousPath) {
				t.Errorf("CanonicalPath(%q) = %q, %v; want ErrAmbiguousPath", tc.Path, got, err)
			}
			continue
		}
		if err != nil || got != tc.Canonical {
			t.Errorf("CanonicalPath(%q) = %q, %v; want %q", tc.Path, got, err, tc.Canonical)
		} else if m := PathRuleMatch("/admin/*", got); m != tc.Admin {
			t.Errorf("PathRuleMatch(/admin/*, %q) = %v, want %v", got, m, tc.Admin)
		}
	}
}

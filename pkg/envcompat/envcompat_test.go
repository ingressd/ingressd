// SPDX-License-Identifier: Apache-2.0

package envcompat

import "testing"

func TestLookup(t *testing.T) {
	t.Setenv("INGRESSD_X_NEW", "new")
	t.Setenv(legacyPrefix+"X_NEW", "old")
	t.Setenv(legacyPrefix+"X_OLD", "old")
	if v := Get("INGRESSD_X_NEW"); v != "new" {
		t.Fatalf("new name wins: %q", v)
	}
	if v, ok := Lookup("INGRESSD_X_OLD"); !ok || v != "old" {
		t.Fatalf("legacy fallback: %q %v", v, ok)
	}
	if _, ok := Lookup("INGRESSD_X_UNSET"); ok {
		t.Fatal("unset reported as set")
	}
	if Legacy("OTHER") != "" {
		t.Fatal("non-INGRESSD name has no legacy name")
	}
}

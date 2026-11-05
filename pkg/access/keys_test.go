// SPDX-License-Identifier: Apache-2.0

package access

import (
	"encoding/hex"
	"testing"
)

// Shared test vector with edge/modules/edgeauth (TestDeriveVector).
func TestDeriveVector(t *testing.T) {
	got := hex.EncodeToString(derive([]byte("0123456789abcdef0123456789abcdef"), kdfPrefix+"edge_auth/cookie/web"))
	if want := "c21d56724026cde83c7e95aa589b69a54386518c301d9ac3bec055f9cc372795"; got != want {
		t.Fatalf("derive = %s, want %s", got, want)
	}
}

// Shared test vector with edge/modules/edgeauth (TestRealmDeriveVector).
func TestRealmDeriveVector(t *testing.T) {
	if AppCookieInfo("", "web") != kdfPrefix+"edge_auth/cookie/web" {
		t.Fatal("configs without realms must keep their cookie keys")
	}
	got := hex.EncodeToString(derive([]byte("0123456789abcdef0123456789abcdef"), AppCookieInfo("tq7k2m", "tq7k2m.nas")))
	if want := "bc33c03792797154289ad17ee699ece4d3d45f720820bf1307545c5f43ee8ee2"; got != want {
		t.Fatalf("derive = %s, want %s", got, want)
	}
}

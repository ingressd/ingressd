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

// SPDX-License-Identifier: Apache-2.0

package access

import "testing"

// Shared vector with edge/modules/edgeauth (TestNonceHashVector): the
// portal seals what edge_auth puts in the login URL.
func TestFlowNonceHashVector(t *testing.T) {
	if got := FlowNonceHash("abc"); got != "ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0" {
		t.Fatalf("FlowNonceHash = %s", got)
	}
	if !ValidFlowNonceHash(FlowNonceHash("x")) || ValidFlowNonceHash("abc") || ValidFlowNonceHash("") {
		t.Fatal("ValidFlowNonceHash")
	}
}

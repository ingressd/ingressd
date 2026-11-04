// SPDX-License-Identifier: Apache-2.0

package edgehello

import (
	"testing"

	"github.com/caddyserver/caddy/v2/caddytest"

	_ "github.com/caddyserver/caddy/v2/modules/standard"
)

func TestHelloHeader(t *testing.T) {
	tester := caddytest.NewTester(t)
	tester.InitServer(`
	{
		skip_install_trust
		admin localhost:2999
		http_port 9080
		https_port 9443
	}
	:9080 {
		ingressd_hello test-edge
		respond "ok"
	}
	`, "caddyfile")

	resp, _ := tester.AssertGetResponse("http://localhost:9080/", 200, "ok")
	if got := resp.Header.Get("X-Ingressd-Edge"); got != "test-edge" {
		t.Fatalf("X-Ingressd-Edge = %q, want %q", got, "test-edge")
	}
}

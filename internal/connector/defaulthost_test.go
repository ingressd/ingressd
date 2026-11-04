// SPDX-License-Identifier: Apache-2.0

package connector

import "testing"

func TestDefaultHost(t *testing.T) {
	cfg := testConfig(51821)
	cfg.Edge.Admin.Hostname = ""
	cfg.Edge.PublicIPv4 = "198.51.100.9"
	defer func() { DefaultHost = nil }()
	DefaultHost = func() string { return "203.0.113.10" }
	tc, err := TunnelConfig(cfg, fakeKeys{}, "cloud")
	if err != nil {
		t.Fatal(err)
	}
	if tc.Endpoint != "203.0.113.10:51821" || tc.WSURL != "wss://203.0.113.10/.ingressd/tunnel/cloud" {
		t.Errorf("tc = %+v", tc)
	}
}

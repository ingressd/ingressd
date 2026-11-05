// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"testing"

	"github.com/ingressd/ingressd/pkg/config"
)

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

// Realms refuse edge.admin.hostname: without an enrolment endpoint the
// public IPv4 serves connectors, WebSocket fallback included.
func TestRealmsMachineHostFallback(t *testing.T) {
	cfg := testConfig(51821)
	cfg.Edge.Admin.Hostname = ""
	cfg.Edge.PublicIPv4 = "198.51.100.9"
	cfg.Realms = map[string]config.Realm{"ra": {}}
	tc, err := TunnelConfig(cfg, fakeKeys{}, "cloud")
	if err != nil {
		t.Fatal(err)
	}
	if tc.Endpoint != "198.51.100.9:51821" || tc.WSURL != "wss://198.51.100.9/.ingressd/tunnel/cloud" {
		t.Errorf("tc = %+v", tc)
	}
	defer func() { DefaultHost = nil }()
	DefaultHost = func() string { return "node1.example.net" }
	if tc, _ := TunnelConfig(cfg, fakeKeys{}, "cloud"); tc.WSURL != "wss://node1.example.net/.ingressd/tunnel/cloud" {
		t.Errorf("enrolment endpoint not preferred: %+v", tc)
	}
}

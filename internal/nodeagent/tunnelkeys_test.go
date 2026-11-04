// SPDX-License-Identifier: Apache-2.0

package nodeagent

import (
	"testing"

	"github.com/ingressd/ingressd/internal/connector"
	"github.com/ingressd/ingressd/pkg/config"
)

func TestConnectorKey(t *testing.T) {
	cfg := &config.Config{Tunnels: map[string]config.Tunnel{"home": {Site: config.SiteConnector, PublicKey: "CFG"}}}
	if k := connectorKey(cfg, nil, "home"); k != "CFG" {
		t.Errorf("no store: %q", k)
	}
	cs := &connector.State{Connectors: map[string]*connector.Connector{"home": {}}}
	if k := connectorKey(cfg, cs, "home"); k != "CFG" {
		t.Errorf("attached (no enrolled key): %q", k)
	}
	cs.Connectors["home"].PublicKey = "ENROLLED"
	if k := connectorKey(cfg, cs, "home"); k != "ENROLLED" {
		t.Errorf("enrolled: %q", k)
	}
}

// SPDX-License-Identifier: Apache-2.0

package render

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/ingressd/ingressd/internal/secrets"
	"github.com/ingressd/ingressd/pkg/config"
)

func TestRealmShapesGolden(t *testing.T) {
	y := strings.Replace(realmsConfig, "  tq7k2m:\n", "  tq7k2m:\n    shape: { rate_mbit: 20 }\n", 1)
	y = strings.Replace(y, "  tb4x9p:\n", "  tb4x9p:\n    shape: { rate_mbit: 100 }\n", 1)
	// A second tunnel of tq7k2m shares the realm's IFB.
	y = strings.Replace(y, "groups:\n", "  tq7k2m02: { realm: tq7k2m, table: 1203, site: router, listen_port: 51822, transit: 10.100.3.0/30, subnets: [192.168.7.0/24], virtual_prefix: 10.0.6.0/24 }\ngroups:\n", 1)
	cfg, err := config.Parse([]byte(y))
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	p, err := Render(cfg, secrets.NewMemory(realmSecrets), fakeKeys{}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.MarshalIndent(p.Network.Shapes, "", "  ")
	golden(t, "shapes.json", string(b)+"\n")

	// Unshaped realms render no shapes at all.
	_, plain := renderRealms(t)
	if len(plain.Network.Shapes) != 0 {
		t.Errorf("shapes without shape blocks: %+v", plain.Network.Shapes)
	}
}

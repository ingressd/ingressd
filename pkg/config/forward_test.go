// SPDX-License-Identifier: Apache-2.0

package config

import (
	"slices"
	"strings"
	"testing"
)

const forwardYAML = baseYAML + `mesh:
  address: 10.255.0.1/16
  peers:
    nod_b: { public_key: "eEvqkSJVw/7cGUEcJXmeHiNFDLBGOz8GpScshecvNHU=", address: 10.255.0.2/32 }
    nod_c: { public_key: "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=", address: 10.255.0.3 }
`

func withForward(t *testing.T, f string) *Config {
	t.Helper()
	return mustParse(t, strings.Replace(forwardYAML, "  acme: { ca: internal }\n", "  acme: { ca: internal }\n  forward: "+f+"\n", 1))
}

func TestForwardValid(t *testing.T) {
	c := withForward(t, "{ listen_mesh: true, secret: secret://fwd, siblings: { home: [nod_c, nod_b] } }")
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	if got := c.ForwardSiblings("web"); !slices.Equal(got, []string{"10.255.0.3:51880", "10.255.0.2:51880"}) {
		t.Errorf("ForwardSiblings = %v", got)
	}
	if !c.ForwardTarget("web") {
		t.Error("tunnelled app is not a forward target")
	}
}

func TestForwardValidation(t *testing.T) {
	for _, tt := range []struct{ f, want string }{
		{"{ listen_mesh: true }", "edge.forward.secret: must be a secret reference"},
		{"{ secret: secret://fwd }", "edge.forward: set listen_mesh, siblings or both"},
		{"{ secret: secret://fwd, siblings: { nope: [nod_b] } }", `edge.forward.siblings.nope: unknown tunnel "nope"`},
		{"{ secret: secret://fwd, siblings: { home: [] } }", "edge.forward.siblings.home: at least one sibling is required"},
		{"{ secret: secret://fwd, siblings: { home: [nod_x] } }", `edge.forward.siblings.home[0]: unknown mesh peer "nod_x"`},
		{"{ secret: secret://fwd, siblings: { home: [nod_b, nod_b] } }", `edge.forward.siblings.home[1]: duplicate sibling "nod_b"`},
		{"{ secret: secret://fwd, siblings: { home: [nod_b, nod_c, nod_b, nod_c, nod_b] } }", "at most 4 siblings"},
	} {
		err := withForward(t, tt.f).Validate()
		if err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("%s: err = %v, want %q", tt.f, err, tt.want)
		}
	}

	c := mustParse(t, strings.Replace(baseYAML, "  acme: { ca: internal }\n", "  acme: { ca: internal }\n  forward: { listen_mesh: true, secret: secret://fwd }\n", 1))
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "edge.forward: needs the mesh section") {
		t.Errorf("forward without mesh: %v", err)
	}
}

// SPDX-License-Identifier: Apache-2.0

package render

import (
	"encoding/json"

	"github.com/ingressd/ingressd/internal/auth"
	"github.com/ingressd/ingressd/pkg/config"
)

// identityHeaders are set by edge_auth for origins; clients must never be
// able to supply them, on protected and public apps alike.
var identityHeaders = []string{"X-Edge-User-Email", "Edge-Jwt-Assertion", "X-Edge-Service-Token"}

// withAccess puts the access handler in front of an app's handlers:
// edge_auth for protected apps (it also strips spoofed identity headers),
// and a header scrub for public ones.
func withAccess(cfg *config.Config, res Resolver, opts Options, name string, handlers []obj) ([]obj, error) {
	app := cfg.Apps[name]
	if !app.Protected() {
		strip := obj{"handler": "headers", "request": obj{"delete": identityHeaders}}
		return append([]obj{strip}, handlers...), nil
	}
	ec, err := auth.BuildEdgeConfig(cfg, res, name, opts.ControlSocket)
	if err != nil {
		return nil, err
	}
	ec.CountryDB = opts.Security.CountryDB // for country selectors
	// Round-trip through JSON so the handler is a plain obj like the rest.
	b, err := json.Marshal(ec)
	if err != nil {
		return nil, err
	}
	var h obj
	if err := json.Unmarshal(b, &h); err != nil {
		return nil, err
	}
	return append([]obj{h}, handlers...), nil
}

// SPDX-License-Identifier: Apache-2.0

// Package edgehello is a placeholder Caddy module that proves the custom
// build pipeline end to end. The real edge modules (edge_state, edge_auth,
// edge_tiered, edge_challenge, edge_fallback) replace it from Phase 1.
package edgehello

import (
	"net/http"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func init() {
	caddy.RegisterModule(Hello{})
	httpcaddyfile.RegisterHandlerDirective("ingressd_hello", parseCaddyfile)
	httpcaddyfile.RegisterDirectiveOrder("ingressd_hello", httpcaddyfile.Before, "header")
}

// Hello sets an X-Ingressd-Edge response header and passes the request on.
type Hello struct {
	// Name is the header value. Defaults to "ingressd".
	Name string `json:"name,omitempty"`
}

func (Hello) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.ingressd_hello",
		New: func() caddy.Module { return new(Hello) },
	}
}

func (h *Hello) Provision(caddy.Context) error {
	if h.Name == "" {
		h.Name = "ingressd"
	}
	return nil
}

func (h Hello) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	w.Header().Set("X-Ingressd-Edge", h.Name)
	return next.ServeHTTP(w, r)
}

// UnmarshalCaddyfile parses:
//
//	ingressd_hello [<name>]
func (h *Hello) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next() // directive name
	if d.NextArg() {
		h.Name = d.Val()
	}
	if d.NextArg() {
		return d.ArgErr()
	}
	return nil
}

func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var m Hello
	err := m.UnmarshalCaddyfile(h.Dispenser)
	return &m, err
}

var (
	_ caddy.Provisioner           = (*Hello)(nil)
	_ caddyhttp.MiddlewareHandler = (*Hello)(nil)
	_ caddyfile.Unmarshaler       = (*Hello)(nil)
)

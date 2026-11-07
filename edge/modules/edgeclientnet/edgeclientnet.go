// SPDX-License-Identifier: Apache-2.0

// Package edgeclientnet is the edge_client_net Caddy handler. It sets the
// client_net variable, the key rate limits count a client by: the client
// address for IPv4, and its /64 for IPv6, the smallest prefix one subscriber
// is normally assigned.
package edgeclientnet

import (
	"net/http"
	"net/netip"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func init() {
	caddy.RegisterModule(Handler{})
}

// Handler is the http.handlers.edge_client_net module.
type Handler struct{}

func (Handler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.edge_client_net",
		New: func() caddy.Module { return new(Handler) },
	}
}

func (Handler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	ip, _ := caddyhttp.GetVar(r.Context(), caddyhttp.ClientIPVarKey).(string)
	caddyhttp.SetVar(r.Context(), "client_net", clientNet(ip))
	return next.ServeHTTP(w, r)
}

func clientNet(ip string) string {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return ip
	}
	a = a.Unmap()
	if a.Is6() {
		pfx, _ := a.Prefix(64)
		return pfx.String()
	}
	return a.String()
}

var _ caddyhttp.MiddlewareHandler = Handler{}

// SPDX-License-Identifier: Apache-2.0

package edgeforward

import (
	"encoding/json"
	"net/http"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/reverseproxy"

	"github.com/ingressd/ingressd/edge/modules/edgestate"
)

func init() {
	caddy.RegisterModule(Selection{})
}

// Selection prefers local upstreams whose tunnel is up and falls back to the
// app's siblings in order. A tunnel is down when the control plane says so
// (edge_state tunnels: stale handshake or missing interface); Caddy's
// passive health also drops a local upstream whose dials fail.
type Selection struct {
	// LocalRaw selects among the usable local upstreams (default first).
	LocalRaw json.RawMessage `json:"local,omitempty" caddy:"namespace=http.reverse_proxy.selection_policies inline_key=policy"`
	// Tunnels maps local dial addresses to their tunnel.
	Tunnels map[string]string `json:"tunnels,omitempty"`
	// Siblings are the forward listeners, in order of preference.
	Siblings []string `json:"siblings,omitempty"`

	local    reverseproxy.Selector
	store    *edgestate.Store
	siblings map[string]bool
	avail    func(*reverseproxy.Upstream) bool
}

func (Selection) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.reverse_proxy.selection_policies.edge_forward",
		New: func() caddy.Module { return new(Selection) },
	}
}

func (s *Selection) Provision(ctx caddy.Context) error {
	app, err := ctx.App("edge_state")
	if err != nil {
		return err
	}
	s.store = app.(*edgestate.App).Store()
	if s.LocalRaw != nil {
		mod, err := ctx.LoadModule(s, "LocalRaw")
		if err != nil {
			return err
		}
		s.local = mod.(reverseproxy.Selector)
	}
	s.setup()
	return nil
}

func (s *Selection) setup() {
	if s.local == nil {
		s.local = reverseproxy.FirstSelection{}
	}
	if s.store == nil {
		s.store = edgestate.Global()
	}
	if s.avail == nil {
		s.avail = (*reverseproxy.Upstream).Available
	}
	s.siblings = map[string]bool{}
	for _, d := range s.Siblings {
		s.siblings[d] = true
	}
}

func (s *Selection) Select(pool reverseproxy.UpstreamPool, r *http.Request, w http.ResponseWriter) *reverseproxy.Upstream {
	down := s.store.Snapshot().Tunnels
	local := make(reverseproxy.UpstreamPool, 0, len(pool))
	sibs := map[string]*reverseproxy.Upstream{}
	for _, up := range pool {
		if s.siblings[up.Dial] {
			sibs[up.Dial] = up
			continue
		}
		if t, ok := s.Tunnels[up.Dial]; ok && down[t].Down {
			continue
		}
		local = append(local, up)
	}
	if len(local) > 0 {
		if up := s.local.Select(local, r, w); up != nil {
			return up
		}
	}
	if forwarded(r) {
		return nil
	}
	for _, d := range s.Siblings {
		if up := sibs[d]; up != nil && s.avail(up) {
			return up
		}
	}
	return nil
}

var (
	_ caddy.Provisioner     = (*Selection)(nil)
	_ reverseproxy.Selector = (*Selection)(nil)
)

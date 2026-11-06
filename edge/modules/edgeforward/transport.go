// SPDX-License-Identifier: Apache-2.0

package edgeforward

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/reverseproxy"
)

func init() {
	caddy.RegisterModule(Transport{})
}

// errLoop refuses to forward a request that already came through a forward
// listener (max one hop).
var errLoop = errors.New("edge_forward: refusing to forward a forwarded request")

// Transport is the HTTP transport of an app with siblings: requests to a
// local origin go out as with the http transport (its fields are inline);
// requests to a sibling's forward listener go out as plain HTTP over the
// mesh (WireGuard encrypts it) with a fresh signed hop header.
type Transport struct {
	reverseproxy.HTTPTransport
	Forward Hop `json:"forward"`

	siblings map[string]bool
	now      func() time.Time
}

// Hop says how this node signs the requests it forwards.
type Hop struct {
	// Secret is the mesh-wide forwarding key.
	Secret string `json:"secret"`
	// Node is this node's mesh address, checked by the receiver against
	// the connection's source.
	Node string `json:"node"`
	App  string `json:"app"`
	// Siblings are the forward listeners (dial addresses) of this app.
	Siblings []string `json:"siblings"`
}

func (Transport) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.reverse_proxy.transport.edge_forward",
		New: func() caddy.Module { return new(Transport) },
	}
}

func (t *Transport) Provision(ctx caddy.Context) error {
	if err := t.setup(); err != nil {
		return err
	}
	return t.HTTPTransport.Provision(ctx)
}

func (t *Transport) setup() error {
	if len(t.Forward.Secret) < minSecretLen {
		return fmt.Errorf("edge_forward: secret must be at least %d bytes", minSecretLen)
	}
	if t.Forward.Node == "" || t.Forward.App == "" {
		return errors.New("edge_forward: node and app are required")
	}
	t.siblings = map[string]bool{}
	for _, s := range t.Forward.Siblings {
		t.siblings[s] = true
	}
	if t.now == nil {
		t.now = time.Now
	}
	return nil
}

func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	if !t.siblings[req.URL.Host] {
		req.Header.Del(HopHeader)
		return t.HTTPTransport.RoundTrip(req)
	}
	if forwarded(req) {
		return nil, errLoop
	}
	req.Header.Set(HopHeader, SignHop([]byte(t.Forward.Secret), t.Forward.Node, t.Forward.App, t.now()))
	req.URL.Scheme = "http"
	return t.Transport.RoundTrip(req)
}

// forwarded reports whether r arrived through a forward listener.
func forwarded(r *http.Request) bool {
	v, _ := caddyhttp.GetVar(r.Context(), VarApp).(string)
	return v != ""
}

var (
	_ caddy.Provisioner  = (*Transport)(nil)
	_ caddy.CleanerUpper = (*Transport)(nil)
	_ http.RoundTripper  = (*Transport)(nil)
)

// SPDX-License-Identifier: Apache-2.0

package edgeforward

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"slices"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(Verify{})
}

// VarApp is the request variable holding the app a verified hop names; the
// forward listener's routes match on it, and a request carrying it is never
// forwarded again.
const VarApp = "edge_forward_app"

// Verify guards the forward listener. Access was enforced by the first
// node; this node trusts only hops signed with the mesh secret, at most
// MaxAge old, by a mesh peer that is also the connection's source.
type Verify struct {
	Secret string `json:"secret"`
	// Self is this node's mesh address: a hop it signed itself is a loop.
	Self string `json:"self"`
	// Peers are the mesh addresses allowed to forward here.
	Peers  []string       `json:"peers"`
	MaxAge caddy.Duration `json:"max_age,omitempty"`

	logger *zap.Logger
	now    func() time.Time
}

func (Verify) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.edge_forward_verify",
		New: func() caddy.Module { return new(Verify) },
	}
}

func (v *Verify) Provision(ctx caddy.Context) error {
	v.logger = ctx.Logger()
	return v.setup()
}

func (v *Verify) setup() error {
	if len(v.Secret) < minSecretLen {
		return fmt.Errorf("edge_forward_verify: secret must be at least %d bytes", minSecretLen)
	}
	if v.MaxAge <= 0 {
		v.MaxAge = caddy.Duration(DefaultMaxAge)
	}
	if v.now == nil {
		v.now = time.Now
	}
	if v.logger == nil {
		v.logger = zap.NewNop()
	}
	return nil
}

var errLoopHop = errors.New("hop signed by this node")

// check returns the app a request may be routed to.
func (v *Verify) check(r *http.Request) (string, int, error) {
	node, app, err := VerifyHop([]byte(v.Secret), r.Header.Get(HopHeader), v.now(), time.Duration(v.MaxAge))
	if err != nil {
		return "", http.StatusForbidden, err
	}
	if node == v.Self {
		return "", http.StatusLoopDetected, errLoopHop
	}
	if !slices.Contains(v.Peers, node) {
		return "", http.StatusForbidden, fmt.Errorf("hop from %s, which is not a mesh peer", node)
	}
	if src, _, err := net.SplitHostPort(r.RemoteAddr); err != nil || src != node {
		return "", http.StatusForbidden, fmt.Errorf("hop signed for %s arrived from %s", node, r.RemoteAddr)
	}
	return app, 0, nil
}

func (v *Verify) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	app, code, err := v.check(r)
	if err != nil {
		v.logger.Warn("forward refused", zap.String("remote", r.RemoteAddr), zap.String("host", r.Host), zap.Error(err))
		return caddyhttp.Error(code, err)
	}
	r.Header.Del(HopHeader)
	caddyhttp.SetVar(r.Context(), VarApp, app)
	return next.ServeHTTP(w, r)
}

var (
	_ caddy.Provisioner           = (*Verify)(nil)
	_ caddyhttp.MiddlewareHandler = (*Verify)(nil)
)

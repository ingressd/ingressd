// SPDX-License-Identifier: Apache-2.0

package client

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/ingressd/ingressd/internal/connector/proto"
)

// A connector sends a request-bound v2 IngressdKey header only to an edge
// whose config advertises it.
func TestAuthHeaderVersion(t *testing.T) {
	site, _ := wgtypes.GeneratePrivateKey()
	edgeKey, _ := wgtypes.GeneratePrivateKey()
	pub := edgeKey.PublicKey()
	e := &edge{s: &session{priv: site}, key: pub, cfg: EdgeState{Config: proto.TunnelConfig{Tunnel: "home"}}}
	if h := e.authHeader(http.MethodGet, proto.PollPath, nil); proto.KeyAuthVersion(h) != 1 {
		t.Errorf("edge without v2 got %q", h)
	}
	e.cfg.Config.KeyAuth = proto.KeyAuthV2
	h := e.authHeader(http.MethodGet, proto.PollPath, nil)
	sitePub := site.PublicKey()
	if _, _, err := proto.CheckKeyAuthRequest(h, edgeKey[:], sitePub[:], time.Now(), http.MethodGet, proto.PollPath, nil); err != nil || proto.KeyAuthVersion(h) != 2 {
		t.Errorf("v2 header %q: %v", h, err)
	}
	e.cfg.Credential = "cred"
	if h := e.authHeader(http.MethodGet, proto.PollPath, nil); !strings.HasPrefix(h, "Bearer ") {
		t.Errorf("enrolled edge got %q", h)
	}
}

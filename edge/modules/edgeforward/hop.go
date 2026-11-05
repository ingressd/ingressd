// SPDX-License-Identifier: Apache-2.0

// Package edgeforward implements PoP forwarding (docs/rev1/ARCHITECTURE.md
// §11): when an app's tunnel is down on this node, the request goes over
// the node mesh to a sibling node's forward listener, which proxies it to
// its own tunnel.
//
//   - http.reverse_proxy.selection_policies.edge_forward picks a local
//     upstream whose tunnel is up (edge_state), else the first available
//     sibling;
//   - http.reverse_proxy.transport.edge_forward is the HTTP transport, which
//     signs requests sent to a sibling with a hop header;
//   - http.handlers.edge_forward_verify guards the forward listener: only
//     fresh hops signed with the mesh secret by the peer that sent them are
//     accepted, and the app they name selects the route.
package edgeforward

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// HopHeader carries the signed hop: "v1;<node>;<app>;<unix>;<mac>".
const HopHeader = "X-Ingressd-Hop"

// DefaultMaxAge is how long a signed hop is accepted (either side of now,
// for clock skew between nodes).
const DefaultMaxAge = 30 * time.Second

// minSecretLen keeps a misconfigured (empty or tiny) secret from signing.
const minSecretLen = 16

var (
	errNoHop    = errors.New("no hop header")
	errBadHop   = errors.New("malformed hop header")
	errBadMAC   = errors.New("hop signature mismatch")
	errStaleHop = errors.New("hop expired")
)

func hopMAC(secret []byte, node, app string, ts int64) string {
	m := hmac.New(sha256.New, secret)
	fmt.Fprintf(m, "ingressd-hop/v1\n%s\n%s\n%d", node, app, ts)
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

// SignHop returns the hop header value for a request node forwards for app.
func SignHop(secret []byte, node, app string, now time.Time) string {
	ts := now.Unix()
	return strings.Join([]string{"v1", node, app, strconv.FormatInt(ts, 10), hopMAC(secret, node, app, ts)}, ";")
}

// VerifyHop checks a hop header and returns the forwarding node and the app.
func VerifyHop(secret []byte, v string, now time.Time, maxAge time.Duration) (node, app string, err error) {
	if v == "" {
		return "", "", errNoHop
	}
	parts := strings.Split(v, ";")
	if len(parts) != 5 || parts[0] != "v1" || parts[1] == "" || parts[2] == "" {
		return "", "", errBadHop
	}
	ts, err := strconv.ParseInt(parts[3], 10, 64)
	if err != nil {
		return "", "", errBadHop
	}
	if !hmac.Equal([]byte(hopMAC(secret, parts[1], parts[2], ts)), []byte(parts[4])) {
		return "", "", errBadMAC
	}
	if d := now.Sub(time.Unix(ts, 0)); d > maxAge || d < -maxAge {
		return "", "", errStaleHop
	}
	return parts[1], parts[2], nil
}

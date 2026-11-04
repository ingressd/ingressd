// SPDX-License-Identifier: Apache-2.0

package proto

import (
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
	"time"
)

// TunnelControlPort is the plain-HTTP port the node serves the connector
// endpoints (poll, report, discovery) on, on every connector tunnel's edge
// transit address. Requests are authenticated by WireGuard itself: only the
// site's peer can send from the site transit address through the tunnel
// interface. A connector uses it to refresh its edge list from any edge it
// has a working tunnel to, without a per-node credential.
const TunnelControlPort = 51819

// WSPath is an alias of TunnelPathPrefix+<tunnel> where the tunnel comes
// from the request's authentication.
const WSPath = "/.ingressd/connector/ws"

// Sibling is another node (edge) the same site is attached to. The
// connector links to it as an additional WireGuard peer.
type Sibling struct {
	Node string `json:"node,omitempty"`
	// Endpoint is that edge's WireGuard UDP listener, host:port.
	Endpoint      string `json:"endpoint"`
	EdgePublicKey string `json:"edge_public_key"`
	// Address is the site's transit address on that edge with prefix, e.g.
	// 100.64.0.10/30; EdgeAddress the edge's, e.g. 100.64.0.9.
	Address     string `json:"address"`
	EdgeAddress string `json:"edge_address"`
	// WSURL is that edge's WireGuard-over-WebSocket URL ("" = no fallback).
	WSURL string `json:"ws_url,omitempty"`
}

// KeyAuthScheme authenticates a connector to an edge it never enrolled
// with, using the WireGuard keys both sides already hold: the MAC key is
// X25519(site private, edge public) = X25519(edge private, site public).
//
//	v1: Authorization: IngressdKey <tunnel>.<unix seconds>.<hex HMAC-SHA256>
//	v2: Authorization: IngressdKey v2.<tunnel>.<unix seconds>.<hex nonce>.<hex HMAC-SHA256>
//
// A v1 header covers only the tunnel and the time, so anyone who sees one
// (e.g. on a learned edge's WebSocket relay, whose certificate is not
// verified) can use it on any endpoint for KeyAuthSkew. A v2 header also
// covers a random nonce, the method, the path and the body's SHA-256
// (KeyAuthRequest), and the edge accepts each nonce once (Server's replay
// cache), so it authorises exactly the request it was made for.
//
// Rollout: edges accept both and advertise v2 in TunnelConfig.KeyAuth; a
// connector sends v2 to an edge whose config advertises it, else v1, so
// either side may update first. v1 acceptance can be removed once every
// supported connector sends v2 (the minimum supported version is at or
// above the first release with v2) — remove after 2027-06.
const KeyAuthScheme = "IngressdKey"

// KeyAuthV2 is the TunnelConfig.KeyAuth value of edges that accept v2.
const KeyAuthV2 = 2

// keyAuthV2Prefix starts a v2 header's value (tunnel names have no dots,
// so a v1 value never has five fields).
const keyAuthV2Prefix = "v2."

// LegacyKeyAuthScheme is accepted from connectors that predate the rename.
const LegacyKeyAuthScheme = "HomeedgeKey" // legacy homeedge name, remove after 2027-01

// cutKeyAuthScheme strips either scheme from an Authorization value.
func cutKeyAuthScheme(h string) (string, bool) {
	if v, ok := strings.CutPrefix(h, KeyAuthScheme+" "); ok {
		return v, true
	}
	return strings.CutPrefix(h, LegacyKeyAuthScheme+" ")
}

// KeyAuthSkew is how far the timestamp may be from the verifier's clock.
const KeyAuthSkew = 5 * time.Minute

func keyAuthMAC(tunnel, ts string, priv, peer []byte) ([]byte, error) {
	// The MAC label is shared by every connector and node release: changing it
	// needs a new scheme version, so it keeps the old name.
	return keyMAC(priv, peer, "homeedge-connector-auth-v1\x00"+tunnel+"\x00"+ts) // legacy homeedge name, remove after 2027-01 (MAC label: only with a v2 scheme)
}

// keyAuthMACv2 covers the request as well: method, path and body hash.
func keyAuthMACv2(tunnel, ts, nonce, method, path string, body []byte, priv, peer []byte) ([]byte, error) {
	bh := sha256.Sum256(body)
	return keyMAC(priv, peer, "ingressd-connector-auth-v2\x00"+tunnel+"\x00"+ts+"\x00"+nonce+"\x00"+
		strings.ToUpper(method)+"\x00"+path+"\x00"+hex.EncodeToString(bh[:]))
}

func keyMAC(priv, peer []byte, msg string) ([]byte, error) {
	k, err := ecdh.X25519().NewPrivateKey(priv)
	if err != nil {
		return nil, err
	}
	p, err := ecdh.X25519().NewPublicKey(peer)
	if err != nil {
		return nil, err
	}
	shared, err := k.ECDH(p)
	if err != nil {
		return nil, err
	}
	m := hmac.New(sha256.New, shared)
	m.Write([]byte(msg))
	return m.Sum(nil), nil
}

// KeyAuth returns the Authorization header value for a tunnel, from the
// caller's WireGuard private key and the other side's public key (raw 32
// bytes each).
func KeyAuth(tunnel string, priv, peer []byte, now time.Time) (string, error) {
	ts := strconv.FormatInt(now.Unix(), 10)
	mac, err := keyAuthMAC(tunnel, ts, priv, peer)
	if err != nil {
		return "", err
	}
	return KeyAuthScheme + " " + tunnel + "." + ts + "." + hex.EncodeToString(mac), nil
}

// KeyAuthRequest returns a v2 Authorization header value for one request
// (method, URL path, body; nil for none).
func KeyAuthRequest(tunnel string, priv, peer []byte, now time.Time, method, path string, body []byte) (string, error) {
	n := make([]byte, 16)
	if _, err := rand.Read(n); err != nil {
		return "", err
	}
	ts, nonce := strconv.FormatInt(now.Unix(), 10), hex.EncodeToString(n)
	mac, err := keyAuthMACv2(tunnel, ts, nonce, method, path, body, priv, peer)
	if err != nil {
		return "", err
	}
	return KeyAuthScheme + " " + keyAuthV2Prefix + tunnel + "." + ts + "." + nonce + "." + hex.EncodeToString(mac), nil
}

// keyAuthFields splits a header value: v1 tunnel, ts, mac; v2 tunnel, ts,
// nonce, mac.
func keyAuthFields(h string) (version int, f []string, ok bool) {
	v, found := cutKeyAuthScheme(h)
	if !found {
		return 0, nil, false
	}
	if rest, isV2 := strings.CutPrefix(v, keyAuthV2Prefix); isV2 {
		if f = strings.Split(rest, "."); len(f) == 4 && f[0] != "" {
			return 2, f, true
		}
	}
	if f = strings.Split(v, "."); len(f) == 3 && f[0] != "" {
		return 1, f, true
	}
	return 0, nil, false
}

// ParseKeyAuth returns the tunnel a IngressdKey header (v1 or v2) claims.
func ParseKeyAuth(h string) (tunnel string, ok bool) {
	_, f, ok := keyAuthFields(h)
	if !ok {
		return "", false
	}
	return f[0], true
}

// KeyAuthVersion returns the version of a IngressdKey header (0: none).
func KeyAuthVersion(h string) int {
	v, _, _ := keyAuthFields(h)
	return v
}

// CheckKeyAuth verifies a v1 IngressdKey header with the verifier's
// private key and the claimed peer's public key.
func CheckKeyAuth(h string, priv, peer []byte, now time.Time) error {
	v, f, ok := keyAuthFields(h)
	if !ok {
		return errors.New("malformed " + KeyAuthScheme + " header")
	}
	if v != 1 {
		return errors.New(KeyAuthScheme + " v2 header needs the request (CheckKeyAuthRequest)")
	}
	if err := checkSkew(f[1], now); err != nil {
		return err
	}
	want, err := keyAuthMAC(f[0], f[1], priv, peer)
	if err != nil {
		return err
	}
	return checkMAC(f[2], want)
}

// CheckKeyAuthRequest verifies a v1 or v2 IngressdKey header for a request.
// For v2 it returns the header's nonce, which the caller must accept only
// once within KeyAuthSkew of the timestamp (a replay cache); for v1 nonce
// is "" (v1 headers cannot be told apart from their replays).
func CheckKeyAuthRequest(h string, priv, peer []byte, now time.Time, method, path string, body []byte) (version int, nonce string, err error) {
	v, f, ok := keyAuthFields(h)
	if !ok {
		return 0, "", errors.New("malformed " + KeyAuthScheme + " header")
	}
	if v == 1 {
		return 1, "", CheckKeyAuth(h, priv, peer, now)
	}
	if err := checkSkew(f[1], now); err != nil {
		return 2, "", err
	}
	if b, err := hex.DecodeString(f[2]); err != nil || len(b) < 16 {
		return 2, "", errors.New("malformed nonce")
	}
	want, err := keyAuthMACv2(f[0], f[1], f[2], method, path, body, priv, peer)
	if err != nil {
		return 2, "", err
	}
	if err := checkMAC(f[3], want); err != nil {
		return 2, "", err
	}
	return 2, f[2], nil
}

func checkSkew(ts string, now time.Time) error {
	sec, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		return errors.New("malformed timestamp")
	}
	if d := now.Sub(time.Unix(sec, 0)); d > KeyAuthSkew || d < -KeyAuthSkew {
		return errors.New("timestamp outside the allowed clock skew")
	}
	return nil
}

func checkMAC(got string, want []byte) error {
	b, err := hex.DecodeString(got)
	if err != nil {
		return errors.New("malformed MAC")
	}
	if !hmac.Equal(b, want) {
		return errors.New("MAC mismatch")
	}
	return nil
}

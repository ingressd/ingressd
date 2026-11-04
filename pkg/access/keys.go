// SPDX-License-Identifier: Apache-2.0

package access

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
)

// Keys are the decoded Access keys.
type Keys struct {
	// SessionRaw and JWTRaw are the secrets exactly as stored. They are
	// what goes into the Caddy config, so diffs redact them.
	SessionRaw string
	JWTRaw     string

	master []byte
	JWT    *ecdsa.PrivateKey
	KID    string
}

// ParseKeys decodes stored key material.
func ParseKeys(sessionRaw, jwtRaw string) (*Keys, error) {
	master, err := base64.StdEncoding.DecodeString(sessionRaw)
	if err != nil || len(master) < 32 {
		return nil, errors.New("access session key must be at least 32 bytes, base64")
	}
	der, err := base64.StdEncoding.DecodeString(jwtRaw)
	if err != nil {
		return nil, fmt.Errorf("access JWT key: %w", err)
	}
	k, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("access JWT key: %w", err)
	}
	ek, ok := k.(*ecdsa.PrivateKey)
	if !ok || ek.Curve != elliptic.P256() {
		return nil, errors.New("access JWT key must be ECDSA P-256")
	}
	kid, err := KeyID(&ek.PublicKey)
	if err != nil {
		return nil, err
	}
	return &Keys{SessionRaw: sessionRaw, JWTRaw: jwtRaw, master: master, JWT: ek, KID: kid}, nil
}

// kdfPrefix starts every HKDF info string. It is part of the key format
// shared by the control plane, edge_auth and the panel: changing it would
// invalidate every session cookie, auth code and service-token verifier, so
// it keeps the pre-rename name until a key-rotation migration replaces it.
const kdfPrefix = "homeedge/" // legacy homeedge name, remove after 2027-01 (key-derivation label)

// derive expands the master key for one purpose (HKDF-SHA256). The info
// strings are part of the format shared with edge_auth.
func derive(master []byte, info string) []byte {
	k, err := hkdf.Key(sha256.New, master, nil, info, 32)
	if err != nil {
		panic(err) // only fails for absurd lengths
	}
	return k
}

// AppCookieKey encrypts the __edge_<app> cookie of one app.
func (k *Keys) AppCookieKey(app string) []byte {
	return derive(k.master, kdfPrefix+"edge_auth/cookie/"+app)
}

// PortalCookieKey encrypts the portal's own session cookie.
func (k *Keys) PortalCookieKey() []byte { return derive(k.master, kdfPrefix+"portal/cookie") }

// PlayCookieKey encrypts the login-to-play session cookie.
func (k *Keys) PlayCookieKey() []byte { return derive(k.master, kdfPrefix+"play/cookie") }

// AuthCodeKey encrypts the one-time callback codes, so any node of the org
// can redeem a code another node's portal issued.
func (k *Keys) AuthCodeKey() []byte { return derive(k.master, kdfPrefix+"portal/authcode") }

// IDPFlowKey seals the identity-provider sign-in state cookie (idp.SealFlow).
func (k *Keys) IDPFlowKey() []byte { return derive(k.master, kdfPrefix+"portal/idp-flow") }

// ServiceTokenHMACKey keys the service-token verifiers rendered for edge_auth.
func (k *Keys) ServiceTokenHMACKey() []byte {
	return derive(k.master, kdfPrefix+"edge_auth/service-token")
}

// ServiceTokenVerifier is what edge_auth compares a presented client secret
// against: HMAC-SHA256 under ServiceTokenHMACKey, hex.
func (k *Keys) ServiceTokenVerifier(secret string) string {
	m := hmac.New(sha256.New, k.ServiceTokenHMACKey())
	m.Write([]byte(secret))
	return hex.EncodeToString(m.Sum(nil))
}

// KeyID names a JWT signing key: the first 16 characters of the base64url
// SHA-256 of its PKIX encoding.
func KeyID(pub *ecdsa.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(der)
	return base64.RawURLEncoding.EncodeToString(sum[:])[:16], nil
}

// JWK is a public key in JSON Web Key form.
type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	Use string `json:"use"`
}

// JWKS returns the key set origins use to verify Edge-Jwt-Assertion.
func (k *Keys) JWKS() map[string][]JWK {
	pub := k.JWT.PublicKey
	ecdh, _ := pub.ECDH()
	raw := ecdh.Bytes() // 0x04 || X || Y
	return map[string][]JWK{"keys": {{
		Kty: "EC", Crv: "P-256",
		X:   base64.RawURLEncoding.EncodeToString(raw[1:33]),
		Y:   base64.RawURLEncoding.EncodeToString(raw[33:65]),
		Kid: k.KID, Alg: "ES256", Use: "sig",
	}}}
}

// SPDX-License-Identifier: Apache-2.0

package access

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"time"

	"aidanwoods.dev/go-paseto"

	"github.com/ingressd/ingressd/pkg/config"
)

// AppClaims is the content of an app cookie (__edge_<app>), a PASETO
// v4.local token encrypted with AppCookieKey(app) and the implicit assertion
// "edge_auth:<app>". edge_auth decrypts and checks it on every request.
type AppClaims struct {
	SID string
	// Email is the session's principal: an email address, or
	// "<method>:<id>" for a sign-in that proved none (see Principal).
	Email string
	App   string
	// Method and Attrs are the login method and the facts captured at
	// sign-in (see SessionFacts); edge_auth matches identity selectors
	// against them on every request.
	Method string
	Attrs  []string
	// Grants maps each allow policy the identity satisfied at sign-in to
	// the policy version it satisfied.
	Grants   map[string]string
	IssuedAt time.Time
	Expires  time.Time
}

// AppCookieName is the per-app session cookie.
func AppCookieName(app string) string { return "__edge_" + app }

func appImplicit(app string) []byte { return []byte("edge_auth:" + app) }

// SealApp encrypts app claims into a cookie value.
func (k *Keys) SealApp(c AppClaims) (string, error) {
	key, err := paseto.V4SymmetricKeyFromBytes(k.AppCookieKey(c.App))
	if err != nil {
		return "", err
	}
	t := paseto.NewToken()
	t.SetIssuedAt(c.IssuedAt)
	t.SetExpiration(c.Expires)
	t.SetString("sid", c.SID)
	t.SetString("email", c.Email)
	t.SetString("app", c.App)
	if err := setFacts(&t, c.Method, c.Attrs); err != nil {
		return "", err
	}
	if err := t.Set("pols", c.Grants); err != nil {
		return "", err
	}
	return t.V4Encrypt(key, appImplicit(c.App)), nil
}

// OpenApp decrypts and validates an app cookie (tests and tools; edge_auth
// has its own copy of this logic).
func (k *Keys) OpenApp(app, value string) (*AppClaims, error) {
	key, err := paseto.V4SymmetricKeyFromBytes(k.AppCookieKey(app))
	if err != nil {
		return nil, err
	}
	t, err := paseto.NewParser().ParseV4Local(key, value, appImplicit(app))
	if err != nil {
		return nil, err
	}
	c := &AppClaims{}
	c.SID, _ = t.GetString("sid")
	c.Email, _ = t.GetString("email")
	c.App, _ = t.GetString("app")
	c.IssuedAt, _ = t.GetIssuedAt()
	c.Expires, _ = t.GetExpiration()
	_ = t.Get("pols", &c.Grants)
	c.Method, c.Attrs = getFacts(t)
	if c.App != app || c.SID == "" {
		return nil, errors.New("token is not for this app")
	}
	return c, nil
}

// PortalClaims is the portal's own session cookie (and the login-to-play
// cookie). It is self-contained so a node that never saw the session (it
// was created on another node of the org) can still accept it.
type PortalClaims struct {
	SID     string
	Email   string // principal (see AppClaims.Email)
	Expires time.Time
	Issued  time.Time // set by OpenPortal; SealPortal uses Issued or now
	// Method and Attrs: how the user signed in and the facts captured
	// then; signing in to another app reuses them for the session's life.
	Method string
	Attrs  []string
}

// claim names of the sign-in facts. Tokens without them come from email
// sign-ins made before login methods existed.
const (
	claimMethod = "m"
	claimAttrs  = "attrs"
)

func setFacts(t *paseto.Token, method string, attrs []string) error {
	if method == "" {
		return nil
	}
	t.SetString(claimMethod, method)
	if len(attrs) > 0 {
		return t.Set(claimAttrs, attrs)
	}
	return nil
}

func getFacts(t *paseto.Token) (string, []string) {
	m, err := t.GetString(claimMethod)
	if err != nil || m == "" {
		return config.MethodEmail, nil
	}
	var attrs []string
	_ = t.Get(claimAttrs, &attrs)
	return m, attrs
}

// PortalCookieName is the session cookie on the portal host.
const PortalCookieName = "__edge_portal"

// implicitPrefix starts the PASETO implicit assertions; like kdfPrefix it is
// part of the token format and keeps the pre-rename name.
const implicitPrefix = "homeedge-" // legacy homeedge name, remove after 2027-01 (token format label)

var portalImplicit = []byte(implicitPrefix + "portal")

func (k *Keys) SealPortal(c PortalClaims) (string, error) {
	return sealSession(k.PortalCookieKey(), portalImplicit, c)
}

func (k *Keys) OpenPortal(value string) (*PortalClaims, error) {
	return openSession(k.PortalCookieKey(), portalImplicit, value)
}

// PlayCookieName is the login-to-play session cookie on a play host.
const PlayCookieName = "__edge_play"

var playImplicit = []byte(implicitPrefix + "play")

// SealPlay and OpenPlay handle the login-to-play cookie.
func (k *Keys) SealPlay(c PortalClaims) (string, error) {
	return sealSession(k.PlayCookieKey(), playImplicit, c)
}

func (k *Keys) OpenPlay(value string) (*PortalClaims, error) {
	return openSession(k.PlayCookieKey(), playImplicit, value)
}

func sealSession(raw, implicit []byte, c PortalClaims) (string, error) {
	key, err := paseto.V4SymmetricKeyFromBytes(raw)
	if err != nil {
		return "", err
	}
	iat := c.Issued
	if iat.IsZero() {
		iat = time.Now()
	}
	t := paseto.NewToken()
	t.SetIssuedAt(iat)
	t.SetExpiration(c.Expires)
	t.SetString("sid", c.SID)
	t.SetString("email", c.Email)
	if err := setFacts(&t, c.Method, c.Attrs); err != nil {
		return "", err
	}
	return t.V4Encrypt(key, implicit), nil
}

func openSession(raw, implicit []byte, value string) (*PortalClaims, error) {
	key, err := paseto.V4SymmetricKeyFromBytes(raw)
	if err != nil {
		return nil, err
	}
	t, err := paseto.NewParser().ParseV4Local(key, value, implicit)
	if err != nil {
		return nil, err
	}
	c := &PortalClaims{}
	c.SID, _ = t.GetString("sid")
	c.Email, _ = t.GetString("email")
	c.Expires, _ = t.GetExpiration()
	c.Issued, _ = t.GetIssuedAt()
	c.Method, c.Attrs = getFacts(t)
	if c.SID == "" || c.Email == "" {
		return nil, errors.New("incomplete portal token")
	}
	return c, nil
}

// SealedCode is the content of a one-time callback code: everything the
// redeeming node needs, encrypted under AuthCodeKey, so the portal and the
// app's callback may be served by different nodes.
type SealedCode struct {
	ID             string // single-use marker (per redeeming node)
	SID            string
	Email          string
	App            string
	RD             string
	Grants         map[string]string
	SessionIssued  time.Time
	SessionExpires time.Time
	Expires        time.Time
	// Nonce binds the code to the browser that started the sign-in: the
	// "n" parameter edge_auth adds to the login URL, which is the
	// base64url SHA-256 of a nonce in a cookie on the app host (see
	// FlowNonceHash). Empty when the login request carried none.
	Nonce string
	// Method and Attrs are the sign-in's login method and facts; the
	// redeeming node evaluates the app's policies against them.
	Method string
	Attrs  []string
}

// FlowNonceHash is the login-URL form of edge_auth's sign-in nonce cookie;
// edge_auth computes the same (edge/modules/edgeauth).
func FlowNonceHash(nonce string) string {
	sum := sha256.Sum256([]byte(nonce))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// ValidFlowNonceHash reports whether s has the shape of FlowNonceHash.
func ValidFlowNonceHash(s string) bool {
	b, err := base64.RawURLEncoding.DecodeString(s)
	return err == nil && len(b) == sha256.Size
}

var codeImplicit = []byte(implicitPrefix + "authcode")

// SealCode encrypts a callback code.
func (k *Keys) SealCode(c SealedCode) (string, error) {
	key, err := paseto.V4SymmetricKeyFromBytes(k.AuthCodeKey())
	if err != nil {
		return "", err
	}
	t := paseto.NewToken()
	t.SetIssuedAt(time.Now())
	t.SetExpiration(c.Expires)
	t.SetJti(c.ID)
	t.SetString("sid", c.SID)
	t.SetString("email", c.Email)
	t.SetString("app", c.App)
	t.SetString("rd", c.RD)
	t.SetString("siat", c.SessionIssued.UTC().Format(time.RFC3339))
	t.SetString("sexp", c.SessionExpires.UTC().Format(time.RFC3339))
	if c.Nonce != "" {
		t.SetString("nonce", c.Nonce)
	}
	if err := setFacts(&t, c.Method, c.Attrs); err != nil {
		return "", err
	}
	if err := t.Set("pols", c.Grants); err != nil {
		return "", err
	}
	return t.V4Encrypt(key, codeImplicit), nil
}

// OpenCode decrypts and validates (expiry) a callback code.
func (k *Keys) OpenCode(value string) (*SealedCode, error) {
	key, err := paseto.V4SymmetricKeyFromBytes(k.AuthCodeKey())
	if err != nil {
		return nil, err
	}
	t, err := paseto.NewParser().ParseV4Local(key, value, codeImplicit)
	if err != nil {
		return nil, err
	}
	c := &SealedCode{}
	c.ID, _ = t.GetJti()
	c.SID, _ = t.GetString("sid")
	c.Email, _ = t.GetString("email")
	c.App, _ = t.GetString("app")
	c.RD, _ = t.GetString("rd")
	c.Expires, _ = t.GetExpiration()
	if s, err := t.GetString("siat"); err == nil {
		c.SessionIssued, _ = time.Parse(time.RFC3339, s)
	}
	if s, err := t.GetString("sexp"); err == nil {
		c.SessionExpires, _ = time.Parse(time.RFC3339, s)
	}
	_ = t.Get("pols", &c.Grants)
	c.Nonce, _ = t.GetString("nonce")
	c.Method, c.Attrs = getFacts(t)
	if c.ID == "" || c.SID == "" || c.Email == "" || c.App == "" {
		return nil, errors.New("incomplete code")
	}
	return c, nil
}

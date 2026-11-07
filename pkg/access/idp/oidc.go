// SPDX-License-Identifier: Apache-2.0

package idp

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/ingressd/ingressd/pkg/config"
)

// OpenID Connect (Google, Microsoft): discovery and JWKS are cached per
// URL; ID tokens are verified in full (RS256 signature against the
// provider's JWKS, issuer, audience, authorized party, expiry, issue time
// and nonce).

type discoveryDoc struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
}

const (
	discoveryTTL = 24 * time.Hour
	jwksTTL      = time.Hour
	// jwksMinRefresh rate-limits refetching the JWKS for an unknown kid
	// (key rotation), so forged tokens cannot make us hammer the provider.
	jwksMinRefresh = 30 * time.Second
	clockSkew      = 2 * time.Minute
)

type cached[T any] struct {
	v       T
	fetched time.Time
}

var (
	cacheMu   sync.Mutex
	discCache = map[string]cached[*discoveryDoc]{}
	jwksCache = map[string]cached[map[string]*rsa.PublicKey]{}
)

// discoveryURL is the provider's OpenID configuration document.
func (p *Provider) discoveryURL() string {
	e := p.ep()
	if p.Method == config.MethodGoogle {
		return strings.TrimSuffix(e.GoogleIssuer, "/") + "/.well-known/openid-configuration"
	}
	t := p.Tenant
	if t == "" {
		t = "common"
	}
	return strings.TrimSuffix(e.MicrosoftLogin, "/") + "/" + t + "/v2.0/.well-known/openid-configuration"
}

func (p *Provider) discovery(ctx context.Context) (*discoveryDoc, error) {
	u := p.discoveryURL()
	cacheMu.Lock()
	c, ok := discCache[u]
	cacheMu.Unlock()
	if ok && time.Since(c.fetched) < discoveryTTL {
		return c.v, nil
	}
	var d discoveryDoc
	status, err := p.getJSON(ctx, u, "", &d)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK || d.Issuer == "" || d.AuthorizationEndpoint == "" || d.TokenEndpoint == "" || d.JWKSURI == "" {
		return nil, fmt.Errorf("%s: OpenID configuration: HTTP %d or incomplete document", p.Method, status)
	}
	for _, x := range []string{d.AuthorizationEndpoint, d.TokenEndpoint, d.JWKSURI} {
		if !strings.HasPrefix(x, "https://") && !strings.HasPrefix(u, "http://") {
			return nil, fmt.Errorf("%s: OpenID configuration has a non-https endpoint", p.Method)
		}
	}
	cacheMu.Lock()
	discCache[u] = cached[*discoveryDoc]{&d, time.Now()}
	cacheMu.Unlock()
	return &d, nil
}

type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// key returns the RSA key kid from the JWKS at u, refetching (rate
// limited) when the cache is stale or does not know kid.
func (p *Provider) key(ctx context.Context, u, kid string) (*rsa.PublicKey, error) {
	cacheMu.Lock()
	c, ok := jwksCache[u]
	cacheMu.Unlock()
	if ok {
		if k := c.v[kid]; k != nil && time.Since(c.fetched) < jwksTTL {
			return k, nil
		}
		if time.Since(c.fetched) < jwksMinRefresh {
			if k := c.v[kid]; k != nil {
				return k, nil
			}
			return nil, errors.New("unknown signing key")
		}
	}
	var set struct {
		Keys []jwk `json:"keys"`
	}
	status, err := p.getJSON(ctx, u, "", &set)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("%s: JWKS: HTTP %d", p.Method, status)
	}
	keys := map[string]*rsa.PublicKey{}
	for _, k := range set.Keys {
		if k.Kty != "RSA" || (k.Use != "" && k.Use != "sig") {
			continue
		}
		nb, err1 := base64.RawURLEncoding.DecodeString(k.N)
		eb, err2 := base64.RawURLEncoding.DecodeString(k.E)
		if err1 != nil || err2 != nil || len(eb) > 4 || len(nb) < 256 {
			continue
		}
		keys[k.Kid] = &rsa.PublicKey{N: new(big.Int).SetBytes(nb), E: int(new(big.Int).SetBytes(eb).Int64())}
	}
	cacheMu.Lock()
	jwksCache[u] = cached[map[string]*rsa.PublicKey]{keys, time.Now()}
	cacheMu.Unlock()
	if k := keys[kid]; k != nil {
		return k, nil
	}
	return nil, errors.New("unknown signing key")
}

// idClaims are the ID token claims used.
type idClaims struct {
	Iss           string          `json:"iss"`
	Sub           string          `json:"sub"`
	Aud           json.RawMessage `json:"aud"`
	Azp           string          `json:"azp"`
	Exp           json.Number     `json:"exp"`
	Iat           json.Number     `json:"iat"`
	Nonce         string          `json:"nonce"`
	Email         string          `json:"email"`
	EmailVerified any             `json:"email_verified"`
	Name          string          `json:"name"`
	HD            string          `json:"hd"`
	// Microsoft
	TID               string            `json:"tid"`
	OID               string            `json:"oid"`
	PreferredUsername string            `json:"preferred_username"`
	Groups            []string          `json:"groups"`
	Roles             []string          `json:"roles"`
	XmsEdov           any               `json:"xms_edov"`
	ClaimNames        map[string]string `json:"_claim_names"`
}

// truthy accepts a JSON boolean or the strings "true"/"1" (Microsoft
// optional claims arrive as either).
func truthy(v any) bool {
	switch x := v.(type) {
	case bool:
		return x
	case string:
		return x == "true" || x == "1"
	case float64:
		return x == 1
	}
	return false
}

// verifyIDToken checks an RS256 JWT and returns its claims.
func (p *Provider) verifyIDToken(ctx context.Context, d *discoveryDoc, raw, nonce string) (*idClaims, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return nil, errors.New("malformed ID token")
	}
	hb, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, errors.New("malformed ID token header")
	}
	var hdr struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
		Typ string `json:"typ"`
	}
	if err := json.Unmarshal(hb, &hdr); err != nil {
		return nil, errors.New("malformed ID token header")
	}
	if hdr.Alg != "RS256" {
		return nil, fmt.Errorf("ID token algorithm %q is not allowed", truncate(hdr.Alg, 16))
	}
	key, err := p.key(ctx, d.JWKSURI, hdr.Kid)
	if err != nil {
		return nil, fmt.Errorf("ID token: %w", err)
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, errors.New("malformed ID token signature")
	}
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(key, crypto.SHA256, sum[:], sig); err != nil {
		return nil, errors.New("ID token signature is invalid")
	}
	pb, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, errors.New("malformed ID token payload")
	}
	dec := json.NewDecoder(strings.NewReader(string(pb)))
	dec.UseNumber()
	var c idClaims
	if err := dec.Decode(&c); err != nil {
		return nil, errors.New("malformed ID token payload")
	}
	// Audience: our client ID; with several audiences azp must be us.
	var auds []string
	if err := json.Unmarshal(c.Aud, &auds); err != nil {
		var one string
		if json.Unmarshal(c.Aud, &one) != nil {
			return nil, errors.New("ID token has no audience")
		}
		auds = []string{one}
	}
	if !slices.Contains(auds, p.ClientID) || (len(auds) > 1 && c.Azp != p.ClientID) || (c.Azp != "" && c.Azp != p.ClientID) {
		return nil, errors.New("ID token is for another application")
	}
	now := time.Now()
	exp, err1 := c.Exp.Int64()
	iat, err2 := c.Iat.Int64()
	if err1 != nil || err2 != nil || now.After(time.Unix(exp, 0).Add(clockSkew)) || time.Unix(iat, 0).After(now.Add(clockSkew)) {
		return nil, errors.New("ID token is expired or not yet valid")
	}
	if nonce == "" || subtle.ConstantTimeCompare([]byte(c.Nonce), []byte(nonce)) != 1 {
		return nil, errors.New("ID token nonce does not match this sign-in")
	}
	if c.Sub == "" {
		return nil, errors.New("ID token has no subject")
	}
	if err := p.checkIssuer(d, &c); err != nil {
		return nil, err
	}
	return &c, nil
}

// checkIssuer compares iss with the discovery document's issuer. For the
// Microsoft multi-tenant endpoints the document's issuer contains
// "{tenantid}", which must be the token's own tid; the configured tenant
// further restricts which tenants may sign in.
func (p *Provider) checkIssuer(d *discoveryDoc, c *idClaims) error {
	switch p.Method {
	case config.MethodGoogle:
		if c.Iss != d.Issuer && "https://"+c.Iss != d.Issuer {
			return errors.New("ID token issuer is not Google")
		}
		return nil
	case config.MethodMicrosoft:
		tid := strings.ToLower(c.TID)
		if !guid(tid) {
			return errors.New("ID token has no tenant ID")
		}
		want := strings.ReplaceAll(d.Issuer, "{tenantid}", tid)
		if c.Iss != want {
			return errors.New("ID token issuer does not match its tenant")
		}
		switch t := strings.ToLower(p.Tenant); t {
		case "", "common":
		case "organizations":
			if tid == config.MicrosoftConsumersTenant {
				return userErr("personal Microsoft accounts cannot sign in here; use a work or school account")
			}
		case "consumers":
			if tid != config.MicrosoftConsumersTenant {
				return userErr("only personal Microsoft accounts can sign in here")
			}
		default:
			if tid != t {
				return userErr("accounts of this organization cannot sign in here")
			}
		}
		return nil
	}
	return errors.New("not an OpenID Connect provider")
}

func guid(s string) bool {
	return len(s) == 36 && strings.Count(s, "-") == 4 && strings.Trim(s, "0123456789abcdef-") == ""
}

func (p *Provider) oidcFinish(ctx context.Context, redirectURI string, f Flow, code string) (*Identity, error) {
	d, err := p.discovery(ctx)
	if err != nil {
		return nil, err
	}
	tr, err := p.exchange(ctx, d.TokenEndpoint, redirectURI, code, f.Verifier)
	if err != nil {
		return nil, err
	}
	if tr.IDToken == "" {
		return nil, fmt.Errorf("%s returned no ID token", p.Method)
	}
	c, err := p.verifyIDToken(ctx, d, tr.IDToken, f.Nonce)
	if err != nil {
		var ue *Error
		if errors.As(err, &ue) {
			return nil, err
		}
		return nil, fmt.Errorf("%s: %w", p.Method, err)
	}
	id := &Identity{Method: p.Method, Subject: c.Sub, Name: c.Name}
	email, _ := normEmail(c.Email)
	switch p.Method {
	case config.MethodGoogle:
		if email != "" && truthy(c.EmailVerified) {
			id.Email = email
		}
		if c.HD != "" {
			id.Attrs = append(id.Attrs, config.Attr("google_hd", c.HD))
		}
	case config.MethodMicrosoft:
		tid := strings.ToLower(c.TID)
		oid := strings.ToLower(c.OID)
		if oid == "" {
			oid = c.Sub
		}
		id.Subject = tid + "/" + oid
		// Entra lets tenant admins set any address as a user's email, so
		// it only counts as verified when Microsoft says the domain is
		// verified by the tenant (optional claim xms_edov) or when the
		// account is a personal one (Microsoft verifies those addresses).
		if email != "" && (tid == config.MicrosoftConsumersTenant || truthy(c.XmsEdov) || truthy(c.EmailVerified)) {
			id.Email = email
		}
		id.Attrs = append(id.Attrs, config.Attr("microsoft_tenant", tid))
		if _, overage := c.ClaimNames["groups"]; overage && f.Wants.MicrosoftGroups {
			return nil, userErr("your account is in too many groups for Microsoft to list them in the sign-in token; " +
				"ask the administrator to emit only groups assigned to the application")
		}
		for _, g := range c.Groups {
			id.Attrs = append(id.Attrs, config.Attr("microsoft_group", g))
		}
		// A role value only has meaning inside the directory that assigned
		// it, so it counts only when the provider is limited to one tenant.
		kind := config.AttrMicrosoftRoleUnbound
		if config.MicrosoftSingleTenant(strings.ToLower(p.Tenant)) {
			kind = "microsoft_role"
		}
		for _, r := range c.Roles {
			id.Attrs = append(id.Attrs, config.Attr(kind, r))
		}
		if id.Name == "" {
			id.Name = c.PreferredUsername
		}
	}
	return id, nil
}

// normEmail lowercases and sanity-checks a provider's email.
func normEmail(s string) (string, bool) {
	s = strings.ToLower(strings.TrimSpace(s))
	at := strings.LastIndexByte(s, '@')
	if s == "" || len(s) > 254 || at < 1 || at == len(s)-1 || strings.ContainsAny(s, " \t\r\n<>()[],;:\"\\") {
		return "", false
	}
	return s, true
}

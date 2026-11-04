// SPDX-License-Identifier: Apache-2.0

// Package idp signs users in with third-party identity providers for
// ingressd Access: Discord (OAuth2), Google and Microsoft (OpenID Connect)
// and Steam (OpenID 2.0). The node's portal (internal/auth) and the hosted
// panel's central portal share it.
//
// A sign-in is two requests. Start returns the provider's authorization URL
// and a Flow (state, PKCE verifier, OIDC nonce) that the caller seals into
// a short-lived cookie (SealFlow) bound to the browser. Finish runs on the
// callback: it checks state against the cookie, redeems the code (with the
// PKCE verifier), fully verifies the ID token (signature via the
// provider's JWKS, issuer, audience, expiry, nonce) or, for Steam, has
// Steam verify the assertion (check_authentication), and returns the
// identity with the facts the policies need (Wants) as config.Attr
// strings.
//
// Emails are only reported when the provider says they are verified.
package idp

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/ingressd/ingressd/pkg/config"
)

// Endpoints are the providers' base URLs. Production code uses Default;
// tests point a Provider at fakes (see idptest).
type Endpoints struct {
	DiscordAuth string // authorization endpoint
	DiscordAPI  string // API base (token endpoint is DiscordAPI + "/oauth2/token")
	// GoogleIssuer serves /.well-known/openid-configuration.
	GoogleIssuer string
	// MicrosoftLogin is the Microsoft identity platform host; discovery is
	// MicrosoftLogin + "/<tenant>/v2.0/.well-known/openid-configuration".
	MicrosoftLogin string
	SteamOpenID    string // Steam's OpenID 2.0 endpoint
	SteamAPI       string // Steam Web API base
}

// Default are the real providers.
var Default = Endpoints{
	DiscordAuth:    "https://discord.com/oauth2/authorize",
	DiscordAPI:     "https://discord.com/api/v10",
	GoogleIssuer:   "https://accounts.google.com",
	MicrosoftLogin: "https://login.microsoftonline.com",
	SteamOpenID:    "https://steamcommunity.com/openid/login",
	SteamAPI:       "https://api.steampowered.com",
}

// DefaultEndpoints returns the endpoints a Provider without its own uses:
// Default, unless a build for end-to-end tests overrides them (the
// idptest build tag; never in release builds).
func DefaultEndpoints() Endpoints {
	if testEndpoints != nil {
		return *testEndpoints
	}
	return Default
}

// testEndpoints is set only by override_idptest.go (build tag idptest).
var testEndpoints *Endpoints

// Provider is one configured sign-in method.
type Provider struct {
	Method       string // config.MethodDiscord, ...
	ClientID     string
	ClientSecret string
	Tenant       string // microsoft: common (default), organizations, consumers or a tenant ID
	APIKey       string // steam: Web API key (optional)
	// Endpoints overrides DefaultEndpoints (tests).
	Endpoints *Endpoints
	// HTTP is the client for provider requests (default: 10s timeout, no
	// redirects).
	HTTP *http.Client
}

// New builds a Provider from config (secrets already resolved).
func New(method string, p config.IdentityProvider, clientSecret, apiKey string) *Provider {
	return &Provider{Method: method, ClientID: p.ClientID, ClientSecret: clientSecret, Tenant: p.Tenant, APIKey: apiKey}
}

func (p *Provider) ep() Endpoints {
	if p.Endpoints != nil {
		return *p.Endpoints
	}
	return DefaultEndpoints()
}

var defaultClient = &http.Client{
	Timeout:       10 * time.Second,
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
}

func (p *Provider) client() *http.Client {
	if p.HTTP != nil {
		return p.HTTP
	}
	return defaultClient
}

// Wants says which facts beyond the identity a sign-in should collect;
// WantsFrom derives it from the facts the policies refer to.
type Wants struct {
	DiscordGuilds     bool     // the user's server list (discord_guild)
	DiscordRoleGuilds []string // servers whose member roles to read (discord_role)
	SteamGroups       bool     // the user's Steam groups (steam_group)
	SteamApps         []string // app IDs to check ownership of (steam_app)
	MicrosoftGroups   bool     // microsoft_group selectors exist
}

// WantsFrom derives Wants from access.Engine.ReferencedAttrs.
func WantsFrom(ref map[string]bool) Wants {
	var w Wants
	for a := range ref {
		kind, v, _ := strings.Cut(a, ":")
		switch kind {
		case "discord_guild":
			w.DiscordGuilds = true
		case "discord_role":
			g, _, _ := strings.Cut(v, "/")
			w.DiscordRoleGuilds = append(w.DiscordRoleGuilds, g)
		case "steam_group":
			w.SteamGroups = true
		case "steam_app":
			w.SteamApps = append(w.SteamApps, v)
		case "microsoft_group":
			w.MicrosoftGroups = true
		}
	}
	slices.Sort(w.DiscordRoleGuilds)
	w.DiscordRoleGuilds = slices.Compact(w.DiscordRoleGuilds)
	slices.Sort(w.SteamApps)
	w.SteamApps = slices.Compact(w.SteamApps)
	return w
}

// Flow is the state of one sign-in between Start and Finish. The caller
// seals it into a cookie (SealFlow) and may add its own fields.
type Flow struct {
	Method   string    `json:"m"`
	State    string    `json:"s"`
	Verifier string    `json:"v,omitempty"` // PKCE code verifier
	Nonce    string    `json:"o,omitempty"` // OIDC nonce
	Wants    Wants     `json:"w"`
	Expires  time.Time `json:"e"`
	// Caller data: the app, return URL and edge_auth's browser binding.
	App string `json:"a,omitempty"`
	RD  string `json:"r,omitempty"`
	N   string `json:"n,omitempty"`
}

// FlowTTL bounds how long a user may take at the provider.
const FlowTTL = 10 * time.Minute

// Identity is a verified sign-in.
type Identity struct {
	Method  string
	Subject string // the provider's stable user ID
	// Email is verified (lowercase), or "" when the provider proved none.
	Email string
	// Name is a display name for pages and logs (not used by policies).
	Name string
	// Attrs are the facts for identity selectors (config.Attr strings).
	Attrs []string
}

// Principal is the session user (see access.Principal).
func (id *Identity) Principal() string {
	if id.Email != "" {
		return id.Email
	}
	return id.Method + ":" + id.Subject
}

// Error is a sign-in failure safe to show the user.
type Error struct{ Msg string }

func (e *Error) Error() string { return e.Msg }

func userErr(format string, args ...any) error { return &Error{Msg: fmt.Sprintf(format, args...)} }

// ErrState means the callback does not belong to the flow in the cookie
// (another browser, a replay or a forged request).
var ErrState = &Error{Msg: "this sign-in was started in another browser or has expired; start again"}

func random(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// Start begins a sign-in: it returns the URL to send the browser to and
// the flow to seal into a cookie. redirectURI is the callback registered
// with the provider.
func (p *Provider) Start(ctx context.Context, redirectURI string, w Wants) (string, Flow, error) {
	f := Flow{Method: p.Method, State: random(24), Wants: w, Expires: time.Now().Add(FlowTTL)}
	switch p.Method {
	case config.MethodSteam:
		return p.steamStart(redirectURI, f)
	case config.MethodDiscord:
		f.Verifier = random(48)
		scopes := []string{"identify", "email"}
		if w.DiscordGuilds {
			scopes = append(scopes, "guilds")
		}
		if len(w.DiscordRoleGuilds) > 0 {
			scopes = append(scopes, "guilds.members.read")
		}
		q := url.Values{"response_type": {"code"}, "client_id": {p.ClientID}, "redirect_uri": {redirectURI},
			"scope": {strings.Join(scopes, " ")}, "state": {f.State},
			"code_challenge": {challenge(f.Verifier)}, "code_challenge_method": {"S256"}}
		return p.ep().DiscordAuth + "?" + q.Encode(), f, nil
	case config.MethodGoogle, config.MethodMicrosoft:
		d, err := p.discovery(ctx)
		if err != nil {
			return "", f, err
		}
		f.Verifier, f.Nonce = random(48), random(24)
		q := url.Values{"response_type": {"code"}, "client_id": {p.ClientID}, "redirect_uri": {redirectURI},
			"scope": {"openid email profile"}, "state": {f.State}, "nonce": {f.Nonce},
			"code_challenge": {challenge(f.Verifier)}, "code_challenge_method": {"S256"}}
		if p.Method == config.MethodGoogle {
			q.Set("prompt", "select_account")
		} else {
			q.Set("response_mode", "query")
			q.Set("prompt", "select_account")
		}
		return d.AuthorizationEndpoint + "?" + q.Encode(), f, nil
	}
	return "", f, fmt.Errorf("unknown provider %q", p.Method)
}

func challenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// Finish completes a sign-in on the callback. q is the callback's query;
// redirectURI must be the one Start used. The flow must come from the
// caller's sealed cookie (its expiry is checked here).
func (p *Provider) Finish(ctx context.Context, redirectURI string, f Flow, q url.Values) (*Identity, error) {
	if f.Method != p.Method || time.Now().After(f.Expires) || f.State == "" {
		return nil, ErrState
	}
	if p.Method == config.MethodSteam {
		// Steam carries the state in return_to (checked exactly).
		return p.steamFinish(ctx, redirectURI, f, q)
	}
	if subtle.ConstantTimeCompare([]byte(q.Get("state")), []byte(f.State)) != 1 {
		return nil, ErrState
	}
	if e := q.Get("error"); e != "" {
		if e == "access_denied" {
			return nil, userErr("sign-in was cancelled at %s", Title(p.Method))
		}
		return nil, userErr("%s refused the sign-in (%s)", Title(p.Method), truncate(e, 64))
	}
	code := q.Get("code")
	if code == "" || len(code) > 4096 {
		return nil, userErr("%s returned no authorization code", Title(p.Method))
	}
	switch p.Method {
	case config.MethodDiscord:
		return p.discordFinish(ctx, redirectURI, f, code)
	case config.MethodGoogle, config.MethodMicrosoft:
		return p.oidcFinish(ctx, redirectURI, f, code)
	}
	return nil, fmt.Errorf("unknown provider %q", p.Method)
}

// Title is the provider's display name.
func Title(method string) string {
	switch method {
	case config.MethodDiscord:
		return "Discord"
	case config.MethodGoogle:
		return "Google"
	case config.MethodMicrosoft:
		return "Microsoft"
	case config.MethodSteam:
		return "Steam"
	}
	return method
}

// tokenResponse is an OAuth token endpoint answer.
type tokenResponse struct {
	AccessToken string `json:"access_token"`
	IDToken     string `json:"id_token"`
	TokenType   string `json:"token_type"`
	Error       string `json:"error"`
}

// exchange redeems an authorization code with the PKCE verifier.
func (p *Provider) exchange(ctx context.Context, tokenURL, redirectURI, code, verifier string) (*tokenResponse, error) {
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {redirectURI},
		"client_id": {p.ClientID}, "client_secret": {p.ClientSecret}, "code_verifier": {verifier}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	var tr tokenResponse
	status, err := p.doJSON(req, &tr)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK || tr.AccessToken == "" {
		// The error code only (never the request, which holds the secret).
		return nil, fmt.Errorf("%s token endpoint: HTTP %d %s", p.Method, status, truncate(tr.Error, 64))
	}
	return &tr, nil
}

// maxBody bounds provider responses.
const maxBody = 1 << 20

// doJSON performs req and decodes a JSON body into v (also for error
// statuses, where v may stay empty). Errors never include the URL, which
// may carry parameters.
func (p *Provider) doJSON(req *http.Request, v any) (int, error) {
	resp, err := p.client().Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return 0, fmt.Errorf("%s: %s %s: %w", p.Method, req.Method, req.URL.Host, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return resp.StatusCode, fmt.Errorf("%s: reading %s: %w", p.Method, req.URL.Host, err)
	}
	if len(body) > 0 && v != nil {
		if err := json.Unmarshal(body, v); err != nil && resp.StatusCode < 300 {
			return resp.StatusCode, fmt.Errorf("%s: %s %s: invalid JSON", p.Method, req.Method, req.URL.Host)
		}
	}
	return resp.StatusCode, nil
}

func (p *Provider) getJSON(ctx context.Context, u, bearer string, v any) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Accept", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	return p.doJSON(req, v)
}

func truncate(s string, n int) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
	if len(s) > n {
		return s[:n]
	}
	return s
}

// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/ingressd/ingressd/internal/secrets"
	"github.com/ingressd/ingressd/pkg/access/idp/idptest"
	"github.com/ingressd/ingressd/pkg/config"
)

const (
	guildA = "100000000000000001"
	roleA  = "200000000000000001"
	steamA = "76561198000000001"
)

const providerConfig = `
version: 1
edge: { acme: { ca: internal } }
email: { provider: log, log: { path: /tmp/mail.log } }
access:
  portal_host: auth.example.com
  providers:
    discord: { client_id: client-1, client_secret: secret://discord }
    google: { client_id: client-1, client_secret: secret://google }
    microsoft: { client_id: client-1, client_secret: secret://ms, session: 1h }
    steam: { api_key: secret://steamkey }
policies:
  mods:
    action: allow
    include: [{ discord_role: ["` + guildA + `/` + roleA + `"] }]
  gamers:
    action: allow
    include: [{ steam_app: ["440"] }]
    require: [{ login_method: [steam] }]
  workspace:
    action: allow
    include: [{ google_hd: [corp.example] }]
  staff:
    action: allow
    include: [{ email_domain: [corp.example] }]
apps:
  web:
    hosts: [web.example.com]
    origin: http://192.0.2.10:80
    access: [mods, gamers, workspace, staff]
    login_methods: [discord, steam, google, microsoft]
  mail:
    hosts: [mail.example.com]
    origin: http://192.0.2.11:80
    access: [staff]
`

func newProviderPortal(t *testing.T) (*portalEnv, *idptest.Server) {
	t.Helper()
	dir := t.TempDir()
	cfg, err := config.Parse([]byte(providerConfig))
	if err != nil {
		t.Fatal(err)
	}
	cfg.Email.Log.Path = filepath.Join(dir, "mail.log")
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	st := secrets.NewMemory(map[string]string{"discord": "secret-1", "google": "secret-1", "ms": "secret-1", "steamkey": "steam-key"})
	if _, err := EnsureKeys(cfg, st); err != nil {
		t.Fatal(err)
	}
	svc, err := Open(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = svc.Close() })
	if err := svc.Update(cfg, st); err != nil {
		t.Fatal(err)
	}
	f := idptest.New("client-1", "secret-1", "steam-key").Start()
	t.Cleanup(f.Close)
	for _, p := range svc.st.providers {
		p.Endpoints = f.Endpoints()
	}
	keys, _ := LoadKeys(st)
	return &portalEnv{t: t, svc: svc, h: svc.PortalHandler(), api: svc.EdgeAPIHandler(), keys: keys, mail: cfg.Email.Log.Path}, f
}

// providerSignIn runs a provider sign-in like a browser and returns the
// portal's answer to the callback.
func (p *portalEnv) providerSignIn(method, app, rd string) *httptest.ResponseRecorder {
	p.t.Helper()
	form := url.Values{"provider": {method}, "app": {app}, "rd": {rd}, "n": {FlowNonceHash(testNonce)}}
	w := p.do("POST", "/oauth/start", form, "198.51.100.7")
	if w.Code != http.StatusSeeOther {
		p.t.Fatalf("start: %d %s", w.Code, w.Body)
	}
	flow := cookieFrom(w, "__edge_idp")
	if flow == nil || flow.Path != "/oauth/" || !flow.HttpOnly || !flow.Secure {
		p.t.Fatalf("flow cookie %+v", flow)
	}
	c := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := c.Get(w.Header().Get("Location"))
	if err != nil {
		p.t.Fatal(err)
	}
	_ = resp.Body.Close()
	cb, _ := url.Parse(resp.Header.Get("Location"))
	if cb.Host != "auth.example.com" || cb.Path != "/oauth/"+method+"/callback" {
		p.t.Fatalf("provider redirected to %s", cb)
	}
	return p.do("GET", cb.RequestURI(), nil, "198.51.100.7", flow)
}

func TestProviderLoginPage(t *testing.T) {
	p, _ := newProviderPortal(t)
	rd := "https://web.example.com/x"
	w := p.do("GET", "/login?"+url.Values{"app": {"web"}, "rd": {rd}}.Encode(), nil, "198.51.100.7")
	body := w.Body.String()
	for _, want := range []string{"Continue with Discord", "Continue with Steam", "Continue with Google", "Continue with Microsoft", `action="/oauth/start"`} {
		if !strings.Contains(body, want) {
			t.Errorf("login page lacks %q", want)
		}
	}
	if strings.Contains(body, `name="step" value="email"`) {
		t.Error("email form shown although web does not offer email")
	}
	if csp := w.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "form-action 'self' https://discord.com") {
		t.Errorf("CSP %q", csp)
	}
	// mail: email only.
	w = p.do("GET", "/login?"+url.Values{"app": {"mail"}, "rd": {"https://mail.example.com/"}}.Encode(), nil, "198.51.100.7")
	if strings.Contains(w.Body.String(), "Continue with") || !strings.Contains(w.Body.String(), `value="email"`) {
		t.Error("mail should offer email only")
	}
}

func TestProviderSignInDiscord(t *testing.T) {
	p, f := newProviderPortal(t)
	rd := "https://web.example.com/x"
	f.SetUser("discord", idptest.User{Sub: "300000000000000003", Username: "ann", Email: "ann@mail.example", EmailVerified: true,
		Guilds: []string{guildA, "100000000000000099"}, Members: map[string][]string{guildA: {roleA, "200000000000000077"}}})
	w := p.providerSignIn("discord", "web", rd)
	loc := w.Header().Get("Location")
	if w.Code != http.StatusFound || !strings.HasPrefix(loc, "https://web.example.com/.ingressd/callback?code=") {
		t.Fatalf("callback: %d %s %s", w.Code, loc, w.Body)
	}
	portal := cookieFrom(w, PortalCookieName)
	pc, err := p.keys.OpenPortal(portal.Value)
	if err != nil || pc.Method != "discord" || pc.Email != "ann@mail.example" {
		t.Fatalf("portal claims %+v %v", pc, err)
	}
	// Only the facts the policies refer to are kept.
	if !slices.Equal(pc.Attrs, []string{"discord_role:" + guildA + "/" + roleA}) {
		t.Errorf("attrs %v", pc.Attrs)
	}
	u, _ := url.Parse(loc)
	ew, er := p.exchange(u.Query().Get("code"), "web", "web.example.com")
	if ew.Code != http.StatusOK {
		t.Fatalf("exchange: %d %s", ew.Code, ew.Body)
	}
	ac, err := p.keys.OpenApp("web", er.Token)
	if err != nil || ac.Method != "discord" || ac.Grants["mods"] == "" {
		t.Fatalf("app claims %+v %v", ac, err)
	}

	// Not in the role: denied at the portal.
	f.SetUser("discord", idptest.User{Sub: "300000000000000004", Username: "bob", Guilds: []string{guildA}, Members: map[string][]string{guildA: {}}})
	if w := p.providerSignIn("discord", "web", rd); w.Code != http.StatusForbidden {
		t.Fatalf("non-member: %d %s", w.Code, w.Body)
	}
}

func TestProviderSignInSteam(t *testing.T) {
	p, f := newProviderPortal(t)
	f.SetUser("steam", idptest.User{SteamID: steamA, SteamApps: []int64{440}})
	w := p.providerSignIn("steam", "web", "https://web.example.com/")
	if w.Code != http.StatusFound {
		t.Fatalf("steam: %d %s", w.Code, w.Body)
	}
	u, _ := url.Parse(w.Header().Get("Location"))
	_, er := p.exchange(u.Query().Get("code"), "web", "web.example.com")
	ac, err := p.keys.OpenApp("web", er.Token)
	if err != nil || ac.Email != "steam:"+steamA || ac.Grants["gamers"] == "" || !slices.Contains(ac.Attrs, "steam_app:440") {
		t.Fatalf("app claims %+v %v", ac, err)
	}
	// Without the game: denied.
	f.SetUser("steam", idptest.User{SteamID: steamA})
	if w := p.providerSignIn("steam", "web", "https://web.example.com/"); w.Code != http.StatusForbidden {
		t.Fatalf("no game: %d", w.Code)
	}
}

func TestProviderSignInGoogleAndMicrosoft(t *testing.T) {
	p, f := newProviderPortal(t)
	f.SetUser("google", idptest.User{Sub: "1", Email: "ann@corp.example", EmailVerified: true, HD: "corp.example"})
	if w := p.providerSignIn("google", "web", "https://web.example.com/"); w.Code != http.StatusFound {
		t.Fatalf("google: %d %s", w.Code, w.Body)
	}
	// An unverified Google email does not satisfy email_domain.
	f.SetUser("google", idptest.User{Sub: "2", Email: "eve@corp.example"})
	if w := p.providerSignIn("google", "web", "https://web.example.com/"); w.Code != http.StatusForbidden {
		t.Fatalf("unverified email allowed: %d", w.Code)
	}
	// Entra account with a tenant-verified domain: email_domain applies,
	// and the provider session (1h) caps the portal session.
	f.SetUser("microsoft", idptest.User{Sub: "s", OID: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", TID: "11111111-2222-3333-4444-555555555555", Email: "joe@corp.example", Edov: true})
	w := p.providerSignIn("microsoft", "web", "https://web.example.com/")
	if w.Code != http.StatusFound {
		t.Fatalf("microsoft: %d %s", w.Code, w.Body)
	}
	pc, _ := p.keys.OpenPortal(cookieFrom(w, PortalCookieName).Value)
	if d := pc.Expires.Sub(pc.Issued); d > 61*60e9 {
		t.Errorf("provider session not capped: %v", d)
	}
}

func TestProviderFlowChecks(t *testing.T) {
	p, f := newProviderPortal(t)
	f.SetUser("discord", idptest.User{Sub: "300000000000000003", Username: "ann"})
	form := url.Values{"provider": {"discord"}, "app": {"web"}, "rd": {"https://web.example.com/"}}
	// Cross-site start.
	r := httptest.NewRequest("POST", "https://auth.example.com/oauth/start", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Origin", "https://evil.example")
	w := httptest.NewRecorder()
	p.h.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Errorf("cross-site start: %d", w.Code)
	}
	// Open redirect.
	bad := url.Values{"provider": {"discord"}, "app": {"web"}, "rd": {"https://evil.example/"}}
	if w := p.do("POST", "/oauth/start", bad, "1.2.3.4"); w.Code != http.StatusBadRequest {
		t.Errorf("foreign rd: %d", w.Code)
	}
	// A method the app does not offer.
	off := url.Values{"provider": {"discord"}, "app": {"mail"}, "rd": {"https://mail.example.com/"}}
	if w := p.do("POST", "/oauth/start", off, "1.2.3.4"); w.Code != http.StatusBadRequest {
		t.Errorf("method not offered: %d", w.Code)
	}
	// Callback without the flow cookie (another browser).
	w = p.do("POST", "/oauth/start", form, "1.2.3.4")
	c := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := c.Get(w.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	cb, _ := url.Parse(resp.Header.Get("Location"))
	if w := p.do("GET", cb.RequestURI(), nil, "1.2.3.4"); w.Code != http.StatusBadRequest {
		t.Errorf("callback without flow cookie: %d", w.Code)
	}
	// The flow cookie of another sign-in.
	other := cookieFrom(p.do("POST", "/oauth/start", form, "1.2.3.4"), "__edge_idp")
	if w := p.do("GET", cb.RequestURI(), nil, "1.2.3.4", other); w.Code != http.StatusForbidden {
		t.Errorf("callback with another flow: %d", w.Code)
	}
}

func TestEdgeConfigIdentity(t *testing.T) {
	cfg, err := config.Parse([]byte(strings.Replace(providerConfig, "policies:\n", `service_tokens:
  bot: { header: X-Bot-Token, client_secret: secret://bot }
policies:
  bot:
    action: service_auth
    include: [{ service_token: bot }]
`, 1)))
	if err != nil {
		t.Fatal(err)
	}
	app := cfg.Apps["web"]
	app.Access = append([]string{"bot"}, app.Access...)
	cfg.Apps["web"] = app
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	st := secrets.NewMemory(map[string]string{"bot": "0123456789abcdef"})
	if _, err := EnsureKeys(cfg, st); err != nil {
		t.Fatal(err)
	}
	ec, err := BuildEdgeConfig(cfg, st, "web", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(ec.ServiceTokens) != 1 || ec.ServiceTokens[0].Header != "X-Bot-Token" || ec.ServiceTokens[0].ClientID != "" {
		t.Errorf("tokens %+v", ec.ServiceTokens)
	}
	mods := ec.Policies["mods"]
	if mods.Offline || !slices.Equal(mods.Include[0].Attr, []string{"discord_role:" + guildA + "/" + roleA}) {
		t.Errorf("mods %+v", mods)
	}
	if g := ec.Policies["gamers"]; !slices.Equal(g.Require[0].Attr, []string{"login_method:steam"}) {
		t.Errorf("gamers %+v", g)
	}
	// Header token secrets must be long.
	short := secrets.NewMemory(map[string]string{"bot": "short"})
	_, _ = EnsureKeys(cfg, short)
	if _, err := BuildEdgeConfig(cfg, short, "web", ""); err == nil || !strings.Contains(err.Error(), "at least 16") {
		t.Errorf("short secret: %v", err)
	}
}

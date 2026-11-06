// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/ingressd/ingressd/internal/secrets"
)

type portalEnv struct {
	t    *testing.T
	svc  *Service
	h    http.Handler
	api  http.Handler
	keys *Keys
	mail string
}

func newPortal(t *testing.T) *portalEnv {
	t.Helper()
	dir := t.TempDir()
	mail := filepath.Join(dir, "mail.log")
	cfg := testConfig(t)
	cfg.Email.Log.Path = mail
	st := secrets.NewMemory(map[string]string{"hook": "hook-secret"})
	if changed, err := EnsureKeys(cfg, st); err != nil || !changed {
		t.Fatalf("EnsureKeys = %v, %v", changed, err)
	}
	if changed, _ := EnsureKeys(cfg, st); changed {
		t.Fatal("EnsureKeys regenerated existing keys")
	}
	svc, err := Open(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { svc.Close() })
	if err := svc.Update(cfg, st); err != nil {
		t.Fatal(err)
	}
	keys, _ := LoadKeys(st)
	return &portalEnv{t: t, svc: svc, h: svc.PortalHandler(), api: svc.EdgeAPIHandler(), keys: keys, mail: mail}
}

func (p *portalEnv) do(method, target string, form url.Values, ip string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	var body *strings.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	} else {
		body = strings.NewReader("")
	}
	r := httptest.NewRequest(method, "https://auth.example.com"+target, body)
	if form != nil {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	r.Header.Set("X-Forwarded-For", ip)
	if method == "POST" {
		r.Header.Set("Origin", "https://auth.example.com") // a same-origin form post
	}
	for _, c := range cookies {
		r.AddCookie(c)
	}
	w := httptest.NewRecorder()
	p.h.ServeHTTP(w, r)
	return w
}

var codeRe = regexp.MustCompile(`To: (\S+)\nSubject: Your sign-in code for [^\n]*\n\n(?s:.*?)Your sign-in code is: (\d+)`)

// code waits for the latest code mailed to email.
func (p *portalEnv) code(email string) string {
	p.t.Helper()
	for i := 0; i < 100; i++ {
		b, _ := os.ReadFile(p.mail)
		last := ""
		for _, m := range codeRe.FindAllStringSubmatch(string(b), -1) {
			if m[1] == email {
				last = m[2]
			}
		}
		if last != "" {
			return last
		}
		time.Sleep(20 * time.Millisecond)
	}
	p.t.Fatalf("no code mailed to %s", email)
	return ""
}

func (p *portalEnv) exchange(code, app, host string) (*httptest.ResponseRecorder, ExchangeResponse) {
	return p.exchangeNonce(code, app, host, testNonce)
}

func (p *portalEnv) exchangeNonce(code, app, host, nonce string) (*httptest.ResponseRecorder, ExchangeResponse) {
	b, _ := json.Marshal(ExchangeRequest{Code: code, App: app, Host: host, Nonce: nonce})
	r := httptest.NewRequest("POST", "http://"+ControlHost+"/v1/exchange", bytes.NewReader(b))
	w := httptest.NewRecorder()
	p.api.ServeHTTP(w, r)
	var er ExchangeResponse
	json.Unmarshal(w.Body.Bytes(), &er)
	return w, er
}

func cookieFrom(w *httptest.ResponseRecorder, name string) *http.Cookie {
	for _, c := range w.Result().Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

const rd = "https://web.example.com/docs?page=2"

// testNonce is the browser's sign-in nonce cookie (edge_auth sets it and
// passes its hash to the portal as "n").
const testNonce = "Zm9yLXRlc3RzLW9ubHktMzItYnl0ZXMtbm9uY2UhISE"

func loginForm(step, email, code string) url.Values {
	return url.Values{"app": {"web"}, "rd": {rd}, "n": {FlowNonceHash(testNonce)}, "step": {step}, "email": {email}, "code": {code}}
}

func TestPortalLoginFlow(t *testing.T) {
	p := newPortal(t)
	q := "/login?" + url.Values{"app": {"web"}, "rd": {rd}, "n": {FlowNonceHash(testNonce)}}.Encode()

	if w := p.do("GET", q, nil, "198.51.100.7"); w.Code != 200 || !strings.Contains(w.Body.String(), `name="step" value="email"`) {
		t.Fatalf("login page: %d %s", w.Code, w.Body)
	}

	// Request a code for an allowed and an unknown email: same response.
	w1 := p.do("POST", "/login", loginForm("email", "alice@gmail.com", ""), "198.51.100.7")
	w2 := p.do("POST", "/login", loginForm("email", "nobody@nowhere.test", ""), "198.51.100.8")
	b1 := strings.ReplaceAll(w1.Body.String(), "alice@gmail.com", "X")
	b2 := strings.ReplaceAll(w2.Body.String(), "nobody@nowhere.test", "X")
	if w1.Code != 200 || w1.Code != w2.Code || b1 != b2 {
		t.Fatalf("responses differ (enumeration):\n%d %s\n%d %s", w1.Code, b1, w2.Code, b2)
	}
	// The code form redirects to the app's callback once verified: a
	// form-action of 'self' alone makes browsers block that redirect, so
	// the visitor is signed in on the portal but never sent back to rd.
	if csp := w1.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "form-action 'self' https://web.example.com;") {
		t.Errorf("code page CSP does not allow the app's callback: %q", csp)
	}
	if csp := p.do("GET", "/login", nil, "198.51.100.7").Header().Get("Content-Security-Policy"); !strings.Contains(csp, "form-action 'self';") {
		t.Errorf("login without a target: CSP %q", csp)
	}
	code := p.code("alice@gmail.com")
	if b, _ := os.ReadFile(p.mail); strings.Contains(string(b), "nobody@nowhere.test") {
		t.Fatal("code sent to an email no policy allows")
	}

	// Wrong code, then the right one.
	if w := p.do("POST", "/login", loginForm("code", "alice@gmail.com", "000000"), "198.51.100.7"); w.Code != 401 {
		t.Fatalf("wrong code: %d", w.Code)
	}
	w := p.do("POST", "/login", loginForm("code", "alice@gmail.com", code), "198.51.100.7")
	loc, _ := url.Parse(w.Header().Get("Location"))
	if w.Code != 302 || loc.Host != "web.example.com" || loc.Path != "/.ingressd/callback" {
		t.Fatalf("verify: %d %q", w.Code, w.Header().Get("Location"))
	}
	portal := cookieFrom(w, PortalCookieName)
	if portal == nil || !portal.HttpOnly || !portal.Secure {
		t.Fatalf("portal cookie %+v", portal)
	}
	if w := p.do("POST", "/login", loginForm("code", "alice@gmail.com", code), "198.51.100.7"); w.Code != 401 {
		t.Fatalf("code reused: %d", w.Code)
	}

	// Exchange: wrong host, then right host, then replay.
	authCode := loc.Query().Get("code")
	if w, _ := p.exchange(authCode, "other", "web.example.com"); w.Code != 403 {
		t.Fatalf("exchange for another app: %d", w.Code)
	}
	if w, er := p.exchange(authCode, "web", "web.example.com"); w.Code != 200 || er.RD != rd {
		t.Fatalf("exchange: %d %s", w.Code, w.Body)
	} else {
		c, err := p.keys.OpenApp("web", er.Token)
		if err != nil || c.Email != "alice@gmail.com" || c.Grants["family-or-work"] == "" {
			t.Fatalf("token %+v %v", c, err)
		}
		if d := time.Until(c.Expires); d > 12*time.Hour || d < 11*time.Hour {
			t.Errorf("cookie lifetime %s, want the policy's 12h", d)
		}
	}
	if w, _ := p.exchange(authCode, "web", "web.example.com"); w.Code != 403 {
		t.Fatalf("code replay: %d", w.Code)
	}

	// The portal session skips the OTP.
	w = p.do("GET", q, nil, "198.51.100.7", portal)
	loc, _ = url.Parse(w.Header().Get("Location"))
	if w.Code != 302 || loc.Path != "/.ingressd/callback" {
		t.Fatalf("portal session: %d %s", w.Code, w.Body)
	}
	if w, _ := p.exchange(loc.Query().Get("code"), "web", "evil.example.com"); w.Code != 403 {
		t.Fatalf("exchange on another host: %d", w.Code)
	}

	// GET /logout only asks; a cross-site POST is refused.
	if w := p.do("GET", "/logout", nil, "198.51.100.7", portal); w.Code != 200 || !strings.Contains(w.Body.String(), `<form method="post" action="/logout">`) {
		t.Fatalf("logout confirmation: %d %s", w.Code, w.Body)
	}
	cross := httptest.NewRequest("POST", "https://auth.example.com/logout", nil)
	cross.Header.Set("Origin", "https://evil.example")
	cross.AddCookie(portal)
	cw := httptest.NewRecorder()
	if p.h.ServeHTTP(cw, cross); cw.Code != 403 {
		t.Fatalf("cross-site logout: %d", cw.Code)
	}
	if rl := revocations(p); len(rl.SIDs) != 0 {
		t.Fatalf("revoked without a same-origin POST: %+v", rl)
	}
	// Logout revokes the session globally.
	if w := p.do("POST", "/logout", nil, "198.51.100.7", portal); w.Code != 200 {
		t.Fatalf("logout: %d", w.Code)
	}
	r := httptest.NewRequest("GET", "http://"+ControlHost+"/v1/revocations", nil)
	rw := httptest.NewRecorder()
	p.api.ServeHTTP(rw, r)
	var rl RevocationList
	json.Unmarshal(rw.Body.Bytes(), &rl)
	if rl.Revision != 1 || len(rl.SIDs) != 1 {
		t.Fatalf("revocations %+v", rl)
	}
	r.Header.Set("If-None-Match", rw.Header().Get("ETag"))
	rw = httptest.NewRecorder()
	p.api.ServeHTTP(rw, r)
	if rw.Code != http.StatusNotModified {
		t.Fatalf("revocations with matching ETag: %d", rw.Code)
	}
	if w := p.do("GET", q, nil, "198.51.100.7", portal); w.Code != 200 {
		t.Fatalf("revoked portal session still accepted: %d", w.Code)
	}
}

func TestPortalRejectsOpenRedirect(t *testing.T) {
	p := newPortal(t)
	for _, bad := range []string{
		"https://evil.com/",
		"http://web.example.com/",
		"https://web.example.com.evil.com/",
		"https://evil.com\\@web.example.com/",
		"https://user@web.example.com/",
		"//evil.com/",
		"javascript:alert(1)",
		"https://a;sandbox.lab.example.com/", // would break out of the CSP source list
		"https://a,b.lab.example.com/",
	} {
		q := "/login?" + url.Values{"app": {"web"}, "rd": {bad}}.Encode()
		if w := p.do("GET", q, nil, "198.51.100.7"); w.Code != 400 {
			t.Errorf("rd=%q accepted: %d", bad, w.Code)
		}
	}
	if w := p.do("GET", "/login?"+url.Values{"app": {"open"}, "rd": {"https://open.example.com/"}}.Encode(), nil, "1.1.1.1"); w.Code != 400 {
		t.Errorf("unprotected app accepted: %d", w.Code)
	}
	if w := p.do("GET", "/login?"+url.Values{"app": {"web"}, "rd": {"https://x.lab.example.com/"}}.Encode(), nil, "1.1.1.1"); w.Code != 200 {
		t.Errorf("wildcard host rejected: %d", w.Code)
	}
}

func TestPortalLockout(t *testing.T) {
	p := newPortal(t)
	p.do("POST", "/login", loginForm("email", "bob@outlook.com", ""), "198.51.100.9")
	code := p.code("bob@outlook.com")
	for i := 0; i < 5; i++ {
		p.do("POST", "/login", loginForm("code", "bob@outlook.com", "999999"), "198.51.100.9")
	}
	if w := p.do("POST", "/login", loginForm("code", "bob@outlook.com", code), "198.51.100.9"); w.Code != 401 {
		t.Fatalf("correct code accepted after lockout: %d", w.Code)
	}
	if w := p.do("POST", "/login", loginForm("email", "bob@outlook.com", ""), "198.51.100.9"); w.Code != 429 {
		t.Fatalf("new code allowed during lockout: %d", w.Code)
	}
}

func TestPortalLockoutIsPerAddress(t *testing.T) {
	p := newPortal(t)
	for i := 0; i < 5; i++ {
		p.do("POST", "/login", loginForm("code", "alice@gmail.com", "999999"), "198.51.100.9")
	}
	if w := p.do("POST", "/login", loginForm("email", "alice@gmail.com", ""), "198.51.100.9"); w.Code != 429 {
		t.Fatalf("code request from the locked address: %d", w.Code)
	}
	if w := p.do("POST", "/login", loginForm("email", "alice@gmail.com", ""), "198.51.100.7"); w.Code != 200 {
		t.Fatalf("code request from another address: %d", w.Code)
	}
	code := p.code("alice@gmail.com")
	if w := p.do("POST", "/login", loginForm("code", "alice@gmail.com", code), "198.51.100.9"); w.Code != 401 {
		t.Fatalf("code accepted from the locked address: %d", w.Code)
	}
	if w := p.do("POST", "/login", loginForm("code", "alice@gmail.com", code), "198.51.100.7"); w.Code != http.StatusFound {
		t.Fatalf("sign-in from another address: %d", w.Code)
	}
}

func TestPortalFormLimits(t *testing.T) {
	p := newPortal(t)
	big := url.Values{"step": {"email"}, "email": {"bob@outlook.com"}, "pad": {strings.Repeat("x", maxFormBytes)}}
	if w := p.do("POST", "/login", big, "198.51.100.11"); w.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("oversized form: %d", w.Code)
	}

	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	_ = mw.WriteField("step", "email")
	_ = mw.WriteField("email", "bob@outlook.com")
	mw.Close()
	r := httptest.NewRequest("POST", "https://auth.example.com/login", &body)
	r.Header.Set("Content-Type", mw.FormDataContentType())
	r.Header.Set("Origin", "https://auth.example.com")
	w := httptest.NewRecorder()
	p.h.ServeHTTP(w, r)
	if r.MultipartForm != nil || !strings.Contains(w.Body.String(), "valid email") {
		t.Errorf("multipart form was read: %d %s", w.Code, w.Body)
	}
}

func TestPortalDeniedEmail(t *testing.T) {
	p := newPortal(t)
	// eve is in the work domain (could be allowed) but denied by policy.
	p.do("POST", "/login", loginForm("email", "eve@example.com", ""), "198.51.100.10")
	code := p.code("eve@example.com")
	w := p.do("POST", "/login", loginForm("code", "eve@example.com", code), "198.51.100.10")
	if w.Code != 403 || !strings.Contains(w.Body.String(), "not allowed") {
		t.Fatalf("denied email: %d %s", w.Code, w.Body)
	}
}

// Cloudflare's Email Address Obfuscation must leave portal pages alone:
// addresses sit between email_off markers and responses say no-transform.
func TestPortalEmailObfuscationOff(t *testing.T) {
	p := newPortal(t)
	w := p.do("POST", "/login", loginForm("email", "alice@gmail.com", ""), "198.51.100.7")
	if cc := w.Header().Get("Cache-Control"); cc != "no-store, no-transform" {
		t.Errorf("Cache-Control = %q", cc)
	}
	body := w.Body.String()
	on, off := strings.Index(body, "<!--email_off-->"), strings.LastIndex(body, "<!--/email_off-->")
	if on < 0 || off < on || !strings.Contains(body[on:off], "A code is on its way to alice@gmail.com") || strings.Count(body, "alice@gmail.com") != strings.Count(body[on:off], "alice@gmail.com") {
		t.Fatalf("addresses not inside email_off markers:\n%s", body)
	}
}

// A callback code only works in the browser that started the sign-in, so
// an attacker cannot plant a code for their own account (login fixation).
func TestCallbackBoundToBrowser(t *testing.T) {
	p := newPortal(t)
	p.do("POST", "/login", loginForm("email", "alice@gmail.com", ""), "198.51.100.7")
	w := p.do("POST", "/login", loginForm("code", "alice@gmail.com", p.code("alice@gmail.com")), "198.51.100.7")
	portal := cookieFrom(w, PortalCookieName)
	if portal == nil {
		t.Fatalf("sign-in: %d %s", w.Code, w.Body)
	}
	codeFor := func(q url.Values) string {
		t.Helper()
		w := p.do("GET", "/login?"+q.Encode(), nil, "198.51.100.7", portal)
		loc, _ := url.Parse(w.Header().Get("Location"))
		if w.Code != 302 {
			t.Fatalf("code: %d %s", w.Code, w.Body)
		}
		return loc.Query().Get("code")
	}
	bound := url.Values{"app": {"web"}, "rd": {rd}, "n": {FlowNonceHash(testNonce)}}
	for name, nonce := range map[string]string{"another browser's nonce": "b3RoZXItYnJvd3Nlci1ub25jZS0zMi1ieXRlcy1sb25n", "no nonce cookie": ""} {
		if w, _ := p.exchangeNonce(codeFor(bound), "web", "web.example.com", nonce); w.Code != 403 {
			t.Errorf("%s: %d", name, w.Code)
		}
	}
	// A code minted without "n" (an attacker visiting the portal directly).
	if w, _ := p.exchangeNonce(codeFor(url.Values{"app": {"web"}, "rd": {rd}}), "web", "web.example.com", testNonce); w.Code != 403 {
		t.Errorf("unbound code: %d", w.Code)
	}
	if w, _ := p.exchange(codeFor(bound), "web", "web.example.com"); w.Code != 200 {
		t.Fatalf("same browser: %d %s", w.Code, w.Body)
	}
	if w := p.do("GET", "/login?"+url.Values{"app": {"web"}, "rd": {rd}, "n": {"short"}}.Encode(), nil, "198.51.100.7", portal); w.Code != 400 {
		t.Errorf("malformed n: %d", w.Code)
	}
}

func TestPortalCrossSitePost(t *testing.T) {
	p := newPortal(t)
	for _, tc := range []struct {
		name string
		hdr  map[string]string
		want int
	}{
		{"cross-site origin", map[string]string{"Origin": "https://evil.com"}, 403},
		{"same origin", map[string]string{"Origin": "https://auth.example.com"}, 200},
		{"null origin, cross-site fetch", map[string]string{"Origin": "null", "Sec-Fetch-Site": "cross-site"}, 403},
		{"null origin, same-origin fetch", map[string]string{"Origin": "null", "Sec-Fetch-Site": "same-origin"}, 200},
		{"referer only", map[string]string{"Referer": "https://auth.example.com/login"}, 200},
		{"cross-site referer", map[string]string{"Referer": "https://evil.com/x"}, 403},
		{"no origin, fetch metadata or referer", nil, 403},
	} {
		r := httptest.NewRequest("POST", "https://auth.example.com/login", strings.NewReader(loginForm("email", "alice@gmail.com", "").Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("X-Forwarded-For", "198.51.100.30")
		for k, v := range tc.hdr {
			r.Header.Set(k, v)
		}
		w := httptest.NewRecorder()
		p.h.ServeHTTP(w, r)
		if w.Code != tc.want {
			t.Errorf("%s: %d, want %d", tc.name, w.Code, tc.want)
		}
	}
}

func TestJWKS(t *testing.T) {
	p := newPortal(t)
	w := p.do("GET", "/.well-known/jwks.json", nil, "1.1.1.1")
	var set struct{ Keys []JWK }
	if err := json.Unmarshal(w.Body.Bytes(), &set); err != nil || len(set.Keys) != 1 || set.Keys[0].Kid != p.keys.KID || set.Keys[0].Crv != "P-256" {
		t.Fatalf("jwks %s", w.Body)
	}
}

func TestRateLimits(t *testing.T) {
	p := newPortal(t)
	o := &OTP{Store: p.svc.store, Settings: testConfig(t).Access.OTP}
	o.Settings.ResendCooldown = 0
	ctx := context.Background()
	for i := 0; i < 5; i++ {
		if send, err := o.Allow(ctx, "a@x.test", "10.0.0.1"); !send || err != nil {
			t.Fatalf("request %d: %v %v", i, send, err)
		}
	}
	if _, err := o.Allow(ctx, "a@x.test", "10.0.0.1"); err != ErrRateLimited {
		t.Fatalf("6th request per email: %v", err)
	}
	// Per IP: 20 codes across emails.
	for i := 0; i < 15; i++ {
		if _, err := o.Allow(ctx, "u"+string(rune('a'+i))+"@x.test", "10.0.0.1"); err != nil {
			t.Fatalf("ip request %d: %v", i, err)
		}
	}
	if _, err := o.Allow(ctx, "zz@x.test", "10.0.0.1"); err != ErrRateLimited {
		t.Fatalf("per-IP limit not applied: %v", err)
	}
	// Cooldown suppresses resends without an error.
	o.Settings = testConfig(t).Access.OTP
	if send, _ := o.Allow(ctx, "c@x.test", "10.0.0.2"); !send {
		t.Fatal("first request not sent")
	}
	if send, err := o.Allow(ctx, "c@x.test", "10.0.0.2"); send || err != nil {
		t.Fatalf("resend within cooldown: %v %v", send, err)
	}
}

func TestEdgeConfig(t *testing.T) {
	cfg := testConfig(t)
	st := secrets.NewMemory(map[string]string{"hook": "hook-secret"})
	EnsureKeys(cfg, st)
	ec, err := BuildEdgeConfig(cfg, st, "web", "/run/ingressd/control.sock")
	if err != nil {
		t.Fatal(err)
	}
	keys, _ := LoadKeys(st)
	if len(ec.ServiceTokens) != 1 || ec.ServiceTokens[0].Verifier != keys.ServiceTokenVerifier("hook-secret") {
		t.Fatalf("service tokens %+v", ec.ServiceTokens)
	}
	if p := ec.Policies["blocked"]; p.Offline || len(p.Include) != 2 || p.Include[0].Email[0] != "eve@example.com" || p.Include[1].Country[0] != "RU" {
		t.Errorf("identity deny policy: %+v", p)
	}
	if p := ec.Policies["public"]; !p.Offline || !p.Include[0].Everyone {
		t.Errorf("bypass policy %+v", p)
	}
	if ec.Policies["family-or-work"].Version != NewEngine(cfg).Version("family-or-work") {
		t.Error("version mismatch")
	}
	if _, err := BuildEdgeConfig(cfg, secrets.NewMemory(nil), "web", ""); err == nil {
		t.Error("missing keys not reported")
	}
}

func TestEmailTemplates(t *testing.T) {
	m, err := renderCodeEmail("a@b.test", codeEmail{Brand: testConfig(t).Access.Branding, App: "web", Code: "123456", IP: "1.2.3.4", TTL: "5 minutes"})
	if err != nil {
		t.Fatal(err)
	}
	if m.Subject != "Your sign-in code for web" || !strings.Contains(m.Text, "123456") || !strings.Contains(m.HTML, "solid #ff6b2c") {
		t.Fatalf("message %+v", m)
	}
	b, err := buildMIME("ingressd <login@example.com>", m)
	if err != nil || !bytes.Contains(b, []byte("multipart/alternative")) {
		t.Fatalf("mime %v", err)
	}
}

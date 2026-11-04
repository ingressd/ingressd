// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ingressd/ingressd/internal/secrets"
	"github.com/ingressd/ingressd/pkg/config"
	"github.com/ingressd/ingressd/pkg/nodeproto"
)

// fakePanel is the hosted panel as several nodes see it: it keeps the
// codes it "emailed" and relays revocations to every registered node.
type fakePanel struct {
	mu      sync.Mutex
	codes   map[string]string // email → code
	starts  []nodeproto.AuthOTPStart
	nodes   []*Service
	revokes []nodeproto.AuthRevoke
}

func (f *fakePanel) OTPStart(_ context.Context, req nodeproto.AuthOTPStart) (nodeproto.AuthOTPStartResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.starts = append(f.starts, req)
	f.codes[req.Email] = "424242"
	return nodeproto.AuthOTPStartResult{OK: true, Code: nodeproto.OTPOK, TTL: 10 * time.Minute}, nil
}

func (f *fakePanel) OTPVerify(_ context.Context, req nodeproto.AuthOTPVerify) (nodeproto.AuthOTPVerifyResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if c, ok := f.codes[req.Email]; ok && c == req.Code {
		delete(f.codes, req.Email)
		return nodeproto.AuthOTPVerifyResult{OK: true, Code: nodeproto.OTPOK, Email: req.Email}, nil
	}
	return nodeproto.AuthOTPVerifyResult{Code: nodeproto.OTPInvalid}, nil
}

func (f *fakePanel) ReportRevoke(r nodeproto.AuthRevoke) error {
	f.mu.Lock()
	f.revokes = append(f.revokes, r)
	nodes := append([]*Service(nil), f.nodes...)
	f.mu.Unlock()
	for _, n := range nodes { // the panel relays to every node (the origin ignores the repeat)
		if err := n.ApplyRemoteRevoke(context.Background(), r); err != nil {
			return err
		}
	}
	return nil
}

func (f *fakePanel) code(t *testing.T, email string) string {
	t.Helper()
	for i := 0; i < 200; i++ {
		f.mu.Lock()
		c := f.codes[email]
		f.mu.Unlock()
		if c != "" {
			return c
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("panel sent no code to %s", email)
	return ""
}

// orgSecrets are org-wide keys as the panel delivers them.
func orgSecrets(t *testing.T) map[string]string {
	t.Helper()
	k := make([]byte, 32)
	rand.Read(k)
	ek, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKCS8PrivateKey(ek)
	return map[string]string{
		"org_access_session_key": base64.StdEncoding.EncodeToString(k),
		"org_access_jwt_key":     base64.StdEncoding.EncodeToString(der),
	}
}

func hostedConfig(t *testing.T) *config.Config {
	t.Helper()
	cfg := testConfig(t)
	cfg.Email = config.Email{Provider: config.EmailPanel}
	cfg.Access.SessionKey = "secret://org_access_session_key"
	cfg.Access.JWTKey = "secret://org_access_jwt_key"
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	return cfg
}

// hostedNode is one node of an org with org-wide keys.
func hostedNode(t *testing.T, cfg *config.Config, sec map[string]string) *portalEnv {
	t.Helper()
	dir := t.TempDir()
	st := secrets.NewMemory(sec)
	if changed, err := EnsureKeys(cfg, st); err != nil || changed {
		t.Fatalf("EnsureKeys with org keys = %v, %v (must not generate)", changed, err)
	}
	svc, err := Open(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = svc.Close() })
	if err := svc.Update(cfg, st); err != nil {
		t.Fatal(err)
	}
	keys, err := LoadConfigKeys(cfg, st)
	if err != nil {
		t.Fatal(err)
	}
	return &portalEnv{t: t, svc: svc, h: svc.PortalHandler(), api: svc.EdgeAPIHandler(), keys: keys}
}

func revocations(p *portalEnv) RevocationList {
	r := httptest.NewRequest("GET", "http://"+ControlHost+"/v1/revocations", nil)
	w := httptest.NewRecorder()
	p.api.ServeHTTP(w, r)
	var rl RevocationList
	_ = json.Unmarshal(w.Body.Bytes(), &rl) // zero value on an error body; callers check the list
	return rl
}

func TestHostedSignInAcrossNodes(t *testing.T) {
	fp := &fakePanel{codes: map[string]string{}}
	SetPanel(fp)
	t.Cleanup(func() { SetPanel(nil) })
	cfg, sec := hostedConfig(t), orgSecrets(t)
	a, b := hostedNode(t, cfg, sec), hostedNode(t, cfg, sec)
	fp.nodes = []*Service{a.svc, b.svc}

	// Code requested on node A, typed on node B.
	if w := a.do("POST", "/login", loginForm("email", "alice@gmail.com", ""), "198.51.100.7"); w.Code != 200 {
		t.Fatalf("request code on A: %d %s", w.Code, w.Body)
	}
	code := fp.code(t, "alice@gmail.com")
	if s := fp.starts[0]; s.Host != "auth.example.com" || s.ClientIP != "198.51.100.7" || s.Label != "web" || s.Length != 6 {
		t.Fatalf("start request %+v", s)
	}
	// Ineligible emails never reach the panel.
	a.do("POST", "/login", loginForm("email", "nobody@nowhere.test", ""), "198.51.100.8")
	time.Sleep(50 * time.Millisecond)
	fp.mu.Lock()
	n := len(fp.starts)
	fp.mu.Unlock()
	if n != 1 {
		t.Fatalf("panel asked %d times, want 1 (ineligible email)", n)
	}
	if w := b.do("POST", "/login", loginForm("code", "alice@gmail.com", "000000"), "198.51.100.7"); w.Code != 401 {
		t.Fatalf("wrong code on B: %d", w.Code)
	}
	w := b.do("POST", "/login", loginForm("code", "alice@gmail.com", code), "198.51.100.7")
	loc, _ := url.Parse(w.Header().Get("Location"))
	if w.Code != 302 || loc.Path != "/.ingressd/callback" {
		t.Fatalf("verify on B: %d %s", w.Code, w.Body)
	}
	portal := cookieFrom(w, PortalCookieName)

	// The callback code from B's portal is redeemed by A's edge_auth.
	authCode := loc.Query().Get("code")
	if len(authCode) > 1024 { // edge_auth accepts up to 4096 (return URLs are capped at 2048)
		t.Fatalf("sealed code is %d bytes", len(authCode))
	}
	wx, er := a.exchange(authCode, "web", "web.example.com")
	if wx.Code != 200 {
		t.Fatalf("exchange on A: %d %s", wx.Code, wx.Body)
	}
	claims, err := b.keys.OpenApp("web", er.Token) // same keys everywhere
	if err != nil || claims.Email != "alice@gmail.com" {
		t.Fatalf("app token %+v %v", claims, err)
	}
	if wx, _ := a.exchange(authCode, "web", "web.example.com"); wx.Code != 403 {
		t.Fatalf("replay on A: %d", wx.Code)
	}

	// B's portal cookie is accepted by A (session imported there).
	q := "/login?" + url.Values{"app": {"web"}, "rd": {rd}, "n": {FlowNonceHash(testNonce)}}.Encode()
	if w := a.do("GET", q, nil, "198.51.100.7", portal); w.Code != 302 {
		t.Fatalf("B's session on A: %d %s", w.Code, w.Body)
	}
	if ss, _ := a.svc.Store().ListSessions(context.Background(), "alice@gmail.com"); len(ss) != 1 {
		t.Fatalf("imported sessions on A: %+v", ss)
	}

	// Sign out on A: reported to the panel, relayed to B.
	if w := a.do("POST", "/logout", nil, "198.51.100.7", portal); w.Code != 200 {
		t.Fatalf("logout: %d", w.Code)
	}
	if len(fp.revokes) != 1 || fp.revokes[0].SID != claims.SID {
		t.Fatalf("revocations reported %+v", fp.revokes)
	}
	if w := b.do("GET", q, nil, "198.51.100.7", portal); w.Code != 200 {
		t.Fatalf("revoked session still accepted on B: %d", w.Code)
	}
	if rl := revocations(b); len(rl.SIDs) != 1 || rl.SIDs[0] != claims.SID {
		t.Fatalf("B's revocation list %+v", rl)
	}
}

func TestHostedRevokedBeforeAndList(t *testing.T) {
	fp := &fakePanel{codes: map[string]string{}}
	SetPanel(fp)
	t.Cleanup(func() { SetPanel(nil) })
	cfg, sec := hostedConfig(t), orgSecrets(t)
	a := hostedNode(t, cfg, sec)
	a.do("POST", "/login", loginForm("email", "alice@gmail.com", ""), "198.51.100.7")
	w := a.do("POST", "/login", loginForm("code", "alice@gmail.com", fp.code(t, "alice@gmail.com")), "198.51.100.7")
	portal := cookieFrom(w, PortalCookieName)
	q := "/login?" + url.Values{"app": {"web"}, "rd": {rd}, "n": {FlowNonceHash(testNonce)}}.Encode()
	if w := a.do("GET", q, nil, "198.51.100.7", portal); w.Code != 302 {
		t.Fatalf("session: %d", w.Code)
	}

	// A snapshot revokes everyone signed in before now, plus a session id.
	cfg2 := hostedConfig(t)
	cut := time.Now().Add(time.Second).Truncate(time.Second)
	cfg2.Access.RevokedBefore = map[string]config.Instant{"alice@gmail.com": {Time: cut}}
	cfg2.Access.RevokedSessions = []string{"other-sid"}
	if err := a.svc.Update(cfg2, secrets.NewMemory(sec)); err != nil {
		t.Fatal(err)
	}
	if w := a.do("GET", q, nil, "198.51.100.7", portal); w.Code != 200 {
		t.Fatalf("session issued before revoked_before still accepted: %d", w.Code)
	}
	rl := revocations(a)
	if rl.Before["alice@gmail.com"] != cut.Unix() || len(rl.SIDs) != 1 || rl.SIDs[0] != "other-sid" {
		t.Fatalf("revocation list %+v", rl)
	}
}

func TestHostedPanelUnavailable(t *testing.T) {
	SetPanel(nil)
	cfg, sec := hostedConfig(t), orgSecrets(t)
	a := hostedNode(t, cfg, sec)
	if w := a.do("POST", "/login", loginForm("email", "alice@gmail.com", ""), "198.51.100.7"); w.Code != 503 || !strings.Contains(w.Body.String(), "temporarily unavailable") {
		t.Fatalf("no panel: %d %s", w.Code, w.Body)
	}
	if w := a.do("POST", "/login", loginForm("code", "alice@gmail.com", "123456"), "198.51.100.7"); w.Code != 503 {
		t.Fatalf("verify without panel: %d", w.Code)
	}
}

func TestHostedVerifyLocalLockout(t *testing.T) {
	fp := &fakePanel{codes: map[string]string{}}
	SetPanel(fp)
	t.Cleanup(func() { SetPanel(nil) })
	a := hostedNode(t, hostedConfig(t), orgSecrets(t))
	a.do("POST", "/login", loginForm("email", "bob@outlook.com", ""), "198.51.100.9")
	code := fp.code(t, "bob@outlook.com")
	for i := 0; i < 5; i++ {
		a.do("POST", "/login", loginForm("code", "bob@outlook.com", "999999"), "198.51.100.9")
	}
	if w := a.do("POST", "/login", loginForm("code", "bob@outlook.com", code), "198.51.100.9"); w.Code != 401 {
		t.Fatalf("code accepted during the node's lockout: %d", w.Code)
	}
}

func TestPlayAuthenticate(t *testing.T) {
	fp := &fakePanel{codes: map[string]string{}}
	SetPanel(fp)
	t.Cleanup(func() { SetPanel(nil) })
	a := hostedNode(t, hostedConfig(t), orgSecrets(t))
	policy := "family-or-work"
	do := func(method string, form url.Values, cookies ...*http.Cookie) (*httptest.ResponseRecorder, string, bool) {
		var r *http.Request
		if form != nil {
			r = httptest.NewRequest(method, "https://play.example.com/join/mc", strings.NewReader(form.Encode()))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		} else {
			r = httptest.NewRequest(method, "https://play.example.com/join/mc", nil)
		}
		r.Header.Set("X-Forwarded-For", "198.51.100.20")
		r.Header.Set("Sec-Fetch-Site", "same-origin")
		for _, c := range cookies {
			r.AddCookie(c)
		}
		w := httptest.NewRecorder()
		email, ok := a.svc.PlayAuthenticate(w, r, policy)
		return w, email, ok
	}
	if w, _, ok := do("GET", nil); ok || !strings.Contains(w.Body.String(), `value="email"`) {
		t.Fatalf("first visit: ok=%v %s", ok, w.Body)
	}
	if w, _, ok := do("POST", url.Values{"step": {"email"}, "email": {"alice@gmail.com"}}); ok || !strings.Contains(w.Body.String(), `value="code"`) {
		t.Fatalf("email step: ok=%v %s", ok, w.Body)
	}
	code := fp.code(t, "alice@gmail.com")
	if s := fp.starts[len(fp.starts)-1]; s.Host != "play.example.com" || s.Policy != "family-or-work" || s.Label != "mc" {
		t.Fatalf("start %+v", s)
	}
	w, email, ok := do("POST", url.Values{"step": {"code"}, "email": {"alice@gmail.com"}, "code": {code}})
	play := cookieFrom(w, PlayCookieName)
	if !ok || email != "alice@gmail.com" || play == nil || w.Body.Len() != 0 {
		t.Fatalf("code step: ok=%v email=%q cookie=%v body=%s", ok, email, play, w.Body)
	}
	// The play cookie signs the player in on the next visit, on any node.
	if _, email, ok := do("GET", nil, play); !ok || email != "alice@gmail.com" {
		t.Fatalf("with cookie: %v %q", ok, email)
	}
	// A verified email the policy does not allow from this IP is denied.
	policy = "admins"
	do("POST", url.Values{"step": {"email"}, "email": {"me@example.org"}})
	if w, _, ok := do("POST", url.Values{"step": {"code"}, "email": {"me@example.org"}, "code": {fp.code(t, "me@example.org")}}); ok || w.Code != 403 {
		t.Fatalf("denied player: ok=%v %d", ok, w.Code)
	}
}

func TestKeyRefsAndValidation(t *testing.T) {
	cfg := testConfig(t)
	if s, j := KeyRefs(cfg); s != "secret://access_session_key" || j != "secret://access_jwt_key" {
		t.Fatalf("default refs %s %s", s, j)
	}
	cfg = hostedConfig(t)
	if s, _ := KeyRefs(cfg); s != "secret://org_access_session_key" {
		t.Fatalf("org ref %s", s)
	}
	bad := hostedConfig(t)
	bad.Access.JWTKey = ""
	if err := bad.Validate(); err == nil || !strings.Contains(err.Error(), "set both session_key and jwt_key") {
		t.Fatalf("one key only: %v", err)
	}
	bad = hostedConfig(t)
	bad.Access.RevokedBefore = map[string]config.Instant{"Not-An-Email": {Time: time.Now()}}
	if err := bad.Validate(); err == nil {
		t.Fatal("bad revoked_before key accepted")
	}
}

func TestHostedConfigYAML(t *testing.T) {
	y := strings.Replace(policyConfig, "access: { portal_host: auth.example.com }", `access:
  portal_host: auth.example.com
  session_key: secret://org_access_session_key
  jwt_key: secret://org_access_jwt_key
  revoked_before: { "*": 2026-11-03T10:00:00Z }
  revoked_sessions: [abc]`, 1)
	y = strings.Replace(y, "email: { provider: log, log: { path: /tmp/mail.log } }", "email: { provider: panel }", 1)
	cfg, err := config.Parse([]byte(y))
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if got := cfg.Access.RevokedBefore["*"].UTC().Format(time.RFC3339); got != "2026-11-03T10:00:00Z" || !OrgKeys(cfg) || !usesPanel(cfg) {
		t.Fatalf("parsed %s %+v", got, cfg.Access)
	}
}

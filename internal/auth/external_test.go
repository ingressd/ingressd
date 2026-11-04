// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ingressd/ingressd/internal/secrets"
	"github.com/ingressd/ingressd/pkg/access"
	"github.com/ingressd/ingressd/pkg/config"
)

// externalConfig is a managed node whose sign-in portal is the panel's
// (access.portal_url): no portal host here.
func externalConfig(t *testing.T) *config.Config {
	t.Helper()
	cfg := testConfig(t)
	cfg.Email = config.Email{Provider: config.EmailPanel}
	cfg.Access.PortalHost = ""
	cfg.Access.PortalURL = "https://auth.ingressd.test/a/org_1"
	cfg.Access.SessionKey = "secret://org_access_session_key"
	cfg.Access.JWTKey = "secret://org_access_jwt_key"
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	return cfg
}

func TestExternalPortalConfig(t *testing.T) {
	cfg := externalConfig(t)
	if Enabled(cfg) || !External(cfg) || !Needed(cfg) {
		t.Fatalf("Enabled=%v External=%v Needed=%v", Enabled(cfg), External(cfg), Needed(cfg))
	}
	sec := orgSecrets(t)
	sec["hook"] = "hook-secret"
	ec, err := BuildEdgeConfig(cfg, secrets.NewMemory(sec), "web", "/run/x.sock")
	if err != nil {
		t.Fatal(err)
	}
	if ec.PortalURL != "https://auth.ingressd.test/a/org_1" {
		t.Errorf("portal_url = %q", ec.PortalURL)
	}
}

// exchangeFrom redeems a code as edge_auth does, from a visitor address.
func (p *portalEnv) exchangeFrom(code, app, host, ip string) (*httptest.ResponseRecorder, ExchangeResponse) {
	b, _ := json.Marshal(ExchangeRequest{Code: code, App: app, Host: host, IP: ip})
	r := httptest.NewRequest("POST", "http://"+ControlHost+"/v1/exchange", bytes.NewReader(b))
	w := httptest.NewRecorder()
	p.api.ServeHTTP(w, r)
	var er ExchangeResponse
	_ = json.Unmarshal(w.Body.Bytes(), &er) // zero value on an error body; callers check the status
	return w, er
}

// TestExternalPortalCallbackEnforcesPolicy: the panel's central portal only
// proves the email (it seals the code with the org keys, as here through
// pkg/access); the node evaluates the app's policies at the callback.
func TestExternalPortalCallbackEnforcesPolicy(t *testing.T) {
	cfg := externalConfig(t)
	sec := orgSecrets(t)
	n := hostedNode(t, cfg, sec)
	panelKeys, err := access.ParseKeys(sec["org_access_session_key"], sec["org_access_jwt_key"])
	if err != nil {
		t.Fatal(err)
	}
	seal := func(email, rd string, grants map[string]string) string {
		t.Helper()
		now := time.Now()
		code, err := panelKeys.SealCode(access.SealedCode{ID: randomToken(16), SID: "panel-" + randomToken(8), Email: email, App: "web", RD: rd,
			Grants: grants, SessionIssued: now, SessionExpires: now.Add(24 * time.Hour), Expires: now.Add(time.Minute)})
		if err != nil {
			t.Fatal(err)
		}
		return code
	}
	for _, tc := range []struct {
		name, email, ip, rd string
		grants              map[string]string
		ok                  bool
		grant               string
	}{
		{"allowed by group", "alice@gmail.com", "198.51.100.7", rd, nil, true, "family-or-work"},
		{"denied email, even with forged grants", "eve@example.com", "198.51.100.7", rd, map[string]string{"family-or-work": "x"}, false, ""},
		{"outsider", "mallory@evil.test", "198.51.100.7", rd, nil, false, ""},
		{"ip requirement met", "me@example.org", "81.2.3.4", rd, nil, true, "admins"},
		{"ip requirement not met", "me@example.org", "198.51.100.7", rd, nil, false, ""},
		{"excluded network", "alice@gmail.com", "203.0.113.9", rd, nil, false, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w, er := n.exchangeFrom(seal(tc.email, tc.rd, tc.grants), "web", "web.example.com", tc.ip)
			if !tc.ok {
				if w.Code != http.StatusForbidden || !strings.HasPrefix(w.Body.String(), "not allowed: ") {
					t.Fatalf("exchange = %d %q, want 403 not allowed", w.Code, w.Body.String())
				}
				return
			}
			if w.Code != http.StatusOK || er.RD != tc.rd {
				t.Fatalf("exchange = %d %q", w.Code, w.Body.String())
			}
			c, err := n.keys.OpenApp("web", er.Token)
			if err != nil || c.Email != tc.email {
				t.Fatalf("app cookie: %+v, %v", c, err)
			}
			if _, ok := c.Grants[tc.grant]; !ok || len(c.Grants) == 0 {
				t.Errorf("grants = %v, want %s", c.Grants, tc.grant)
			}
			if tc.grant == "family-or-work" && time.Until(time.Unix(er.Expires, 0)) > 13*time.Hour {
				t.Errorf("cookie outlives the policy session (12h): %v", time.Unix(er.Expires, 0))
			}
		})
	}
	// Codes the panel binds to the browser are checked (the panel does not
	// carry the nonce yet, so unbound panel codes stay accepted above).
	now := time.Now()
	bound, err := panelKeys.SealCode(access.SealedCode{ID: randomToken(16), SID: "panel-" + randomToken(8), Email: "alice@gmail.com", App: "web", RD: rd,
		SessionIssued: now, SessionExpires: now.Add(time.Hour), Expires: now.Add(time.Minute), Nonce: FlowNonceHash(testNonce)})
	if err != nil {
		t.Fatal(err)
	}
	for _, nonce := range []string{"", "b3RoZXItYnJvd3Nlci1ub25jZS0zMi1ieXRlcy1sb25n"} {
		b, _ := json.Marshal(ExchangeRequest{Code: bound, App: "web", Host: "web.example.com", IP: "198.51.100.7", Nonce: nonce})
		w := httptest.NewRecorder()
		n.api.ServeHTTP(w, httptest.NewRequest("POST", "http://"+ControlHost+"/v1/exchange", bytes.NewReader(b)))
		if w.Code != http.StatusForbidden {
			t.Errorf("bound panel code with nonce %q: %d", nonce, w.Code)
		}
	}
	if w, _ := n.exchangeNonce(bound, "web", "web.example.com", testNonce); w.Code != http.StatusOK {
		t.Errorf("bound panel code from its browser: %d %s", w.Code, w.Body)
	}

	// A code is single-use and bound to the app's host.
	code := seal("alice@gmail.com", rd, nil)
	if w, _ := n.exchangeFrom(code, "web", "other.example.com", "198.51.100.7"); w.Code != http.StatusForbidden {
		t.Errorf("other host: %d", w.Code)
	}
	if w, _ := n.exchangeFrom(code, "web", "web.example.com", "198.51.100.7"); w.Code != http.StatusOK {
		t.Errorf("first use: %d %s", w.Code, w.Body.String())
	}
	if w, _ := n.exchangeFrom(code, "web", "web.example.com", "198.51.100.7"); w.Code != http.StatusForbidden {
		t.Errorf("replay: %d", w.Code)
	}
}

func TestExternalPortalValidation(t *testing.T) {
	for _, tc := range []struct {
		name string
		mod  func(a *config.Access)
		want string
	}{
		{"both", func(a *config.Access) { a.PortalHost = "auth.example.com" }, "not both"},
		{"bad url", func(a *config.Access) { a.PortalURL = "ftp://x" }, "access.portal_url"},
		{"query", func(a *config.Access) { a.PortalURL = "https://auth.ingressd.test/a/org?x=1" }, "access.portal_url"},
		{"no org keys", func(a *config.Access) { a.SessionKey, a.JWTKey = "", "" }, "org-wide keys"},
		{"neither", func(a *config.Access) { a.PortalURL = "" }, "access.portal_host: is required"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := externalConfig(t)
			tc.mod(cfg.Access)
			err := cfg.Validate()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Validate = %v, want %q", err, tc.want)
			}
		})
	}
}

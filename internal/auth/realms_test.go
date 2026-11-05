// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ingressd/ingressd/internal/secrets"
	"github.com/ingressd/ingressd/pkg/access"
	"github.com/ingressd/ingressd/pkg/config"
	"github.com/ingressd/ingressd/pkg/nodeproto"
)

// realmsAuthConfig has two realms whose apps share a name apart from the
// namespace and admit the same email; each realm has its own keys.
const realmsAuthConfig = `
version: 1
edge: { acme: { ca: internal } }
security: { tunnel_input: restricted }
realms:
  ra:
    access: { portal_url: https://auth.ingressd.test/a/ra, session_key: secret://ra_session, jwt_key: secret://ra_jwt, revoked_before: { "alice@example.com": "2020-01-01T00:00:00Z" } }
  rb:
    access: { portal_url: https://auth.ingressd.test/a/rb, session_key: secret://rb_session, jwt_key: secret://rb_jwt, revoked_sessions: [rb-revoked] }
tunnels:
  ra01: { realm: ra, table: 1201, site: connector, listen_port: 51820, transit: 10.100.1.0/30, subnets: [192.168.1.0/24], virtual_prefix: 10.0.4.0/24 }
  rb01: { realm: rb, table: 1202, site: connector, listen_port: 51821, transit: 10.100.2.0/30, subnets: [192.168.1.0/24], virtual_prefix: 10.0.5.0/24 }
policies:
  ra.all: { realm: ra, action: allow, include: [{ email: alice@example.com }] }
  rb.all: { realm: rb, action: allow, include: [{ email: alice@example.com }] }
apps:
  ra.nas: { realm: ra, hosts: [nas.a.example], tunnel: ra01, origin: http://192.168.1.10:80, access: [ra.all] }
  rb.nas: { realm: rb, hosts: [nas.b.example], tunnel: rb01, origin: http://192.168.1.10:80, access: [rb.all] }
`

type realmsEnv struct {
	*portalEnv
	cfg    *config.Config
	ra, rb *Keys // as the realms' portals hold them (unscoped)
}

func newRealmsEnv(t *testing.T) *realmsEnv {
	t.Helper()
	cfg, err := config.Parse([]byte(realmsAuthConfig))
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	a, b := orgSecrets(t), orgSecrets(t)
	sec := map[string]string{
		"ra_session": a["org_access_session_key"], "ra_jwt": a["org_access_jwt_key"],
		"rb_session": b["org_access_session_key"], "rb_jwt": b["org_access_jwt_key"],
	}
	st := secrets.NewMemory(sec)
	if changed, err := EnsureKeys(cfg, st); err != nil || changed {
		t.Fatalf("EnsureKeys = %v, %v (realms bring their own keys)", changed, err)
	}
	svc, err := Open(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = svc.Close() })
	if err := svc.Update(cfg, st); err != nil {
		t.Fatal(err)
	}
	ra, _ := access.ParseKeys(sec["ra_session"], sec["ra_jwt"])
	rb, _ := access.ParseKeys(sec["rb_session"], sec["rb_jwt"])
	return &realmsEnv{portalEnv: &portalEnv{t: t, svc: svc, api: svc.EdgeAPIHandler()}, cfg: cfg, ra: ra, rb: rb}
}

func sealFor(t *testing.T, k *Keys, app, host string) string {
	t.Helper()
	now := time.Now()
	code, err := k.SealCode(access.SealedCode{ID: randomToken(16), SID: "s-" + randomToken(8), Email: "alice@example.com", App: app,
		RD: "https://" + host + "/", SessionIssued: now, SessionExpires: now.Add(time.Hour), Expires: now.Add(time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	return code
}

func TestRealmsExchangeUsesRealmKeys(t *testing.T) {
	e := newRealmsEnv(t)
	if !Needed(e.cfg) || Enabled(e.cfg) || External(e.cfg) {
		t.Fatalf("Needed=%v Enabled=%v External=%v", Needed(e.cfg), Enabled(e.cfg), External(e.cfg))
	}

	w, er := e.exchangeFrom(sealFor(t, e.rb, "rb.nas", "nas.b.example"), "rb.nas", "nas.b.example", "198.51.100.7")
	if w.Code != http.StatusOK {
		t.Fatalf("exchange in realm rb = %d %s", w.Code, w.Body)
	}
	// The app cookie opens only under rb's realm-scoped keys.
	if c, err := e.rb.ForRealm("rb").OpenApp("rb.nas", er.Token); err != nil || c.Email != "alice@example.com" {
		t.Fatalf("realm cookie: %+v %v", c, err)
	}
	if _, err := e.rb.OpenApp("rb.nas", er.Token); err == nil {
		t.Error("realm cookie opens under the unscoped key derivation")
	}
	if _, err := e.ra.ForRealm("rb").OpenApp("rb.nas", er.Token); err == nil {
		t.Error("realm cookie opens under another realm's master key")
	}

	// A code sealed by realm ra's portal is worthless for realm rb's app,
	// and the reverse: each app redeems with its own realm's keys only.
	if w, _ := e.exchangeFrom(sealFor(t, e.ra, "rb.nas", "nas.b.example"), "rb.nas", "nas.b.example", "198.51.100.7"); w.Code != http.StatusForbidden {
		t.Errorf("ra code for rb app = %d, want 403", w.Code)
	}
	if w, _ := e.exchangeFrom(sealFor(t, e.rb, "ra.nas", "nas.a.example"), "ra.nas", "nas.a.example", "198.51.100.7"); w.Code != http.StatusForbidden {
		t.Errorf("rb code for ra app = %d, want 403", w.Code)
	}
	// Legacy stored codes come from a node portal, which realms do not run.
	if w, _ := e.exchangeFrom("legacy-code", "ra.nas", "nas.a.example", ""); w.Code != http.StatusForbidden {
		t.Errorf("legacy code = %d, want 403", w.Code)
	}
}

func TestRealmsRevocationsAreScoped(t *testing.T) {
	e := newRealmsEnv(t)
	list := func(q string) RevocationList {
		w := httptest.NewRecorder()
		e.api.ServeHTTP(w, httptest.NewRequest("GET", "http://"+ControlHost+"/v1/revocations"+q, nil))
		var rl RevocationList
		_ = json.Unmarshal(w.Body.Bytes(), &rl)
		return rl
	}
	ra, rb, none := list("?realm=ra"), list("?realm=rb"), list("")
	if _, ok := ra.Before["alice@example.com"]; !ok || len(ra.SIDs) != 0 {
		t.Errorf("realm ra list %+v", ra)
	}
	if len(rb.Before) != 0 || len(rb.SIDs) != 1 || rb.SIDs[0] != "rb-revoked" {
		t.Errorf("realm rb list %+v (ra's revoked_before must not apply)", rb)
	}
	if len(none.Before) != 0 || len(none.SIDs) != 0 {
		t.Errorf("node-wide list %+v", none)
	}

	// ra's revoked_before applies at ra's callback only.
	if w, _ := e.exchangeFrom(sealFor(t, e.ra, "ra.nas", "nas.a.example"), "ra.nas", "nas.a.example", ""); w.Code != http.StatusOK {
		t.Errorf("ra exchange = %d %s", w.Code, w.Body)
	}
	now := time.Now()
	old, _ := e.ra.SealCode(access.SealedCode{ID: randomToken(16), SID: "s-old", Email: "alice@example.com", App: "ra.nas",
		RD: "https://nas.a.example/", SessionIssued: now.AddDate(-7, 0, 0), SessionExpires: now.Add(time.Hour), Expires: now.Add(time.Minute)})
	if w, _ := e.exchangeFrom(old, "ra.nas", "nas.a.example", ""); w.Code != http.StatusForbidden {
		t.Errorf("session from before ra's revoked_before = %d, want 403", w.Code)
	}
	oldB, _ := e.rb.SealCode(access.SealedCode{ID: randomToken(16), SID: "s-oldb", Email: "alice@example.com", App: "rb.nas",
		RD: "https://nas.b.example/", SessionIssued: now.AddDate(-7, 0, 0), SessionExpires: now.Add(time.Hour), Expires: now.Add(time.Minute)})
	if w, _ := e.exchangeFrom(oldB, "rb.nas", "nas.b.example", ""); w.Code != http.StatusOK {
		t.Errorf("rb session hit by ra's revoked_before: %d %s", w.Code, w.Body)
	}

	// Email-wide revocations from the panel would hit every realm.
	if err := e.svc.ApplyRemoteRevoke(context.Background(), nodeproto.AuthRevoke{Email: "alice@example.com", Before: time.Now()}); err == nil {
		t.Error("email-wide remote revoke accepted on a node with realms")
	}
	if err := e.svc.ApplyRemoteRevoke(context.Background(), nodeproto.AuthRevoke{SID: "s-x", Email: "alice@example.com"}); err != nil {
		t.Errorf("session revoke: %v", err)
	}
}

func TestRealmsEdgeConfig(t *testing.T) {
	e := newRealmsEnv(t)
	sec := secrets.NewMemory(map[string]string{"ra_session": e.ra.SessionRaw, "ra_jwt": e.ra.JWTRaw, "rb_session": e.rb.SessionRaw, "rb_jwt": e.rb.JWTRaw})
	ec, err := BuildEdgeConfig(e.cfg, sec, "rb.nas", "/run/x.sock")
	if err != nil {
		t.Fatal(err)
	}
	if ec.Realm != "rb" || ec.PortalURL != "https://auth.ingressd.test/a/rb" || ec.SessionKey != e.rb.SessionRaw || ec.JWTKey != e.rb.JWTRaw {
		t.Errorf("edge config realm=%q portal=%q, keys from the wrong realm", ec.Realm, ec.PortalURL)
	}
	if ec.Audience != "nas" {
		t.Errorf("audience %q, want the app's name without its realm", ec.Audience)
	}
	if _, ok := ec.Policies["ra.all"]; ok || len(ec.Policies) != 1 {
		t.Errorf("policies %v", ec.Policies)
	}
}

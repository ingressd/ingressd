// SPDX-License-Identifier: Apache-2.0

package idp_test

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/ingressd/ingressd/pkg/access"
	"github.com/ingressd/ingressd/pkg/access/idp"
	"github.com/ingressd/ingressd/pkg/access/idp/idptest"
	"github.com/ingressd/ingressd/pkg/config"
)

const cb = "https://auth.example.test/oauth/cb"

// browser follows the authorization redirect to the fake and returns the
// callback query.
func browser(t *testing.T, authURL string) url.Values {
	t.Helper()
	c := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := c.Get(authURL)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("authorize: %d", resp.StatusCode)
	}
	u, err := url.Parse(resp.Header.Get("Location"))
	if err != nil || !strings.HasPrefix(u.String(), cb) {
		t.Fatalf("callback %q", resp.Header.Get("Location"))
	}
	return u.Query()
}

func signIn(t *testing.T, p *idp.Provider, w idp.Wants) (*idp.Identity, error) {
	t.Helper()
	ctx := context.Background()
	u, f, err := p.Start(ctx, cb, w)
	if err != nil {
		t.Fatal(err)
	}
	q := browser(t, u)
	// The flow survives the cookie round trip.
	key := make([]byte, 32)
	sealed, err := idp.SealFlow(key, f)
	if err != nil {
		t.Fatal(err)
	}
	f2, err := idp.OpenFlow(key, sealed)
	if err != nil {
		t.Fatal(err)
	}
	return p.Finish(ctx, cb, f2, q)
}

func fake(t *testing.T) *idptest.Server {
	s := idptest.New("client-1", "secret-1", "steam-key").Start()
	t.Cleanup(s.Close)
	return s
}

func prov(s *idptest.Server, method string) *idp.Provider {
	return &idp.Provider{Method: method, ClientID: "client-1", ClientSecret: "secret-1", APIKey: "steam-key", Endpoints: s.Endpoints()}
}

func TestGoogle(t *testing.T) {
	s := fake(t)
	s.SetUser("google", idptest.User{Sub: "1001", Email: "Ann@Corp.example", EmailVerified: true, HD: "corp.example"})
	id, err := signIn(t, prov(s, "google"), idp.Wants{})
	if err != nil {
		t.Fatal(err)
	}
	if id.Email != "ann@corp.example" || id.Principal() != "ann@corp.example" || !slices.Contains(id.Attrs, "google_hd:corp.example") {
		t.Fatalf("%+v", id)
	}
	// Unverified email: no email, principal by subject.
	s.SetUser("google", idptest.User{Sub: "1002", Email: "bob@gmail.example"})
	id, err = signIn(t, prov(s, "google"), idp.Wants{})
	if err != nil || id.Email != "" || id.Principal() != "google:1002" {
		t.Fatalf("%+v %v", id, err)
	}
}

func TestOIDCRejects(t *testing.T) {
	s := fake(t)
	s.SetUser("google", idptest.User{Sub: "1", Email: "a@b.example", EmailVerified: true})
	for _, k := range []idptest.Knobs{{BadSignature: true}, {WrongAudience: true}, {WrongIssuer: true}, {WrongNonce: true}, {Expired: true}} {
		s.SetKnobs(k)
		if id, err := signIn(t, prov(s, "google"), idp.Wants{}); err == nil {
			t.Errorf("%+v: accepted %+v", k, id)
		}
	}
	s.SetKnobs(idptest.Knobs{})
	// Wrong client secret.
	p := prov(s, "google")
	p.ClientSecret = "nope"
	if _, err := signIn(t, p, idp.Wants{}); err == nil || strings.Contains(err.Error(), "nope") {
		t.Errorf("bad secret: %v", err)
	}
	// State mismatch, PKCE mismatch, expired flow.
	ctx := context.Background()
	p = prov(s, "google")
	u, f, _ := p.Start(ctx, cb, idp.Wants{})
	q := browser(t, u)
	q.Set("state", "forged")
	if _, err := p.Finish(ctx, cb, f, q); !errors.Is(err, idp.ErrState) {
		t.Errorf("state: %v", err)
	}
	u, f, _ = p.Start(ctx, cb, idp.Wants{})
	q = browser(t, u)
	f.Verifier = "wrong-verifier-wrong-verifier-wrong-verifier-123"
	if _, err := p.Finish(ctx, cb, f, q); err == nil {
		t.Error("PKCE verifier not checked")
	}
	// A code is single use.
	u, f, _ = p.Start(ctx, cb, idp.Wants{})
	q = browser(t, u)
	if _, err := p.Finish(ctx, cb, f, q); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Finish(ctx, cb, f, q); err == nil {
		t.Error("code redeemed twice")
	}
}

func TestMicrosoftRoleTenants(t *testing.T) {
	const tid = "11111111-2222-3333-4444-555555555555"
	eng := access.NewEngine(&config.Config{Policies: map[string]config.Policy{
		"admins": {Action: config.ActionAllow, Include: []config.Selector{{MicrosoftRole: config.StringList{"Admin"}}}},
	}})
	for _, tc := range []struct {
		tenant, tid string
		match       bool
	}{
		{"", tid, false},
		{"common", tid, false},
		{"organizations", tid, false},
		{"consumers", config.MicrosoftConsumersTenant, false},
		{config.MicrosoftConsumersTenant, config.MicrosoftConsumersTenant, false},
		{tid, tid, true},
	} {
		t.Run("tenant="+tc.tenant, func(t *testing.T) {
			s := fake(t)
			s.SetUser("microsoft", idptest.User{Sub: "x", OID: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", TID: tc.tid, Roles: []string{"Admin"}})
			p := prov(s, "microsoft")
			p.Tenant = tc.tenant
			id, err := signIn(t, p, idp.Wants{})
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Contains(id.Attrs, "microsoft_tenant:"+tc.tid) {
				t.Errorf("missing tenant in %v", id.Attrs)
			}
			d := eng.Evaluate([]string{"admins"}, access.UserIdentity(id.Principal(), id.Method, id.Attrs))
			if d.Allowed() != tc.match {
				t.Errorf("allowed = %v, want %v (attrs %v)", d.Allowed(), tc.match, id.Attrs)
			}
		})
	}
}

func TestMicrosoftUnboundRoles(t *testing.T) {
	const tid = "11111111-2222-3333-4444-555555555555"
	role := []config.Selector{{MicrosoftRole: config.StringList{"Guest"}}}
	everyone := []config.Selector{{Everyone: true}}
	tenant := []config.Selector{{MicrosoftTenant: config.StringList{tid}}}
	eng := access.NewEngine(&config.Config{Policies: map[string]config.Policy{
		"paired":   {Action: config.ActionAllow, Include: role, Require: tenant},
		"excluded": {Action: config.ActionAllow, Include: everyone, Exclude: role},
		"denied":   {Action: config.ActionDeny, Include: role},
		"open":     {Action: config.ActionAllow, Include: everyone},
	}})
	s := fake(t)
	s.SetUser("microsoft", idptest.User{Sub: "x", OID: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", TID: tid, Roles: []string{"Guest"}})
	id, err := signIn(t, prov(s, "microsoft"), idp.Wants{})
	if err != nil {
		t.Fatal(err)
	}
	who := access.UserIdentity(id.Principal(), id.Method, id.Attrs)
	if !eng.Evaluate([]string{"paired"}, who).Allowed() {
		t.Error("a role with a required tenant should match")
	}
	if eng.Evaluate([]string{"excluded"}, who).Allowed() {
		t.Error("an excluded role should still exclude")
	}
	if eng.Evaluate([]string{"denied", "open"}, who).Allowed() {
		t.Error("a deny policy on a role should still deny")
	}
}

func TestMicrosoft(t *testing.T) {
	s := fake(t)
	tid := "11111111-2222-3333-4444-555555555555"
	s.SetUser("microsoft", idptest.User{Sub: "x", OID: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", TID: tid, Email: "ann@corp.example",
		Groups: []string{"99999999-8888-7777-6666-555555555555"}, Roles: []string{"Admin"}})
	single := prov(s, "microsoft")
	single.Tenant = tid
	id, err := signIn(t, single, idp.Wants{})
	if err != nil {
		t.Fatal(err)
	}
	// Entra email without xms_edov is not verified.
	if id.Email != "" || id.Principal() != "microsoft:"+tid+"/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee" {
		t.Fatalf("%+v", id)
	}
	for _, a := range []string{"microsoft_tenant:" + tid, "microsoft_group:99999999-8888-7777-6666-555555555555", "microsoft_role:Admin"} {
		if !slices.Contains(id.Attrs, a) {
			t.Errorf("missing %s in %v", a, id.Attrs)
		}
	}
	u := idptest.User{Sub: "x", OID: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", TID: tid, Email: "ann@corp.example", Edov: true}
	s.SetUser("microsoft", u)
	if id, err = signIn(t, prov(s, "microsoft"), idp.Wants{}); err != nil || id.Email != "ann@corp.example" {
		t.Fatalf("edov: %+v %v", id, err)
	}
	// Personal account: email verified.
	s.SetUser("microsoft", idptest.User{Sub: "y", OID: "00000000-0000-0000-0000-00000000000a", TID: config.MicrosoftConsumersTenant, Email: "joe@outlook.example"})
	if id, err = signIn(t, prov(s, "microsoft"), idp.Wants{}); err != nil || id.Email != "joe@outlook.example" {
		t.Fatalf("msa: %+v %v", id, err)
	}
	// Tenant restrictions.
	p := prov(s, "microsoft")
	p.Tenant = "organizations"
	if _, err := signIn(t, p, idp.Wants{}); err == nil {
		t.Error("personal account accepted by organizations")
	}
	p.Tenant = tid
	s.SetUser("microsoft", u)
	if _, err := signIn(t, p, idp.Wants{}); err != nil {
		t.Errorf("own tenant: %v", err)
	}
	u.TID = "22222222-2222-3333-4444-555555555555"
	s.SetUser("microsoft", u)
	if _, err := signIn(t, p, idp.Wants{}); err == nil {
		t.Error("other tenant accepted on a single-tenant provider")
	}
	// Group overage with group selectors fails rather than missing groups.
	p.Tenant = ""
	u.GroupsOverage = true
	s.SetUser("microsoft", u)
	if _, err := signIn(t, p, idp.Wants{MicrosoftGroups: true}); err == nil {
		t.Error("overage accepted")
	}
}

func TestDiscord(t *testing.T) {
	s := fake(t)
	g1, g2, role := "100000000000000001", "100000000000000002", "200000000000000009"
	s.SetUser("discord", idptest.User{Sub: "300000000000000003", Username: "Ann_x", Email: "ann@mail.example", EmailVerified: true,
		Guilds: []string{g1, g2}, Members: map[string][]string{g1: {role}}})
	id, err := signIn(t, prov(s, "discord"), idp.Wants{DiscordGuilds: true, DiscordRoleGuilds: []string{g1, "100000000000000077"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range []string{"discord_user:300000000000000003", "discord_username:ann_x", "discord_guild:" + g1, "discord_guild:" + g2, "discord_role:" + g1 + "/" + role} {
		if !slices.Contains(id.Attrs, a) {
			t.Errorf("missing %s in %v", a, id.Attrs)
		}
	}
	if id.Email != "ann@mail.example" {
		t.Errorf("email %q", id.Email)
	}
	// Without the wants, no guild scope and no guild facts.
	id, err = signIn(t, prov(s, "discord"), idp.Wants{})
	if err != nil || slices.ContainsFunc(id.Attrs, func(a string) bool { return strings.HasPrefix(a, "discord_guild") }) {
		t.Fatalf("%v %v", id.Attrs, err)
	}
	s.SetUser("discord", idptest.User{Sub: "300000000000000004", Username: "b", Email: "b@mail.example"})
	if id, _ = signIn(t, prov(s, "discord"), idp.Wants{}); id.Email != "" || id.Principal() != "discord:300000000000000004" {
		t.Errorf("unverified email used: %+v", id)
	}
}

func TestSteam(t *testing.T) {
	s := fake(t)
	sid := "76561198000000001"
	s.SetUser("steam", idptest.User{SteamID: sid, SteamGroups: []string{"4"}, SteamApps: []int64{440, 730}})
	id, err := signIn(t, prov(s, "steam"), idp.Wants{SteamGroups: true, SteamApps: []string{"440", "570"}})
	if err != nil {
		t.Fatal(err)
	}
	if id.Principal() != "steam:"+sid || id.Email != "" {
		t.Fatalf("%+v", id)
	}
	for _, a := range []string{"steam_id:" + sid, "steam_group:103582791429521412", "steam_app:440"} {
		if !slices.Contains(id.Attrs, a) {
			t.Errorf("missing %s in %v", a, id.Attrs)
		}
	}
	if slices.Contains(id.Attrs, "steam_app:570") || slices.Contains(id.Attrs, "steam_app:730") {
		t.Errorf("unwanted apps: %v", id.Attrs)
	}
	for _, k := range []idptest.Knobs{{SteamInvalid: true}, {SteamForeign: true}} {
		s.SetKnobs(k)
		if _, err := signIn(t, prov(s, "steam"), idp.Wants{}); err == nil {
			t.Errorf("%+v accepted", k)
		}
	}
	s.SetKnobs(idptest.Knobs{})
	// return_to of another flow, a replayed response and a tampered id.
	ctx := context.Background()
	p := prov(s, "steam")
	u, f, _ := p.Start(ctx, cb, idp.Wants{})
	q := browser(t, u)
	other := f
	other.State = "another-state"
	if _, err := p.Finish(ctx, cb, other, q); !errors.Is(err, idp.ErrState) {
		t.Errorf("foreign return_to: %v", err)
	}
	if _, err := p.Finish(ctx, cb, f, q); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Finish(ctx, cb, f, q); err == nil {
		t.Error("replayed assertion accepted")
	}
	u, f, _ = p.Start(ctx, cb, idp.Wants{})
	q = browser(t, u)
	q.Set("openid.claimed_id", "https://steamcommunity.com/openid/id/76561198000000002")
	q.Set("openid.identity", q.Get("openid.claimed_id"))
	if _, err := p.Finish(ctx, cb, f, q); err == nil {
		t.Error("tampered claimed_id accepted")
	}
	// Group/app facts without an API key fail closed.
	p.APIKey = ""
	if _, err := signIn(t, p, idp.Wants{SteamGroups: true}); err == nil {
		t.Error("no api key")
	}
}

func TestWantsFrom(t *testing.T) {
	w := idp.WantsFrom(map[string]bool{"discord_role:1/2": true, "discord_role:1/3": true, "steam_app:440": true, "microsoft_group:x": true})
	if !slices.Equal(w.DiscordRoleGuilds, []string{"1"}) || !slices.Equal(w.SteamApps, []string{"440"}) || !w.MicrosoftGroups || w.DiscordGuilds {
		t.Fatalf("%+v", w)
	}
}

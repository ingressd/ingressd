// SPDX-License-Identifier: Apache-2.0

package edgeauth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"
	"testing"
	"time"

	"aidanwoods.dev/go-paseto"
	"github.com/caddyserver/caddy/v2/caddytest"
)

// sealFacts mints an app cookie with a login method and sign-in facts, as
// pkg/access.SealApp does.
func (f *fixture) sealFacts(t *testing.T, sid, user, method string, attrs []string, grants map[string]string) string {
	key, err := paseto.V4SymmetricKeyFromBytes(derive(f.master, kdfPrefix+"edge_auth/cookie/web"))
	if err != nil {
		t.Fatal(err)
	}
	tok := paseto.NewToken()
	tok.SetIssuedAt(time.Now().Add(-time.Minute))
	tok.SetExpiration(time.Now().Add(time.Hour))
	tok.SetString("sid", sid)
	tok.SetString("email", user)
	tok.SetString("app", "web")
	tok.SetString("m", method)
	if attrs != nil {
		if err := tok.Set("attrs", attrs); err != nil {
			t.Fatal(err)
		}
	}
	if err := tok.Set("pols", grants); err != nil {
		t.Fatal(err)
	}
	return tok.V4Encrypt(key, []byte("edge_auth:web"))
}

func TestIdentityFactsAndHeaderTokens(t *testing.T) {
	f := newFixture(t)
	m := hmac.New(sha256.New, derive(f.master, kdfPrefix+"edge_auth/service-token"))
	m.Write([]byte("bot-secret-0123456789"))
	botVerifier := hex.EncodeToString(m.Sum(nil))
	cfg := f.config(t, func(h map[string]any) {
		pols := h["policies"].(map[string]any)
		pols["mods"] = map[string]any{"action": "allow", "version": "m1",
			"include": []any{map[string]any{"attr": []string{"discord_role:1/2"}}},
			"exclude": []any{map[string]any{"attr": []string{"discord_user:666"}}}}
		pols["steamers"] = map[string]any{"action": "allow", "version": "s1",
			"include": []any{map[string]any{"attr": []string{"steam_id:76561198000000001"}}},
			"require": []any{map[string]any{"attr": []string{"login_method:steam"}}}}
		pols["emailers"] = map[string]any{"action": "allow", "version": "e1",
			"include": []any{map[string]any{"attr": []string{"login_method:email"}}}}
		pols["bot"] = map[string]any{"action": "service_auth", "version": "b1", "offline": true,
			"include": []any{map[string]any{"service_token": []string{"bot"}}},
			"require": []any{map[string]any{"ip": []string{"127.0.0.0/8", "::1"}}}}
		pols["far-bot"] = map[string]any{"action": "service_auth", "version": "b2", "offline": true,
			"include": []any{map[string]any{"service_token": []string{"bot"}}},
			"require": []any{map[string]any{"ip": []string{"10.0.0.0/8"}}}}
		h["paths"] = append(h["paths"].([]map[string]any),
			map[string]any{"match": "/mods/*", "policies": []string{"mods"}},
			map[string]any{"match": "/steam/*", "policies": []string{"steamers"}},
			map[string]any{"match": "/email/*", "policies": []string{"emailers"}},
			map[string]any{"match": "/bot/*", "policies": []string{"bot", "members"}},
			map[string]any{"match": "/far/*", "policies": []string{"far-bot"}},
		)
		h["service_tokens"] = append(h["service_tokens"].([]map[string]any),
			map[string]any{"name": "bot", "header": "X-Bot-Token", "verifier": botVerifier},
			map[string]any{"name": "expired-bot", "header": "X-Old-Bot", "verifier": botVerifier, "expires": time.Now().Add(-time.Hour).Unix()})
	})
	cfg = strings.Replace(cfg, `"body":"email={http.request.header.X-Edge-User-Email}`,
		`"body":"user={http.request.header.X-Edge-User} bot={http.request.header.X-Bot-Token} email={http.request.header.X-Edge-User-Email}`, 1)
	tester := caddytest.NewTester(t).WithDefaultOverrides(caddytest.Config{AdminPort: 2939})
	tester.InitServer(cfg, "json")
	c := client{t, &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
	ck := func(v string) map[string]string { return map[string]string{"Cookie": "__edge_web=" + v} }
	time.Sleep(300 * time.Millisecond) // first revocation poll

	mod := f.sealFacts(t, "s1", "ann@example.com", "discord", []string{"discord_role:1/2", "discord_user:5"}, map[string]string{"mods": "m1"})
	if resp, body := c.get("/mods/x", ck(mod)); resp.StatusCode != 200 || !strings.Contains(body, "user=ann@example.com") {
		t.Fatalf("mod: %d %s", resp.StatusCode, body)
	}
	banned := f.sealFacts(t, "s2", "ann@example.com", "discord", []string{"discord_role:1/2", "discord_user:666"}, map[string]string{"mods": "m1"})
	if resp, _ := c.get("/mods/x", ck(banned)); resp.StatusCode == 200 {
		t.Error("excluded discord user let in")
	}
	// The grant alone is not enough: the facts must still match.
	nofacts := f.sealFacts(t, "s3", "ann@example.com", "discord", nil, map[string]string{"mods": "m1"})
	if resp, _ := c.get("/mods/x", ck(nofacts)); resp.StatusCode == 200 {
		t.Error("grant without facts let in")
	}

	steam := f.sealFacts(t, "s4", "steam:76561198000000001", "steam", []string{"steam_id:76561198000000001"}, map[string]string{"steamers": "s1"})
	resp, body := c.get("/steam/x", ck(steam))
	if resp.StatusCode != 200 || !strings.Contains(body, "user=steam:76561198000000001") || !strings.Contains(body, "email= ") {
		t.Fatalf("steam: %d %s", resp.StatusCode, body)
	}
	// login_method: cookies without a method are email sign-ins.
	old := f.seal(t, "s5", "alice@example.com", map[string]string{"emailers": "e1"}, time.Now().Add(time.Hour))
	if resp, _ := c.get("/email/x", ck(old)); resp.StatusCode != 200 {
		t.Errorf("legacy cookie as email: %d", resp.StatusCode)
	}
	if resp, _ := c.get("/email/x", ck(f.sealFacts(t, "s6", "alice@example.com", "google", nil, map[string]string{"emailers": "e1"}))); resp.StatusCode == 200 {
		t.Error("google sign-in matched login_method email")
	}

	// Header tokens: valid, wrong, expired, from the wrong network; the
	// header never reaches the origin.
	resp, body = c.get("/bot/run", map[string]string{"X-Bot-Token": "bot-secret-0123456789"})
	if resp.StatusCode != 200 || !strings.Contains(body, "bot= ") {
		t.Fatalf("bot: %d %s", resp.StatusCode, body)
	}
	if resp, _ := c.get("/bot/run", map[string]string{"X-Bot-Token": "bot-secret-0123456780"}); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("wrong bot secret: %d", resp.StatusCode)
	}
	if resp, _ := c.get("/bot/run", map[string]string{"X-Old-Bot": "bot-secret-0123456789"}); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expired bot token: %d", resp.StatusCode)
	}
	if resp, _ := c.get("/far/run", map[string]string{"X-Bot-Token": "bot-secret-0123456789"}); resp.StatusCode == 200 {
		t.Error("bot token accepted from outside its network")
	}
	// A valid token header on a path whose policies do not use it is
	// still removed.
	resp, body = c.get("/public/x", map[string]string{"X-Bot-Token": "bot-secret-0123456789"})
	if resp.StatusCode != 200 || strings.Contains(body, "bot-secret") {
		t.Errorf("token header forwarded: %s", body)
	}
	// Spoofed X-Edge-User is replaced.
	_, body = c.get("/public/x", map[string]string{"X-Edge-User": "mallory"})
	if strings.Contains(body, "mallory") {
		t.Errorf("spoofed X-Edge-User reached the origin: %s", body)
	}
}

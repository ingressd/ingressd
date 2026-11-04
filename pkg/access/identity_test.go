// SPDX-License-Identifier: Apache-2.0

package access

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"slices"
	"testing"
	"time"

	"github.com/ingressd/ingressd/pkg/config"
)

func TestIdentitySelectors(t *testing.T) {
	cfg := &config.Config{Policies: map[string]config.Policy{
		"mods": {Action: config.ActionAllow, Include: []config.Selector{{DiscordRole: config.StringList{"1/2"}}},
			Exclude: []config.Selector{{DiscordUser: config.StringList{"666"}}}},
		"steam": {Action: config.ActionAllow, Include: []config.Selector{{SteamID: config.StringList{"76561198000000001"}}},
			Require: []config.Selector{{LoginMethod: config.StringList{"steam"}}}},
		"email": {Action: config.ActionAllow, Include: []config.Selector{{EmailDomain: config.StringList{"corp.example"}}},
			Require: []config.Selector{{LoginMethod: config.StringList{"email"}}}},
	}}
	e := NewEngine(cfg)
	for _, tc := range []struct {
		name   string
		id     Identity
		list   string
		action string
	}{
		{"role", UserIdentity("discord:5", "discord", []string{"discord_role:1/2"}), "mods", "allow"},
		{"excluded user", UserIdentity("discord:666", "discord", []string{"discord_role:1/2", "discord_user:666"}), "mods", "deny"},
		{"steam", UserIdentity("steam:76561198000000001", "steam", []string{"steam_id:76561198000000001"}), "steam", "allow"},
		{"steam fact via another method", UserIdentity("x@y.z", "google", []string{"steam_id:76561198000000001"}), "steam", "deny"},
		{"email by code", UserIdentity("ann@corp.example", "", nil), "email", "allow"},
		{"email by google", UserIdentity("ann@corp.example", "google", nil), "email", "deny"},
		{"principal is not an email", UserIdentity("steam:ann@corp.example", "steam", nil), "email", "deny"},
	} {
		if d := e.Evaluate([]string{tc.list}, tc.id); d.Action != tc.action {
			t.Errorf("%s: %s, want %s", tc.name, d.Action, tc.action)
		}
	}
	if UserIdentity("steam:1", "steam", nil).Email != "" || EmailOf("a@b.c") != "a@b.c" {
		t.Error("EmailOf")
	}
	ref := e.ReferencedAttrs()
	if got := KeepAttrs([]string{"discord_role:1/9", "discord_role:1/2", "discord_user:666", "discord_guild:7", "login_method:steam"}, ref); !slices.Equal(got, []string{"discord_role:1/2", "discord_user:666"}) {
		t.Errorf("KeepAttrs = %v", got)
	}
	// Email codes can only satisfy policies an email sign-in can match.
	if e.CouldAllow([]string{"steam"}, "ann@corp.example") || !e.CouldAllow([]string{"email"}, "ann@corp.example") {
		t.Error("CouldAllow")
	}
}

func testKeys(t *testing.T) *Keys {
	ek, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKCS8PrivateKey(ek)
	k, err := ParseKeys(base64.StdEncoding.EncodeToString(make([]byte, 32)), base64.StdEncoding.EncodeToString(der))
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestTokenFacts(t *testing.T) {
	k := testKeys(t)
	exp := time.Now().Add(time.Hour)
	attrs := []string{"steam_id:76561198000000001"}
	v, _ := k.SealPortal(PortalClaims{SID: "s", Email: "steam:76561198000000001", Expires: exp, Method: "steam", Attrs: attrs})
	pc, err := k.OpenPortal(v)
	if err != nil || pc.Method != "steam" || !slices.Equal(pc.Attrs, attrs) {
		t.Fatalf("portal %+v %v", pc, err)
	}
	v, _ = k.SealCode(SealedCode{ID: "i", SID: "s", Email: "steam:1", App: "web", Expires: exp, Method: "steam", Attrs: attrs})
	sc, err := k.OpenCode(v)
	if err != nil || sc.Method != "steam" || !slices.Equal(sc.Attrs, attrs) {
		t.Fatalf("code %+v %v", sc, err)
	}
	v, _ = k.SealApp(AppClaims{SID: "s", Email: "steam:1", App: "web", Expires: exp, Method: "steam", Attrs: attrs})
	ac, err := k.OpenApp("web", v)
	if err != nil || ac.Method != "steam" || !slices.Equal(ac.Attrs, attrs) {
		t.Fatalf("app %+v %v", ac, err)
	}
	// Tokens without facts are email sign-ins.
	v, _ = k.SealPortal(PortalClaims{SID: "s", Email: "a@b.c", Expires: exp})
	if pc, _ := k.OpenPortal(v); pc.Method != config.MethodEmail || pc.Attrs != nil {
		t.Fatalf("legacy %+v", pc)
	}
}

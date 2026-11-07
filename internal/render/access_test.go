// SPDX-License-Identifier: Apache-2.0

package render

import (
	"encoding/json"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/ingressd/ingressd/internal/secrets"
	"github.com/ingressd/ingressd/pkg/config"
)

const accessConfig = `
version: 1
edge:
  admin: { hostname: edge.example.com }
  acme: { ca: internal }
email: { provider: log, log: { path: /var/lib/ingressd/mail.log } }
access: { portal_host: auth.example.com }
groups:
  family: { emails: [alice@gmail.com] }
service_tokens:
  hook: { client_id: hook.access, client_secret: secret://hook, expires: 2030-01-01 }
policies:
  family: { action: allow, include: [{ group: family }], session: 8h }
  hook: { action: service_auth, include: [{ service_token: hook }], require: [{ ip: [10.0.0.0/8] }] }
apps:
  web:
    hosts: [web.example.com]
    origin: http://192.0.2.10:8080
    access: [family]
    paths: [{ match: /hook/*, access: [hook] }]
  site:
    hosts: [example.com]
    origin: http://192.0.2.11:8080
`

// Fixed key material so the golden file is stable.
var accessSecrets = map[string]string{
	"hook":               "hook-secret",
	"access_session_key": "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=",
	"access_jwt_key":     "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgTohYiduqGv16hl2T1vP3fOGtzle8cig/IqJUnUji592hRANCAARzf4dSjgQn+UtYdnN/pJeuiukBdj4m7d+AQ5fTv+kfhbWMH/F35YYwI9jL+P5riaGOtLY/QewPMEufozI2EXZf",
}

func renderAccess(t *testing.T) *Plan {
	t.Helper()
	cfg, err := config.Parse([]byte(accessConfig))
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	p, err := Render(cfg, secrets.NewMemory(accessSecrets), fakeKeys{},
		Options{AdminListen: "unix//run/ingressd/caddy-admin.sock", ControlSocket: "/run/ingressd/control.sock"})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestAccessGolden(t *testing.T) {
	golden(t, "access-caddy.json", string(renderAccess(t).Caddy)+"\n")
}

func TestAccessStructure(t *testing.T) {
	s := string(renderAccess(t).Caddy)
	// The portal host is a control host and goes to the control socket.
	if !strings.Contains(s, `"auth.example.com"`) || !strings.Contains(s, `"dial": "unix//run/ingressd/control.sock"`) {
		t.Error("portal host not routed to the control socket")
	}
	var root struct {
		Apps struct {
			HTTP struct {
				Servers map[string]struct {
					Routes []struct {
						Match []struct {
							Host []string
						}
						Handle []struct {
							Routes []struct {
								Handle []map[string]any
							}
						}
					}
				}
			}
		}
	}
	if err := json.Unmarshal([]byte(s), &root); err != nil {
		t.Fatal(err)
	}
	first := map[string]map[string]any{}
	for _, r := range root.Apps.HTTP.Servers["edge"].Routes {
		if len(r.Match) == 0 || len(r.Match[0].Host) == 0 || len(r.Handle) == 0 || len(r.Handle[0].Routes) == 0 {
			continue
		}
		first[r.Match[0].Host[0]] = r.Handle[0].Routes[0].Handle[0]
	}
	if h := first["web.example.com"]; h["handler"] != "edge_auth" || h["app"] != "web" || h["portal_url"] != "https://auth.example.com" {
		t.Errorf("protected app's first handler = %v", h)
	}
	if h := first["example.com"]; h["handler"] != "headers" || !strings.Contains(toJSON(h), "X-Edge-User-Email") {
		t.Errorf("public app does not strip identity headers: %v", h)
	}
	if strings.Contains(s, "hook-secret") {
		t.Error("service token secret rendered in plain text")
	}
}

func toJSON(v any) string { b, _ := json.Marshal(v); return string(b) }

func TestIdentityHeaderSpellings(t *testing.T) {
	got := identityHeaderSpellings()
	for _, want := range []string{"X-Edge-User", "X_Edge_User", "X-Edge_User", "X_Edge-User-Email", "Edge_Jwt_Assertion", "X_Edge_Session_Id"} {
		if !slices.Contains(got, want) {
			t.Errorf("missing %s in %v", want, got)
		}
	}
}

func TestEdgeServerSettings(t *testing.T) {
	s := string(renderAccess(t).Caddy)
	for _, want := range []string{`"allow_0rtt": false`, `"{http.request.header.Upgrade}"`} {
		if !strings.Contains(s, want) {
			t.Errorf("caddy config missing %s", want)
		}
	}
	re := regexp.MustCompile(upgradeProtocols)
	for v, ok := range map[string]bool{"websocket": true, "WebSocket": true, "SPDY/3.1": true, "tcp": true, "h2c": false, "h2c,websocket": false, "websocket, h2c": false} {
		if re.MatchString(v) != ok {
			t.Errorf("Upgrade %q allowed = %v", v, !ok)
		}
	}
}

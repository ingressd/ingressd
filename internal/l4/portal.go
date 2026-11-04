// SPDX-License-Identifier: Apache-2.0

package l4

import (
	"html/template"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/ingressd/ingressd/pkg/config"
)

// Authenticator signs a player in under an access policy, for login-to-play.
// internal/auth.Service.PlayAuthenticate (email codes, through the panel on
// managed nodes) is the implementation serve uses; RefuseAuthenticate is the
// fallback when Access cannot run.
//
// Contract:
//   - policy is the service's login_to_play.policy (a name from policies:).
//   - It is called on every request to the portal's /join/<service> page,
//     GET or POST, and owns any multi-step flow (email form, OTP entry,
//     session cookie on the portal host). r.URL is the page to come back to
//     once signed in.
//   - Signed in and allowed by the policy: return the user's email and
//     ok=true WITHOUT writing to w; the portal then allowlists the client IP
//     and renders the confirmation.
//   - Otherwise: write a complete response (form, redirect, denial page) to
//     w and return ok=false; the portal writes nothing more.
type Authenticator func(w http.ResponseWriter, r *http.Request, policy string) (email string, ok bool)

// RefuseAuthenticate is the placeholder Authenticator: sign-in is not
// available, so nobody is allowlisted.
func RefuseAuthenticate(w http.ResponseWriter, _ *http.Request, _ string) (string, bool) {
	http.Error(w, "Sign-in for login-to-play is not available yet.", http.StatusServiceUnavailable)
	return "", false
}

// Portal serves a login-to-play host: "/" lists the services that use it,
// "/join/<service>" signs the player in and allowlists their current IP for
// the service's ttl.
type Portal struct {
	Cfg          *config.Config
	Host         string
	Manager      *Manager
	Authenticate Authenticator
	// ClientIP returns the player's address (controlsrv.ClientIP).
	ClientIP func(*http.Request) string
	// OnAllowed, if set, is told about each entry a player added (managed
	// nodes report it to the panel, which relays it to the org's other
	// nodes serving the service).
	OnAllowed func(Entry)
}

func (p *Portal) services() []string {
	var out []string
	for name, s := range p.Cfg.L4 {
		if s.Access == config.L4AccessLoginToPlay && s.LoginToPlay != nil && s.LoginToPlay.PortalHost == p.Host {
			out = append(out, name)
		}
	}
	slices.Sort(out)
	return out
}

func (p *Portal) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	switch {
	case r.URL.Path == "/":
		writePage(w, http.StatusOK, indexTmpl, map[string]any{"Services": p.services()})
	case strings.HasPrefix(r.URL.Path, "/join/"):
		p.join(w, r, strings.TrimPrefix(r.URL.Path, "/join/"))
	default:
		http.NotFound(w, r)
	}
}

func (p *Portal) join(w http.ResponseWriter, r *http.Request, name string) {
	if !slices.Contains(p.services(), name) {
		http.NotFound(w, r)
		return
	}
	s := p.Cfg.L4[name]
	ip, err := netip.ParseAddr(p.ClientIP(r))
	if err != nil || !ip.Unmap().Is4() {
		writePage(w, http.StatusBadRequest, msgTmpl, map[string]any{
			"Title": "IPv4 needed",
			"Msg":   "Game access works over IPv4 only. Open this page from a connection with IPv4 (for example, disable IPv6 or use mobile data) and try again.",
		})
		return
	}
	email, ok := p.Authenticate(w, r, s.LoginToPlay.Policy)
	if !ok {
		return
	}
	ttl := time.Duration(s.LoginToPlay.TTL)
	e, err := p.Manager.Allow(r.Context(), name, ip.Unmap().String(), email, ttl)
	if err != nil && e.IP == "" {
		http.Error(w, "Could not add your address. Ask the server owner.", http.StatusInternalServerError)
		return
	}
	if p.OnAllowed != nil {
		p.OnAllowed(e)
	}
	expires := ""
	if !e.Expires.IsZero() {
		expires = e.Expires.Format(time.RFC1123)
	}
	writePage(w, http.StatusOK, okTmpl, map[string]any{
		"Service": name, "IP": e.IP, "Email": email, "Expires": expires, "Ports": s.Listen,
	})
}

func writePage(w http.ResponseWriter, code int, t *template.Template, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(code)
	_ = t.Execute(w, data)
}

const page = `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{{block "title" .}}Play{{end}}</title>
<style>body{font-family:system-ui,sans-serif;max-width:36rem;margin:3rem auto;padding:0 1rem;line-height:1.5}code{background:#eee;padding:0 .3em}</style></head><body>{{block "body" .}}{{end}}</body></html>`

var (
	indexTmpl = template.Must(template.Must(template.New("i").Parse(page)).Parse(
		`{{define "body"}}<h1>Join a game server</h1>{{if .Services}}<ul>{{range .Services}}<li><a href="/join/{{.}}">{{.}}</a></li>{{end}}</ul>{{else}}<p>No servers here.</p>{{end}}{{end}}`))
	okTmpl = template.Must(template.Must(template.New("o").Parse(page)).Parse(
		`{{define "body"}}<h1>You're in</h1><p>Your address <code>{{.IP}}</code> may connect to <b>{{.Service}}</b> ({{range $i, $p := .Ports}}{{if $i}}, {{end}}{{$p}}{{end}}){{if .Expires}} until {{.Expires}}{{end}}.</p><p>If your address changes, open this page again.</p>{{end}}`))
	msgTmpl = template.Must(template.Must(template.New("m").Parse(page)).Parse(
		`{{define "title"}}{{.Title}}{{end}}{{define "body"}}<h1>{{.Title}}</h1><p>{{.Msg}}</p>{{end}}`))
)

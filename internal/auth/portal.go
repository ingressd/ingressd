// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"html/template"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/ingressd/ingressd/internal/controlsrv"
	"github.com/ingressd/ingressd/pkg/access"
	"github.com/ingressd/ingressd/pkg/access/idp"
	"github.com/ingressd/ingressd/pkg/config"
	"github.com/ingressd/ingressd/pkg/mailtheme"
)

// PortalHandler serves access.portal_host: the sign-in pages, logout and
// the JWKS that origins use to verify Edge-Jwt-Assertion.
func (s *Service) PortalHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/jwks.json", s.serveJWKS)
	mux.HandleFunc("/login", s.serveLogin)
	mux.HandleFunc("GET /logout", s.serveLogoutConfirm)
	mux.HandleFunc("POST /logout", s.serveLogout)
	mux.HandleFunc("POST "+oauthPath+"start", s.serveOAuthStart)
	mux.HandleFunc("GET "+oauthPath+"{provider}/callback", s.serveOAuthCallback)
	mux.HandleFunc("GET /{$}", s.serveHome)
	return securityHeaders(mux)
}

func securityHeaders(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hd := w.Header()
		// no-transform (with the email_off markers in the page) keeps
		// Cloudflare's Email Address Obfuscation from rewriting addresses
		// into "[email protected]" when the portal is proxied.
		hd.Set("Cache-Control", "no-store, no-transform")
		hd.Set("X-Frame-Options", "DENY")
		hd.Set("X-Content-Type-Options", "nosniff")
		// same-origin (not no-referrer) so the portal's own form posts carry
		// a real Origin and Referer for sameOrigin; nothing leaks off-site.
		hd.Set("Referrer-Policy", "same-origin")
		hd.Set("Content-Security-Policy", portalCSP())
		h.ServeHTTP(w, r)
	})
}

// portalCSP is the portal's Content-Security-Policy. form-action also
// governs the redirects that follow a form submission (browsers check every
// hop), so an app's sign-in form names the app's origin: verifying the code
// answers with a redirect to <app>/.ingressd/callback, which 'self' alone
// would block after the portal cookie is set, leaving the visitor on the
// portal instead of the page they asked for.
func portalCSP(formOrigins ...string) string {
	fa := strings.Join(append([]string{"'self'"}, formOrigins...), " ")
	return "default-src 'none'; style-src 'unsafe-inline'; img-src https:; form-action " + fa + "; frame-ancestors 'none'"
}

// returnHost matches a return URL host that is safe to name in the CSP
// (and to redirect to): a DNS name with an optional port.
var returnHost = regexp.MustCompile(`^[A-Za-z0-9_]([A-Za-z0-9_.-]*[A-Za-z0-9_])?\.?(:[0-9]{1,5})?$`)

func (s *Service) serveJWKS(w http.ResponseWriter, _ *http.Request) {
	st, err := s.state()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=300")
	_ = json.NewEncoder(w).Encode(st.keys.JWKS())
}

// target is where a sign-in should lead: an app and a validated return URL.
type target struct {
	app  string
	cfg  config.App
	rd   *url.URL
	list []string // policies for rd's path
	// nonce is edge_auth's browser binding for the callback code (the "n"
	// login parameter), sealed into the code.
	nonce string
}

// parseTarget validates app and rd. rd must be an https URL on one of the
// app's hosts, so the portal can never be used as an open redirect.
func parseTarget(cfg *config.Config, app, rd string) (*target, error) {
	a, ok := cfg.Apps[app]
	if !ok || !a.Protected() {
		return nil, errors.New("unknown app")
	}
	if len(rd) > 2048 { // it travels inside the sealed callback code
		return nil, errors.New("return URL is too long")
	}
	u, err := url.Parse(rd)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Opaque != "" || u.Host == "" ||
		strings.ContainsAny(rd, "\\\r\n\t") {
		return nil, errors.New("invalid return URL")
	}
	if !returnHost.MatchString(u.Host) {
		return nil, errors.New("invalid return URL")
	}
	if !HostAllowed(a.Hosts, u.Hostname()) {
		return nil, errors.New("return URL is not on the app's hosts")
	}
	return &target{app: app, cfg: a, rd: u, list: ListFor(a, u.EscapedPath())}, nil
}

// maxFormBytes bounds a sign-in form post; its largest field is the 2 KiB
// return URL.
const maxFormBytes = 64 << 10

// parseForm reads the request's urlencoded form, bounded. Parsing it here
// also keeps FormValue from reading multipart bodies: no portal form uses
// them. It writes the response and returns false if the body is too large.
func parseForm(w http.ResponseWriter, r *http.Request) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
	var tooLarge *http.MaxBytesError
	if err := r.ParseForm(); errors.As(err, &tooLarge) {
		http.Error(w, "request too large", http.StatusRequestEntityTooLarge)
		return false
	}
	return true
}

func (s *Service) serveHome(w http.ResponseWriter, r *http.Request) {
	st, err := s.state()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	if sess := s.portalSession(r, st); sess != nil {
		s.page(w, st, http.StatusOK, pageData{Title: "Signed in", Message: "You are signed in as " + sess.Email + ".", Step: "logout", Action: "/logout"})
		return
	}
	http.Redirect(w, r, "/login", http.StatusFound)
}

func (s *Service) serveLogin(w http.ResponseWriter, r *http.Request) {
	st, err := s.state()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if r.Method == http.MethodPost && !sameOrigin(r, st.cfg.Access.PortalHost) {
		http.Error(w, "cross-site request rejected", http.StatusForbidden)
		return
	}
	if !parseForm(w, r) {
		return
	}
	app, rd, nonce := r.FormValue("app"), r.FormValue("rd"), r.FormValue("n")
	var t *target
	if app != "" || rd != "" {
		if t, err = parseTarget(st.cfg, app, rd); err == nil && nonce != "" && !ValidFlowNonce(nonce) {
			err = errors.New("malformed n")
		}
		if err != nil {
			s.page(w, st, http.StatusBadRequest, pageData{Title: "Invalid sign-in link", Message: "This sign-in link is not valid: " + err.Error() + "."})
			return
		}
		t.nonce = nonce
	}
	hidden := map[string]string{"app": app, "rd": rd}
	if nonce != "" {
		hidden["n"] = nonce
	}
	// An existing portal session counts if the app offers its login method;
	// otherwise the visitor picks one of the app's methods.
	if sess := s.portalSession(r, st); sess != nil && (t == nil || slices.Contains(st.loginMethods(t), sess.Method)) {
		s.finish(w, r, st, sess, t)
		return
	}

	title := "Sign in"
	label := st.cfg.Access.Branding.Name
	var lists [][]string
	formOrigin := ""
	if t != nil {
		title, label = "Sign in to "+t.app, t.app
		formOrigin = "https://" + t.rd.Host // the code step redirects to the app's callback
		lists = AllLists(t.cfg)
	} else {
		for _, a := range st.cfg.Apps {
			lists = append(lists, AllLists(a)...)
		}
	}
	s.ServeLogin(w, r, LoginFlow{
		Title:      title,
		Label:      label,
		Hidden:     hidden,
		Methods:    st.loginMethods(t),
		FormOrigin: formOrigin,
		Eligible: func(email string) bool {
			for _, l := range lists {
				if st.eng.CouldAllow(l, email) {
					return true
				}
			}
			return false
		},
		OnVerified: func(w http.ResponseWriter, r *http.Request, email string) {
			sess, err := s.store.CreateSession(r.Context(), email, controlsrv.ClientIP(r), r.UserAgent(), time.Duration(st.cfg.Access.Session))
			if err != nil {
				s.fail(w, st, err)
				return
			}
			sess.Method = config.MethodEmail
			val, err := st.keys.SealPortal(PortalClaims{SID: sess.SID, Email: email, Expires: sess.Expires, Issued: sess.Created, Method: config.MethodEmail})
			if err != nil {
				s.fail(w, st, err)
				return
			}
			http.SetCookie(w, &http.Cookie{Name: PortalCookieName, Value: val, Path: "/", Expires: sess.Expires,
				HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
			s.finish(w, r, st, sess, t)
		},
	})
}

// finish evaluates the target app's policies for a signed-in user and, if
// allowed, redirects to the app's callback with a one-time code.
func (s *Service) finish(w http.ResponseWriter, r *http.Request, st *state, sess *Session, t *target) {
	if t == nil {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	id := s.userIdentity(sess, controlsrv.ClientIP(r))
	d := st.eng.Evaluate(t.list, id)
	switch d.Action {
	case config.ActionBypass:
		http.Redirect(w, r, t.rd.String(), http.StatusFound)
		return
	case config.ActionAllow:
	default:
		s.log.Info("access: denied", "app", t.app, "email", sess.Email, "ip", id.IP, "policy", d.Policy)
		s.page(w, st, http.StatusForbidden, pageData{Title: "Access denied",
			Message: sess.Email + " is not allowed to access " + t.app + ".", Link: "/logout", LinkText: "Sign in as someone else"})
		return
	}
	// Record every allow policy of the app the user satisfies, so path
	// overrides with their own policies work without signing in again.
	grants := map[string]string{}
	exp := sess.Expires
	for _, list := range AllLists(t.cfg) {
		if dd := st.eng.Evaluate(list, id); dd.Action == config.ActionAllow {
			grants[dd.Policy] = st.eng.Version(dd.Policy)
			if e := time.Now().Add(dd.Session); e.Before(exp) {
				exp = e
			}
		}
	}
	// The code is sealed rather than stored: the app's callback may land on
	// another node of the org than this portal request.
	code, err := st.keys.SealCode(SealedCode{ID: randomToken(16), SID: sess.SID, Email: sess.Email, App: t.app, RD: t.rd.String(),
		Grants: grants, SessionIssued: sess.Created, SessionExpires: exp, Expires: time.Now().Add(AuthCodeTTL), Nonce: t.nonce,
		Method: sess.Method, Attrs: sess.Attrs})
	if err != nil {
		s.fail(w, st, err)
		return
	}
	s.log.Info("access: allowed", "app", t.app, "email", sess.Email, "ip", id.IP, "policy", d.Policy)
	cb := url.URL{Scheme: "https", Host: t.rd.Host, Path: "/.ingressd/callback", RawQuery: url.Values{"code": {code}}.Encode()}
	http.Redirect(w, r, cb.String(), http.StatusFound)
}

// serveLogoutConfirm asks before signing out: logout is POST-only so other
// sites cannot sign users out (logout CSRF).
func (s *Service) serveLogoutConfirm(w http.ResponseWriter, r *http.Request) {
	st, err := s.state()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	msg := "You are not signed in."
	if sess := s.portalSession(r, st); sess != nil {
		msg = "You are signed in as " + sess.Email + ". Signing out signs you out of all apps."
	}
	s.page(w, st, http.StatusOK, pageData{Title: "Sign out", Message: msg, Step: "logout", Action: "/logout"})
}

func (s *Service) serveLogout(w http.ResponseWriter, r *http.Request) {
	st, err := s.state()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	if !sameOrigin(r, st.cfg.Access.PortalHost) {
		http.Error(w, "cross-site request rejected", http.StatusForbidden)
		return
	}
	if sess := s.portalSession(r, st); sess != nil {
		if _, err := s.store.Revoke(r.Context(), sess.SID, ""); err != nil {
			s.fail(w, st, err)
			return
		}
		s.log.Info("access: signed out", "email", sess.Email)
		s.reportRevoke(sess)
	}
	http.SetCookie(w, &http.Cookie{Name: PortalCookieName, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
	s.page(w, st, http.StatusOK, pageData{Title: "Signed out", Message: "You are signed out of all apps."})
}

// portalSession returns the live session behind the portal cookie, if any.
func (s *Service) portalSession(r *http.Request, st *state) *Session {
	c, err := r.Cookie(PortalCookieName)
	if err != nil {
		return nil
	}
	pc, err := st.keys.OpenPortal(c.Value)
	if err != nil {
		return nil
	}
	return s.acceptSession(r.Context(), st.cfg.Access, pc, controlsrv.ClientIP(r), r.UserAgent())
}

// sameOrigin rejects cross-site form posts (login and logout CSRF). It
// trusts, in order, Origin, Sec-Fetch-Site and Referer; a request with none
// of them (not a current browser) is rejected.
func sameOrigin(r *http.Request, host string) bool {
	if o := r.Header.Get("Origin"); o != "" && o != "null" {
		u, err := url.Parse(o)
		return err == nil && strings.EqualFold(u.Hostname(), host)
	}
	if s := r.Header.Get("Sec-Fetch-Site"); s != "" {
		return s != "cross-site"
	}
	if ref := r.Header.Get("Referer"); ref != "" {
		u, err := url.Parse(ref)
		return err == nil && strings.EqualFold(u.Hostname(), host)
	}
	return false
}

// --- reusable email sign-in flow ---

// LoginFlow configures ServeLogin, the email → one-time code flow. It is
// self-contained so other features (login-to-play, Phase 4) can mount it
// on their own hosts.
type LoginFlow struct {
	Title string // page heading, e.g. "Sign in to web"
	Label string // what the email says the code is for, e.g. "web"
	// Policy names the app or policy for the panel's logs (default Label).
	Policy string
	// Hidden fields are carried through both forms (e.g. return URLs).
	Hidden map[string]string
	// Methods are the login methods to offer (nil: email only). Provider
	// buttons post to /oauth/start with the hidden fields.
	Methods []string
	// FormOrigin is where OnVerified may redirect besides this host (an
	// app's origin), allowed by the pages' form-action (see portalCSP).
	FormOrigin string
	// Eligible reports whether a code should really be sent to an email.
	// The response is identical either way. Nil means always.
	Eligible func(email string) bool
	// OnVerified runs once the user proved control of the email. It must
	// write the response.
	OnVerified func(w http.ResponseWriter, r *http.Request, email string)
}

// ServeLogin runs the email sign-in flow at the request's path: GET shows
// the email form; POST step=email sends a code; POST step=code verifies it.
// Rate limits, attempt caps and lockouts are applied by the Service.
func (s *Service) ServeLogin(w http.ResponseWriter, r *http.Request, f LoginFlow) {
	st, err := s.state()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	if !parseForm(w, r) {
		return
	}
	pd := pageData{Title: f.Title, Hidden: f.Hidden, Action: r.URL.Path, FormOrigin: f.FormOrigin}
	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	emailOK := len(f.Methods) == 0 || slices.Contains(f.Methods, config.MethodEmail)
	for _, m := range f.Methods {
		if m != config.MethodEmail {
			pd.Providers = append(pd.Providers, providerButton{Method: m, Title: idp.Title(m)})
		}
	}
	pd.FormOrigins = providerOrigins(f.Methods)
	if r.Method != http.MethodPost || !emailOK {
		pd.Step = "email"
		if !emailOK {
			pd.Step = "providers"
		}
		s.page(w, st, http.StatusOK, pd)
		return
	}
	pd.Providers, pd.FormOrigins = nil, nil
	ip := controlsrv.ClientIP(r)
	email, err := NormalizeEmail(r.PostFormValue("email"))
	if err != nil {
		pd.Step, pd.Error = "email", "Enter a valid email address."
		s.page(w, st, http.StatusOK, pd)
		return
	}
	pd.Email = email
	switch r.PostFormValue("step") {
	case "email":
		eligible := f.Eligible == nil || f.Eligible(email)
		policy := f.Policy
		if policy == "" {
			policy = f.Label
		}
		if err := s.requestCode(r.Context(), st, codeRequest{email: email, ip: ip, label: f.Label, policy: policy, host: host}, eligible); err != nil {
			if errors.Is(err, ErrRateLimited) {
				pd.Step, pd.Error = "email", "Too many sign-in attempts. Try again later."
				s.page(w, st, http.StatusTooManyRequests, pd)
				return
			}
			if errors.Is(err, ErrPanelUnavailable) {
				pd.Step, pd.Error = "email", "Sign-in is temporarily unavailable. Try again in a minute."
				s.page(w, st, http.StatusServiceUnavailable, pd)
				return
			}
			s.fail(w, st, err)
			return
		}
		pd.Step = "code"
		pd.Message = "A code is on its way to " + email + " if that address may sign in. It expires in " +
			fmtDuration(time.Duration(st.cfg.Access.OTP.TTL)) + "."
		pd.CodeLen = st.cfg.Access.OTP.Length
		s.page(w, st, http.StatusOK, pd)
	case "code":
		code := strings.TrimSpace(r.PostFormValue("code"))
		if err := s.verifyCode(r.Context(), st, email, code, ip); err != nil {
			if errors.Is(err, ErrPanelUnavailable) {
				pd.Step, pd.Error, pd.CodeLen = "code", "Sign-in is temporarily unavailable. Try again in a minute.", st.cfg.Access.OTP.Length
				s.page(w, st, http.StatusServiceUnavailable, pd)
				return
			}
			if !errors.Is(err, ErrInvalidCode) {
				s.fail(w, st, err)
				return
			}
			s.log.Info("access: wrong code", "email", email, "ip", ip)
			pd.Step, pd.Error, pd.CodeLen = "code", "That code is invalid or has expired.", st.cfg.Access.OTP.Length
			s.page(w, st, http.StatusUnauthorized, pd)
			return
		}
		f.OnVerified(w, r, email)
	default:
		pd.Step = "email"
		s.page(w, st, http.StatusBadRequest, pd)
	}
}

// PolicyLogin is ServeLogin bound to one named policy: after the code is
// verified, the policy is evaluated for the email and client IP, and
// onAllowed runs only if it allows. This is the entry point for features
// that need "a verified email that satisfies policy P" (login-to-play).
func (s *Service) PolicyLogin(policy, title string, onAllowed func(w http.ResponseWriter, r *http.Request, email string)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		st, err := s.state()
		if err != nil {
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}
		host := r.Host
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		if r.Method == http.MethodPost && !sameOrigin(r, host) {
			http.Error(w, "cross-site request rejected", http.StatusForbidden)
			return
		}
		list := []string{policy}
		s.ServeLogin(w, r, LoginFlow{
			Title: title, Label: title,
			Eligible: func(email string) bool { return st.eng.CouldAllow(list, email) },
			OnVerified: func(w http.ResponseWriter, r *http.Request, email string) {
				if d := st.eng.Evaluate(list, s.identity(email, controlsrv.ClientIP(r))); d.Action != config.ActionAllow {
					s.page(w, st, http.StatusForbidden, pageData{Title: "Access denied", Message: email + " is not allowed."})
					return
				}
				onAllowed(w, r, email)
			},
		})
	})
}

func (s *Service) fail(w http.ResponseWriter, st *state, err error) {
	s.log.Error("access: portal error", "err", err)
	s.page(w, st, http.StatusInternalServerError, pageData{Title: "Something went wrong", Message: "The sign-in portal hit an error. Try again in a moment."})
}

// --- edge_auth API (on the control socket, Host: ControlHost) ---

// EdgeAPIHandler serves the endpoints edge_auth calls over the control
// socket: code exchange and the revocation list.
func (s *Service) EdgeAPIHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/exchange", s.serveExchange)
	mux.HandleFunc("GET /v1/revocations", s.serveRevocations)
	return mux
}

// ExchangeRequest and ExchangeResponse are the edge_auth code exchange.
type ExchangeRequest struct {
	Code string `json:"code"`
	App  string `json:"app"`
	Host string `json:"host"` // host the callback arrived on
	// IP is the visitor's address as edge_auth saw it; the app's policies
	// are evaluated for it (and the code's email) before a cookie is issued.
	IP string `json:"ip,omitempty"`
	// Nonce is the sign-in nonce cookie edge_auth set on the app host when
	// it sent the browser to the portal ("" if the browser has none); it
	// must match the code's (login fixation).
	Nonce string `json:"nonce,omitempty"`
}

type ExchangeResponse struct {
	Token   string `json:"token"`
	Expires int64  `json:"expires"` // unix seconds
	RD      string `json:"rd"`
}

func (s *Service) serveExchange(w http.ResponseWriter, r *http.Request) {
	st, err := s.current()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	var req ExchangeRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192)).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if strings.HasPrefix(req.Code, "v4.local.") {
		s.exchangeSealed(w, r, st, req)
		return
	}
	// Codes from before sealed codes (stored in this node's database). Only
	// a portal on the node issues them, which realms never have.
	if st.realms != nil || st.keys == nil {
		http.Error(w, "invalid or expired code", http.StatusForbidden)
		return
	}
	ac, err := s.store.RedeemAuthCode(r.Context(), req.Code, req.App)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if ac == nil {
		http.Error(w, "invalid or expired code", http.StatusForbidden)
		return
	}
	rd, err := url.Parse(ac.RD)
	host := req.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if err != nil || !strings.EqualFold(rd.Hostname(), host) {
		http.Error(w, "code was issued for another host", http.StatusForbidden)
		return
	}
	sess, err := s.store.GetSession(r.Context(), ac.SID)
	if err != nil || sess == nil {
		http.Error(w, "session is no longer valid", http.StatusForbidden)
		return
	}
	now := time.Now()
	tok, err := st.keys.SealApp(AppClaims{SID: ac.SID, Email: sess.Email, App: ac.App, Grants: ac.Grants, IssuedAt: now, Expires: ac.SessionExpires})
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(ExchangeResponse{Token: tok, Expires: ac.SessionExpires.Unix(), RD: ac.RD})
}

// RevocationList is polled by edge_auth with If-None-Match.
type RevocationList struct {
	Revision int64    `json:"revision"`
	SIDs     []string `json:"sids"`
	// Before maps an email (or "*" for everyone) to a unix time: app
	// cookies issued before it are rejected (access.revoked_before).
	Before map[string]int64 `json:"before,omitempty"`
}

func (s *Service) serveRevocations(w http.ResponseWriter, r *http.Request) {
	s.maybeGC()
	rev, sids, err := s.store.Revocations(r.Context())
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	etag := `"` + itoa(rev) + `"`
	var before map[string]int64
	// edge_auth of a realm app asks for its realm's list: one realm's
	// revoked_before never signs out another realm's users.
	realm := r.URL.Query().Get("realm")
	s.mu.RLock()
	var a *config.Access
	if s.st != nil {
		if realm != "" {
			a = s.st.cfg.RealmAccess(realm)
		} else {
			a = s.st.cfg.Access
		}
	}
	if a != nil {
		if len(a.RevokedSessions) > 0 || len(a.RevokedBefore) > 0 {
			sids = append(sids, a.RevokedSessions...)
			slices.Sort(sids)
			sids = slices.Compact(sids)
			before = map[string]int64{}
			for who, t := range a.RevokedBefore {
				before[who] = t.Unix()
			}
			b, _ := json.Marshal([]any{sids, before})
			sum := sha256.Sum256(b)
			etag = `"` + itoa(rev) + "-" + hex.EncodeToString(sum[:6]) + `"`
		}
	}
	s.mu.RUnlock()
	w.Header().Set("ETag", etag)
	if slices.Contains(strings.Split(r.Header.Get("If-None-Match"), ","), etag) {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(RevocationList{Revision: rev, SIDs: sids, Before: before})
}

// exchangeSealed redeems a sealed callback code (see SealCode). Any node of
// the org can redeem it; each node redeems a code at most once.
func (s *Service) exchangeSealed(w http.ResponseWriter, r *http.Request, st *state, req ExchangeRequest) {
	keys, a, ok := st.appAccess(req.App)
	if !ok {
		http.Error(w, "invalid or expired code", http.StatusForbidden)
		return
	}
	ac, err := keys.OpenCode(req.Code)
	if err != nil || ac.App != req.App {
		http.Error(w, "invalid or expired code", http.StatusForbidden)
		return
	}
	rd, err := url.Parse(ac.RD)
	host := req.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if err != nil || !strings.EqualFold(rd.Hostname(), host) {
		http.Error(w, "code was issued for another host", http.StatusForbidden)
		return
	}
	// The code must come back to the browser that started the sign-in, or
	// an attacker could sign a victim into the attacker's account (login
	// fixation). This node's portal always seals the nonce; the hosted
	// panel's central portal does not carry it yet, so its codes are
	// checked only when they have one.
	if ac.Nonce != "" || a == nil || a.PortalURL == "" {
		if req.Nonce == "" || !hmac.Equal([]byte(ac.Nonce), []byte(FlowNonceHash(req.Nonce))) {
			http.Error(w, "sign-in was started in another browser", http.StatusForbidden)
			return
		}
	}
	if fresh, err := s.store.useCode(r.Context(), ac.ID, AuthCodeTTL); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	} else if !fresh {
		http.Error(w, "invalid or expired code", http.StatusForbidden)
		return
	}
	sess := s.acceptSession(r.Context(), a, &PortalClaims{SID: ac.SID, Email: ac.Email, Expires: ac.SessionExpires, Issued: ac.SessionIssued,
		Method: ac.Method, Attrs: ac.Attrs}, "", "")
	if sess == nil {
		http.Error(w, "session is no longer valid", http.StatusForbidden)
		return
	}
	exp := ac.SessionExpires
	if sess.Expires.Before(exp) {
		exp = sess.Expires
	}
	// The node is the authority on its apps' policies: whoever sealed the
	// code (this node's portal, another node's, or the panel's central
	// portal) only proved the email. Evaluate the app's policies for that
	// email and the visitor's address now, and grant what they allow.
	// Facts not referred to by this node's policies are not kept (the
	// sealer may know other policies).
	sess.Attrs = access.KeepAttrs(sess.Attrs, st.eng.ReferencedAttrs())
	grants, exp, ok := s.grantsAt(st, ac, sess, req.IP, exp)
	if !ok {
		s.log.Info("access: denied at callback", "app", ac.App, "email", sess.Email, "ip", req.IP)
		http.Error(w, "not allowed: "+sess.Email+" may not access this app", http.StatusForbidden)
		return
	}
	tok, err := keys.SealApp(AppClaims{SID: ac.SID, Email: sess.Email, App: ac.App, Grants: grants, IssuedAt: time.Now(), Expires: exp,
		Method: sess.Method, Attrs: sess.Attrs})
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(ExchangeResponse{Token: tok, Expires: exp.Unix(), RD: ac.RD})
}

// grantsAt evaluates the code's app for its email from ip: ok is false when
// the policy list of the return URL's path does not allow the identity.
// grants lists every allow policy of the app the identity satisfies (path
// overrides work without signing in again); exp is shortened to the
// shortest session of those policies.
func (s *Service) grantsAt(st *state, ac *SealedCode, sess *Session, ip string, exp time.Time) (map[string]string, time.Time, bool) {
	app, ok := st.cfg.Apps[ac.App]
	if !ok || !app.Protected() {
		return nil, exp, false
	}
	rd, err := url.Parse(ac.RD)
	if err != nil {
		return nil, exp, false
	}
	id := s.userIdentity(sess, ip)
	if d := st.eng.Evaluate(ListFor(app, rd.EscapedPath()), id); !d.Allowed() {
		return nil, exp, false
	}
	grants := map[string]string{}
	for _, list := range AllLists(app) {
		if d := st.eng.Evaluate(list, id); d.Action == config.ActionAllow {
			grants[d.Policy] = st.eng.Version(d.Policy)
			if d.Session > 0 {
				if e := time.Now().Add(d.Session); e.Before(exp) {
					exp = e
				}
			}
		}
	}
	return grants, exp, true
}

func itoa(n int64) string { b, _ := json.Marshal(n); return string(b) }

// --- pages ---

type pageData struct {
	Brand    config.Branding
	Title    string
	Message  string
	Error    string
	Step     string // email | code | logout | "" (message page)
	Action   string
	Email    string
	CodeLen  int
	Hidden   map[string]string
	Link     string
	LinkText string
	// Providers are sign-in buttons (posting to /oauth/start) shown with
	// the email step, or alone (step "providers").
	Providers []providerButton
	// FormOrigins are added to the CSP form-action: a provider button's
	// submission redirects to the provider.
	FormOrigins []string
	// FormOrigin is added to the page's form-action too: the code step
	// redirects to the app (see portalCSP).
	FormOrigin string
}

type providerButton struct{ Method, Title string }

func (s *Service) page(w http.ResponseWriter, st *state, status int, d pageData) {
	d.Brand = st.cfg.Access.Branding
	origins := d.FormOrigins
	if d.FormOrigin != "" {
		origins = append(slices.Clone(origins), d.FormOrigin)
	}
	if len(origins) > 0 {
		w.Header().Set("Content-Security-Policy", portalCSP(origins...))
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := pageTmpl.Execute(w, d); err != nil {
		s.log.Error("access: render page", "err", err)
	}
}

var pageTmpl = template.Must(template.New("page").Funcs(template.FuncMap{
	"onAccent": mailtheme.OnAccent,
	// Cloudflare skips everything between these markers when obfuscating
	// addresses; html/template strips comments from template text.
	"emailOff": func() template.HTML { return "<!--email_off-->" },
	"emailOn":  func() template.HTML { return "<!--/email_off-->" },
}).Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{.Title}} · {{.Brand.Name}}</title>
<style>
body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:#f4f4f5;font-family:-apple-system,"Segoe UI",Roboto,sans-serif;color:#18181b}
main{background:#fff;border-radius:12px;box-shadow:0 1px 3px rgba(0,0,0,.1);padding:32px;width:100%;max-width:360px;margin:16px}
h1{font-size:20px;margin:0 0 16px}p{line-height:1.5;color:#3f3f46}
label{display:block;font-size:14px;margin-bottom:6px;color:#3f3f46}
input[type=email],input[type=text]{box-sizing:border-box;width:100%;padding:10px 12px;font-size:16px;border:1px solid #d4d4d8;border-radius:8px;margin-bottom:16px}
button,.btn{display:inline-block;box-sizing:border-box;width:100%;padding:10px;font-size:16px;border:0;border-radius:8px;color:{{onAccent .Brand.Color}};background:{{.Brand.Color}};cursor:pointer;text-align:center;text-decoration:none}
form.idp{margin:0 0 8px}.or{text-align:center;font-size:13px;color:#71717a;margin:12px 0}
.err{color:#b91c1c}.logo{height:32px;margin-bottom:16px}.foot{font-size:12px;color:#a1a1aa;margin-top:24px}
@media (prefers-color-scheme:dark){body{background:#18181b;color:#f4f4f5}main{background:#27272a}p,label{color:#d4d4d8}input{background:#18181b;color:#f4f4f5;border-color:#52525b}}
</style></head><body>{{emailOff}}<main>
{{if .Brand.LogoURL}}<img class="logo" src="{{.Brand.LogoURL}}" alt="{{.Brand.Name}}">{{end}}
<h1>{{.Title}}</h1>
{{if .Message}}<p id="message">{{.Message}}</p>{{end}}
{{if .Error}}<p class="err" id="error">{{.Error}}</p>{{end}}
{{if or (eq .Step "email") (eq .Step "providers")}}{{$h := .Hidden}}{{range .Providers}}
<form method="post" action="/oauth/start" class="idp">
{{range $k, $v := $h}}<input type="hidden" name="{{$k}}" value="{{$v}}">{{end}}
<input type="hidden" name="provider" value="{{.Method}}">
<button type="submit" id="idp-{{.Method}}">Continue with {{.Title}}</button>
</form>
{{end}}{{if and .Providers (eq .Step "email")}}<p class="or">or</p>{{end}}{{end}}
{{if eq .Step "email"}}
<form method="post" action="{{.Action}}">
{{range $k, $v := .Hidden}}<input type="hidden" name="{{$k}}" value="{{$v}}">{{end}}
<input type="hidden" name="step" value="email">
<label for="email">Email address</label>
<input type="email" id="email" name="email" value="{{.Email}}" autocomplete="email" required autofocus>
<button type="submit">Email me a code</button>
</form>
{{else if eq .Step "code"}}
<form method="post" action="{{.Action}}">
{{range $k, $v := .Hidden}}<input type="hidden" name="{{$k}}" value="{{$v}}">{{end}}
<input type="hidden" name="step" value="code">
<input type="hidden" name="email" value="{{.Email}}">
<label for="code">Sign-in code</label>
<input type="text" id="code" name="code" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]*" maxlength="{{.CodeLen}}" required autofocus>
<button type="submit">Sign in</button>
</form>
{{else if eq .Step "logout"}}
<form method="post" action="{{.Action}}">
<button type="submit">Sign out</button>
</form>
{{end}}
{{if .Link}}<p><a class="btn" href="{{.Link}}">{{.LinkText}}</a></p>{{end}}
<p class="foot">{{.Brand.Name}}</p>
</main>{{emailOn}}</body></html>
`))

// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/ingressd/ingressd/internal/controlsrv"
	"github.com/ingressd/ingressd/pkg/access"
	"github.com/ingressd/ingressd/pkg/access/idp"
	"github.com/ingressd/ingressd/pkg/config"
)

// Third-party sign-in on the node's own portal (access.providers; see
// docs/ACCESS-PROVIDERS.md). The login page offers the app's
// login_methods; a provider button POSTs to /oauth/start (same-origin
// only), which seals the flow (state, PKCE verifier, nonce, the target and
// edge_auth's browser binding) into a cookie scoped to /oauth/ and sends
// the browser to the provider. The provider redirects to
// /oauth/<provider>/callback, where idp.Finish verifies everything; the
// facts the policies refer to are kept in the portal session and the
// callback code, and the app's policies are evaluated as for an emailed
// code.

const oauthPath = "/oauth/"

// buildProviders resolves access.providers for this node's portal.
func buildProviders(cfg *config.Config, res Resolver) (map[string]*idp.Provider, error) {
	if !Enabled(cfg) || len(cfg.Access.Providers) == 0 {
		return nil, nil
	}
	out := map[string]*idp.Provider{}
	for name, p := range cfg.Access.Providers {
		var secret, key string
		var err error
		if p.ClientSecret != "" {
			if secret, err = res.Resolve(p.ClientSecret); err != nil {
				return nil, fmt.Errorf("access.providers.%s.client_secret: %w", name, err)
			}
		}
		if p.APIKey != "" {
			if key, err = res.Resolve(p.APIKey); err != nil {
				return nil, fmt.Errorf("access.providers.%s.api_key: %w", name, err)
			}
		}
		out[name] = idp.New(name, p, secret, key)
	}
	return out, nil
}

// CallbackURL is the redirect URI to register with a provider for a
// portal host.
func CallbackURL(portalHost, provider string) string {
	return "https://" + portalHost + oauthPath + provider + "/callback"
}

// loginMethods are the methods the login page offers for a target (every
// configured one without a target).
func (st *state) loginMethods(t *target) []string {
	var want []string
	if t != nil {
		want = config.AppLoginMethods(t.cfg)
	} else {
		want = append([]string{config.MethodEmail}, config.Providers...)
	}
	var out []string
	for _, m := range want {
		if m == config.MethodEmail || st.providers[m] != nil {
			out = append(out, m)
		}
	}
	return out
}

// providerOrigins are the origins a provider button's form submission
// redirects to; the page's CSP form-action must allow them.
func providerOrigins(methods []string) []string {
	e := idp.DefaultEndpoints()
	var out []string
	add := func(u string) {
		if p, err := url.Parse(u); err == nil && p.Host != "" {
			o := p.Scheme + "://" + p.Host
			if !slices.Contains(out, o) {
				out = append(out, o)
			}
		}
	}
	for _, m := range methods {
		switch m {
		case config.MethodDiscord:
			add(e.DiscordAuth)
		case config.MethodGoogle:
			add(e.GoogleIssuer)
		case config.MethodMicrosoft:
			add(e.MicrosoftLogin)
		case config.MethodSteam:
			add(e.SteamOpenID)
		}
	}
	return out
}

// serveOAuthStart starts a provider sign-in (POST, same origin only).
func (s *Service) serveOAuthStart(w http.ResponseWriter, r *http.Request) {
	st, err := s.state()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	if !sameOrigin(r, st.cfg.Access.PortalHost) {
		http.Error(w, "cross-site request rejected", http.StatusForbidden)
		return
	}
	if !parseForm(w, r) {
		return
	}
	method := r.PostFormValue("provider")
	app, rd, nonce := r.PostFormValue("app"), r.PostFormValue("rd"), r.PostFormValue("n")
	var t *target
	if app != "" || rd != "" {
		if t, err = parseTarget(st.cfg, app, rd); err == nil && nonce != "" && !ValidFlowNonce(nonce) {
			err = errors.New("malformed n")
		}
		if err != nil {
			s.page(w, st, http.StatusBadRequest, pageData{Title: "Invalid sign-in link", Message: "This sign-in link is not valid: " + err.Error() + "."})
			return
		}
	}
	p := st.providers[method]
	if p == nil || !slices.Contains(st.loginMethods(t), method) {
		s.page(w, st, http.StatusBadRequest, pageData{Title: "Sign-in method not available", Message: "This sign-in method is not enabled here."})
		return
	}
	authURL, f, err := p.Start(r.Context(), CallbackURL(st.cfg.Access.PortalHost, method), idp.WantsFrom(st.eng.ReferencedAttrs()))
	if err != nil {
		s.log.Error("access: starting provider sign-in failed", "provider", method, "err", err)
		s.page(w, st, http.StatusBadGateway, pageData{Title: "Sign-in unavailable", Message: idp.Title(method) + " sign-in is unavailable right now. Try again in a moment."})
		return
	}
	f.App, f.RD, f.N = app, rd, nonce
	sealed, err := idp.SealFlow(st.keys.IDPFlowKey(), f)
	if err != nil {
		s.fail(w, st, err)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: idp.FlowCookieName, Value: sealed, Path: oauthPath, MaxAge: int(idp.FlowTTL.Seconds()),
		HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
	// The provider's authorization endpoint, from our own configuration.
	http.Redirect(w, r, authURL, http.StatusSeeOther) //nolint:gosec // G710: not user-controlled
}

// serveOAuthCallback completes a provider sign-in.
func (s *Service) serveOAuthCallback(w http.ResponseWriter, r *http.Request) {
	st, err := s.state()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	method := r.PathValue("provider")
	p := st.providers[method]
	c, cerr := r.Cookie(idp.FlowCookieName)
	// The flow cookie is single use, whatever happens next.
	http.SetCookie(w, &http.Cookie{Name: idp.FlowCookieName, Value: "", Path: oauthPath, MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
	if p == nil || cerr != nil {
		s.page(w, st, http.StatusBadRequest, pageData{Title: "Sign-in expired", Message: idp.ErrState.Msg + ".", Link: "/login", LinkText: "Sign in"})
		return
	}
	f, err := idp.OpenFlow(st.keys.IDPFlowKey(), c.Value)
	if err != nil {
		s.page(w, st, http.StatusBadRequest, pageData{Title: "Sign-in expired", Message: idp.ErrState.Msg + ".", Link: "/login", LinkText: "Sign in"})
		return
	}
	id, err := p.Finish(r.Context(), CallbackURL(st.cfg.Access.PortalHost, method), f, r.URL.Query())
	if err != nil {
		var ue *idp.Error
		msg := idp.Title(method) + " sign-in failed. Try again."
		if errors.As(err, &ue) {
			msg = strings.ToUpper(ue.Msg[:1]) + ue.Msg[1:] + "."
		}
		s.log.Info("access: provider sign-in failed", "provider", method, "ip", controlsrv.ClientIP(r), "err", err)
		s.page(w, st, http.StatusForbidden, pageData{Title: "Sign-in failed", Message: msg, Link: "/login", LinkText: "Try again"})
		return
	}
	var t *target
	if f.App != "" || f.RD != "" {
		if t, err = parseTarget(st.cfg, f.App, f.RD); err != nil {
			s.page(w, st, http.StatusBadRequest, pageData{Title: "Invalid sign-in link", Message: "This sign-in link is not valid: " + err.Error() + "."})
			return
		}
		t.nonce = f.N
		if !slices.Contains(st.loginMethods(t), method) {
			s.page(w, st, http.StatusForbidden, pageData{Title: "Sign-in method not available", Message: "This sign-in method is not enabled for " + t.app + "."})
			return
		}
	}
	sess, err := s.providerSession(w, r, st, id)
	if err != nil {
		s.fail(w, st, err)
		return
	}
	s.log.Info("access: signed in with provider", "provider", method, "user", sess.Email, "ip", controlsrv.ClientIP(r))
	s.finish(w, r, st, sess, t)
}

// providerSession creates the portal session (and cookie) of a provider
// sign-in. It keeps only the facts the policies refer to, and lasts no
// longer than the provider's session setting.
func (s *Service) providerSession(w http.ResponseWriter, r *http.Request, st *state, id *idp.Identity) (*Session, error) {
	ttl := time.Duration(st.cfg.Access.Session)
	if ps := time.Duration(st.cfg.Access.Providers[id.Method].Session); ps > 0 && ps < ttl {
		ttl = ps
	}
	attrs := access.KeepAttrs(id.Attrs, st.eng.ReferencedAttrs())
	sess, err := s.store.CreateSession(r.Context(), id.Principal(), controlsrv.ClientIP(r), r.UserAgent(), ttl)
	if err != nil {
		return nil, err
	}
	sess.Method, sess.Attrs = id.Method, attrs
	val, err := st.keys.SealPortal(PortalClaims{SID: sess.SID, Email: sess.Email, Expires: sess.Expires, Issued: sess.Created, Method: id.Method, Attrs: attrs})
	if err != nil {
		return nil, err
	}
	http.SetCookie(w, &http.Cookie{Name: PortalCookieName, Value: val, Path: "/", Expires: sess.Expires,
		HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
	return sess, nil
}

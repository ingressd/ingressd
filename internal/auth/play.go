// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/ingressd/ingressd/internal/controlsrv"
	"github.com/ingressd/ingressd/pkg/config"
)

// PlayAuthenticate is the login-to-play authenticator (l4.Authenticator):
// it signs a player in with an emailed code (through the panel on managed
// nodes, the local email provider standalone) and checks the service's
// policy for the verified email and the player's IP.
//
// Signed in and allowed: it returns the email and true without writing to
// w (cookies it sets are only headers). Otherwise it writes a complete
// page (email form, code form, denial) and returns false.
func (s *Service) PlayAuthenticate(w http.ResponseWriter, r *http.Request, policy string) (string, bool) {
	st, err := s.state()
	if err != nil {
		http.Error(w, "Sign-in is not available on this server: "+err.Error(), http.StatusServiceUnavailable)
		return "", false
	}
	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	list := []string{policy}
	ip := controlsrv.ClientIP(r)
	allowed := func(email string) bool {
		return st.eng.Evaluate(list, s.identity(email, ip)).Action == config.ActionAllow
	}
	deny := func(email string) {
		s.page(w, st, http.StatusForbidden, pageData{Title: "Access denied", Message: email + " may not join this server."})
	}

	if c, err := r.Cookie(PlayCookieName); err == nil {
		if pc, err := st.keys.OpenPlay(c.Value); err == nil {
			if sess := s.acceptSession(r.Context(), st.cfg.Access, pc, ip, r.UserAgent()); sess != nil {
				if allowed(sess.Email) {
					return sess.Email, true
				}
				if r.Method != http.MethodPost {
					deny(sess.Email)
					return "", false
				}
				// POST: let the player sign in as someone else below.
			}
		}
	}

	if r.Method == http.MethodPost && !sameOrigin(r, host) {
		http.Error(w, "cross-site request rejected", http.StatusForbidden)
		return "", false
	}
	label := strings.TrimPrefix(r.URL.Path, "/join/")
	var verified string
	s.ServeLogin(w, r, LoginFlow{
		Title:    "Sign in to play",
		Label:    label,
		Policy:   policy,
		Eligible: func(email string) bool { return st.eng.CouldAllow(list, email) },
		OnVerified: func(w http.ResponseWriter, r *http.Request, email string) {
			if !allowed(email) {
				deny(email)
				return
			}
			sess, err := s.store.CreateSession(r.Context(), email, ip, r.UserAgent(), time.Duration(st.cfg.Access.Session))
			if err != nil {
				s.fail(w, st, err)
				return
			}
			val, err := st.keys.SealPlay(PortalClaims{SID: sess.SID, Email: email, Expires: sess.Expires, Issued: sess.Created})
			if err != nil {
				s.fail(w, st, err)
				return
			}
			http.SetCookie(w, &http.Cookie{Name: PlayCookieName, Value: val, Path: "/", Expires: sess.Expires,
				HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
			verified = email // the caller writes the confirmation page
		},
	})
	if verified == "" {
		return "", false
	}
	return verified, true
}

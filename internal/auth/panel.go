// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/ingressd/ingressd/pkg/config"
	"github.com/ingressd/ingressd/pkg/nodeproto"
)

// Panel is the hosted panel as Access sees it on a managed node (the node
// agent implements it over the control channel). With email.provider:
// panel, one-time codes are sent and checked by the panel, so a sign-in
// started on one node can finish on another.
type Panel interface {
	OTPStart(ctx context.Context, req nodeproto.AuthOTPStart) (nodeproto.AuthOTPStartResult, error)
	OTPVerify(ctx context.Context, req nodeproto.AuthOTPVerify) (nodeproto.AuthOTPVerifyResult, error)
	// ReportRevoke tells the panel about a sign-out so it can revoke the
	// session on the org's other nodes. Best effort.
	ReportRevoke(r nodeproto.AuthRevoke) error
}

// ErrPanelUnavailable means email.provider is panel but the node has no
// working connection to the panel right now.
var ErrPanelUnavailable = errors.New("sign-in is temporarily unavailable (the node cannot reach the ingressd panel)")

var (
	panelMu sync.RWMutex
	panel   Panel
)

// SetPanel registers the panel connection (nil unregisters). serve calls
// it when managed mode starts and stops.
func SetPanel(p Panel) {
	panelMu.Lock()
	panel = p
	panelMu.Unlock()
}

func currentPanel() Panel {
	panelMu.RLock()
	defer panelMu.RUnlock()
	return panel
}

// panelTimeout bounds one OTP round trip through the panel.
const panelTimeout = 15 * time.Second

func usesPanel(cfg *config.Config) bool { return cfg.Email.Provider == config.EmailPanel }

// panelStart asks the panel to email a code. It runs in the background
// (like local delivery) so response timing does not reveal eligibility.
func (s *Service) panelStart(st *state, req nodeproto.AuthOTPStart) error {
	p := currentPanel()
	if p == nil {
		return ErrPanelUnavailable
	}
	o := st.cfg.Access.OTP
	req.TTL, req.Length, req.Attempts = time.Duration(o.TTL), o.Length, o.Attempts
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		ctx, cancel := context.WithTimeout(s.ctx, panelTimeout)
		defer cancel()
		res, err := p.OTPStart(ctx, req)
		switch {
		case err != nil:
			s.log.Error("access: asking the panel to send a sign-in code failed", "email", req.Email, "err", err)
		case !res.OK:
			s.log.Warn("access: the panel did not send a sign-in code", "email", req.Email, "ip", req.ClientIP, "reason", res.Code, "message", res.Message)
		}
	}()
	return nil
}

// panelVerify checks a code with the panel. Local lockouts and failure
// counting still apply, so a node cannot be used to guess faster than the
// panel allows.
func (s *Service) panelVerify(ctx context.Context, st *state, email, code, ip string) error {
	o := st.otp
	failKey, lockKey := guessKeys(email, ip)
	for _, key := range []string{"lock:email:" + email, lockKey} {
		if locked, err := o.Store.Locked(ctx, key); err != nil {
			return err
		} else if locked {
			return ErrInvalidCode
		}
	}
	p := currentPanel()
	if p == nil {
		return ErrPanelUnavailable
	}
	pctx, cancel := context.WithTimeout(ctx, panelTimeout)
	defer cancel()
	res, err := p.OTPVerify(pctx, nodeproto.AuthOTPVerify{Email: email, Code: code, ClientIP: ip})
	if err != nil {
		s.log.Error("access: verifying a code with the panel failed", "email", email, "err", err)
		return ErrPanelUnavailable
	}
	if res.OK && res.Email == email {
		_ = o.Store.ClearHits(ctx, failKey)
		return nil
	}
	if res.Code == nodeproto.OTPUnavailable {
		return ErrPanelUnavailable
	}
	n, err := o.Store.Hit(ctx, failKey, time.Duration(o.Settings.Lockout))
	if err != nil {
		return err
	}
	if n >= o.Settings.Attempts {
		if err := o.Store.Lock(ctx, lockKey, time.Duration(o.Settings.Lockout)); err != nil {
			return err
		}
	}
	return ErrInvalidCode
}

// reportRevoke relays a local sign-out to the panel (managed nodes).
func (s *Service) reportRevoke(sess *Session) {
	p := currentPanel()
	if p == nil || sess == nil {
		return
	}
	if err := p.ReportRevoke(nodeproto.AuthRevoke{SID: sess.SID, Email: sess.Email, Expires: sess.Expires}); err != nil {
		s.log.Warn("access: could not report the sign-out to the panel; other nodes accept the session until it expires or the panel learns of it", "err", err)
	}
}

// ApplyRemoteRevoke applies a revocation the panel relayed from another
// node of the org.
func (s *Service) ApplyRemoteRevoke(ctx context.Context, r nodeproto.AuthRevoke) error {
	if r.SID != "" {
		changed, err := s.store.RevokeRemote(ctx, r.SID, r.Email, r.Expires)
		if changed {
			s.log.Info("access: session revoked on another node", "email", r.Email)
		}
		return err
	}
	if !r.Before.IsZero() && r.Email != "" {
		if s.hasRealms() {
			return errors.New("auth_revoke by email applies to every realm on the node and is refused; use realms.<name>.access.revoked_before")
		}
		_, err := s.store.RevokeBefore(ctx, r.Email, r.Before)
		return err
	}
	return errors.New("auth_revoke needs sid, or email and before")
}

func (s *Service) hasRealms() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.st != nil && s.st.realms != nil
}

// revokedByConfig applies access.revoked_before and access.revoked_sessions
// (delivered in panel snapshots) of the governing access block to a session.
func revokedByConfig(a *config.Access, sid, email string, issued time.Time) bool {
	if a == nil {
		return false
	}
	for _, r := range a.RevokedSessions {
		if r == sid {
			return true
		}
	}
	for _, who := range []string{email, "*"} {
		if t, ok := a.RevokedBefore[who]; ok && !t.IsZero() && issued.Before(t.Time) {
			return true
		}
	}
	return false
}

// acceptSession turns verified cookie claims into a live session: the local
// row if this node knows the session, else (org-wide keys: another node
// created it) a freshly imported one. Revocations from the config apply
// either way. a is the access block governing the request (the node's, or
// the app's realm's).
func (s *Service) acceptSession(ctx context.Context, a *config.Access, c *PortalClaims, ip, ua string) *Session {
	sess, err := s.store.GetSession(ctx, c.SID)
	if err != nil {
		return nil
	}
	if sess == nil {
		known, err := s.store.sessionKnown(ctx, c.SID)
		orgKeys := a != nil && a.SessionKey != "" && a.JWTKey != ""
		if err != nil || known || !orgKeys || !c.Expires.After(time.Now()) {
			return nil // revoked or expired here, or keys are node-local
		}
		issued := c.Issued
		if issued.IsZero() {
			issued = time.Now()
		}
		if sess, err = s.store.importSession(ctx, Session{SID: c.SID, Email: c.Email, Created: issued, Expires: c.Expires, IP: ip, UserAgent: ua}); err != nil || sess == nil {
			return nil
		}
	}
	if sess.Email != c.Email || revokedByConfig(a, sess.SID, sess.Email, sess.Created) {
		return nil
	}
	sess.Method, sess.Attrs = c.Method, c.Attrs
	return sess
}

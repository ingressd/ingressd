// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net/netip"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"github.com/ingressd/ingressd/pkg/access"
	"github.com/ingressd/ingressd/pkg/access/idp"
	"github.com/ingressd/ingressd/pkg/config"
	"github.com/ingressd/ingressd/pkg/nodeproto"
)

// AuthCodeTTL is how long a callback code stays redeemable.
const AuthCodeTTL = 60 * time.Second

// Service is the control-plane side of Access. One Service lives for the
// whole `ingressd serve` process; Update swaps in each applied config.
type Service struct {
	store *Store
	geo   *GeoIP
	log   *slog.Logger

	mu sync.RWMutex
	st *state

	ctx    context.Context // for background email delivery
	cancel context.CancelFunc
	wg     sync.WaitGroup

	gcMu   sync.Mutex
	lastGC time.Time
}

// state is everything derived from one config.
type state struct {
	cfg    *config.Config
	eng    *Engine
	keys   *Keys
	sender Sender
	otp    *OTP
	// providers are the sign-in methods of this node's own portal
	// (access.providers), with secrets resolved.
	providers map[string]*idp.Provider
	// realms is non-nil when the config has realms: each realm's access
	// settings and keys (realms without access settings are absent). The
	// node-wide fields above are then unused.
	realms map[string]*realmState
}

// realmState is what one realm signs in with.
type realmState struct {
	access *config.Access
	keys   *Keys
}

// appAccess returns the keys and access settings that govern an app.
func (st *state) appAccess(app string) (*Keys, *config.Access, bool) {
	if st.realms != nil {
		r, ok := st.realms[st.cfg.Apps[app].Realm]
		if !ok {
			return nil, nil, false
		}
		return r.keys, r.access, true
	}
	return st.keys, st.cfg.Access, st.keys != nil
}

// SecretSource is what Update needs from the secrets store.
type SecretSource interface {
	Resolver
	Getter
}

// DBPath is the Access database under the state directory.
func DBPath(stateDir string) string { return filepath.Join(stateDir, "access.db") }

// Open opens the Access database under stateDir.
func Open(stateDir string, log *slog.Logger) (*Service, error) {
	st, err := OpenStore(DBPath(stateDir))
	if err != nil {
		return nil, err
	}
	if log == nil {
		log = slog.Default()
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Service{store: st, geo: NewGeoIP(stateDir), log: log, ctx: ctx, cancel: cancel}, nil
}

// Close waits for queued emails (briefly) and closes the database.
func (s *Service) Close() error {
	done := make(chan struct{})
	go func() { s.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
	}
	s.cancel()
	return s.store.Close()
}

// Store exposes the database (sessions CLI, tests).
func (s *Service) Store() *Store { return s.store }

// Update installs a new (validated) config.
func (s *Service) Update(cfg *config.Config, sec SecretSource) error {
	ns := &state{cfg: cfg, eng: NewEngine(cfg)}
	if len(cfg.Realms) > 0 {
		ns.realms = map[string]*realmState{}
		for _, name := range slices.Sorted(maps.Keys(cfg.Realms)) {
			a := cfg.Realms[name].Access
			if a == nil {
				continue
			}
			keys, err := LoadRealmKeys(cfg, sec, name)
			if err != nil {
				return err
			}
			ns.realms[name] = &realmState{access: a, keys: keys}
		}
	} else if Needed(cfg) {
		keys, err := LoadConfigKeys(cfg, sec)
		if err != nil {
			return err
		}
		ns.keys = keys
		ns.otp = &OTP{Store: s.store, Settings: cfg.Access.OTP}
		if cfg.Email.Provider != "" && !usesPanel(cfg) {
			if ns.sender, err = NewSender(cfg, sec); err != nil {
				return err
			}
		}
		if ns.providers, err = buildProviders(cfg, sec); err != nil {
			return err
		}
	}
	s.mu.Lock()
	s.st = ns
	s.mu.Unlock()
	return nil
}

// current returns the installed state when anything signs in: the node
// (see state) or any realm.
func (s *Service) current() (*state, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.st == nil || (s.st.keys == nil && len(s.st.realms) == 0) {
		return nil, errors.New("access is not configured")
	}
	return s.st, nil
}

func (s *Service) state() (*state, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.st == nil || s.st.keys == nil {
		return nil, errors.New("access is not configured")
	}
	return s.st, nil
}

// userIdentity is a signed-in user's identity from a client address.
func (s *Service) userIdentity(sess *Session, ip string) Identity {
	id := access.UserIdentity(sess.Email, sess.Method, sess.Attrs)
	net := s.identity("", ip)
	id.IP, id.Country = net.IP, net.Country
	return id
}

// identity builds the network part of an identity for a client address.
func (s *Service) identity(email, ip string) Identity {
	id := Identity{Email: email}
	if a, err := netip.ParseAddr(ip); err == nil {
		id.IP = a.Unmap()
		id.Country = s.geo.Country(id.IP)
	}
	return id
}

// RequestCode handles "email me a code". Rate limits apply to every
// request; a code is only generated and sent when eligible is true, but the
// result (and timing) is the same either way. appLabel names what the user
// is signing in to, for the email.
func (s *Service) RequestCode(ctx context.Context, email, ip, appLabel string, eligible bool) error {
	st, err := s.state()
	if err != nil {
		return err
	}
	return s.requestCode(ctx, st, codeRequest{email: email, ip: ip, label: appLabel, policy: appLabel, host: st.cfg.Access.PortalHost}, eligible)
}

// codeRequest is one "email me a code" request.
type codeRequest struct {
	email, ip string
	label     string // what the user signs in to (email text)
	policy    string // app or policy name (panel logs)
	host      string // portal or play host the user is on
}

func (s *Service) requestCode(ctx context.Context, st *state, req codeRequest, eligible bool) error {
	email, ip, appLabel := req.email, req.ip, req.label
	if usesPanel(st.cfg) && currentPanel() == nil {
		return ErrPanelUnavailable // same for every email: reveals nothing
	}
	send, err := st.otp.Allow(ctx, email, ip)
	if err != nil || !send {
		return err
	}
	if !eligible {
		_ = otpHash("000000", make([]byte, 16)) // equalise timing with Issue
		s.log.Info("access: code not sent, email cannot satisfy policy", "email", email, "ip", ip)
		return nil
	}
	if usesPanel(st.cfg) {
		return s.panelStart(st, nodeproto.AuthOTPStart{Email: email, Policy: req.policy, Label: appLabel, ClientIP: ip, Host: req.host})
	}
	code, err := st.otp.Issue(ctx, email, ip)
	if err != nil {
		return err
	}
	if st.sender == nil {
		return errors.New("email is not configured")
	}
	msg, err := renderCodeEmail(email, codeEmail{
		Brand: st.cfg.Access.Branding, App: appLabel, Code: code, IP: ip,
		Location: s.identity("", ip).Country,
		TTL:      fmtDuration(time.Duration(st.cfg.Access.OTP.TTL)),
	})
	if err != nil {
		return err
	}
	// Deliver in the background so response time does not reveal whether
	// an email was sent.
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		if err := retrySend(s.ctx, st.sender, msg, 3); err != nil {
			s.log.Error("access: sending sign-in code failed", "email", email, "err", err)
		}
	}()
	return nil
}

// VerifyCode checks an emailed code.
func (s *Service) VerifyCode(ctx context.Context, email, code string) error {
	st, err := s.state()
	if err != nil {
		return err
	}
	return s.verifyCode(ctx, st, email, code, "")
}

func (s *Service) verifyCode(ctx context.Context, st *state, email, code, ip string) error {
	if usesPanel(st.cfg) {
		return s.panelVerify(ctx, st, email, code, ip)
	}
	return st.otp.Verify(ctx, email, code)
}

// Evaluate runs a named policy list for an email from a client IP.
func (s *Service) Evaluate(policies []string, email, ip string) (Decision, error) {
	st, err := s.state()
	if err != nil {
		return Decision{}, err
	}
	return st.eng.Evaluate(policies, s.identity(email, ip)), nil
}

func (s *Service) maybeGC() {
	s.gcMu.Lock()
	defer s.gcMu.Unlock()
	if time.Since(s.lastGC) < time.Minute {
		return
	}
	s.lastGC = time.Now()
	if err := s.store.GC(context.Background()); err != nil {
		s.log.Warn("access: gc failed", "err", err)
	}
}

func fmtDuration(d time.Duration) string {
	switch {
	case d%time.Hour == 0:
		return plural(int(d/time.Hour), "hour")
	case d%time.Minute == 0:
		return plural(int(d/time.Minute), "minute")
	}
	return d.String()
}

func plural(n int, unit string) string {
	if n == 1 {
		return fmt.Sprintf("1 %s", unit)
	}
	return fmt.Sprintf("%d %ss", n, unit)
}

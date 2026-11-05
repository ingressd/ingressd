// SPDX-License-Identifier: Apache-2.0

package edgeauth

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/caddyserver/caddy/v2"
	"go.uber.org/zap"
)

// --- sign-in callback ---

type exchangeRequest struct {
	Code string `json:"code"`
	App  string `json:"app"`
	Host string `json:"host"`
	IP   string `json:"ip,omitempty"` // the control plane evaluates the app's policies for it
	// Nonce is the browser's sign-in nonce cookie (see loginURL); the
	// control plane checks it against the code.
	Nonce string `json:"nonce,omitempty"`
}

type exchangeResponse struct {
	Token   string `json:"token"`
	Expires int64  `json:"expires"`
	RD      string `json:"rd"`
}

// callback redeems the one-time code from the portal for a session cookie
// and sends the browser back to where it started.
func (h *Handler) callback(w http.ResponseWriter, r *http.Request) error {
	code := r.URL.Query().Get("code")
	if code == "" || len(code) > 4096 || h.client == nil { // sealed codes carry the return URL
		return h.deny(w, http.StatusBadRequest, "Invalid sign-in link.")
	}
	host := r.Host
	if hh, _, err := net.SplitHostPort(host); err == nil {
		host = hh
	}
	var ip string
	if a := clientIP(r); a.IsValid() {
		ip = a.String()
	}
	var nonce string
	if c, err := r.Cookie(h.flowCookie); err == nil {
		nonce = c.Value
	}
	body, _ := json.Marshal(exchangeRequest{Code: code, App: h.App, Host: host, IP: ip, Nonce: nonce})
	req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, "http://"+h.ControlHost+"/v1/exchange", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := h.client.Do(req)
	if err != nil {
		h.logger.Error("code exchange failed", zap.Error(err))
		return h.deny(w, http.StatusBadGateway, "Sign-in is temporarily unavailable. Please try again.")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		reason := strings.TrimSpace(string(msg))
		h.logger.Info("code exchange rejected", zap.Int("status", resp.StatusCode), zap.String("reason", reason))
		if who, ok := strings.CutPrefix(reason, "not allowed: "); ok && resp.StatusCode == http.StatusForbidden {
			return h.deny(w, http.StatusForbidden, "Access denied: "+strings.TrimSuffix(who, " may not access this app")+" is not allowed to access this app.")
		}
		return h.deny(w, http.StatusForbidden, "This sign-in link is invalid or has expired. Please try again.")
	}
	var er exchangeResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&er); err != nil {
		return h.deny(w, http.StatusBadGateway, "Sign-in failed.")
	}
	rd, err := url.Parse(er.RD)
	if err != nil || rd.Scheme != "https" || !strings.EqualFold(rd.Hostname(), host) {
		return h.deny(w, http.StatusForbidden, "Invalid return address.")
	}
	http.SetCookie(w, &http.Cookie{
		Name: h.cookieName, Value: er.Token, Path: "/",
		Expires: time.Unix(er.Expires, 0), HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode,
	})
	http.SetCookie(w, &http.Cookie{Name: h.flowCookie, Value: "", Path: flowCookiePath, MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, rd.RequestURI(), http.StatusFound)
	return nil
}

// --- identity assertion ---

// assertion returns a compact ES256 JWT for the origin (aud = Audience, else App),
// verifiable against the portal's /.well-known/jwks.json.
func (h *Handler) assertion(sub, email, sid string, sessionExp time.Time) string {
	now := time.Now()
	exp := now.Add(5 * time.Minute)
	if !sessionExp.IsZero() && sessionExp.Before(exp) {
		exp = sessionExp
	}
	aud := h.App
	if h.Audience != "" {
		aud = h.Audience
	}
	claims := map[string]any{
		"iss": strings.TrimSuffix(h.PortalURL, "/"),
		"aud": aud,
		"sub": sub,
		"iat": now.Unix(),
		"exp": exp.Unix(),
	}
	if email != "" {
		claims["email"] = email
	}
	if sid != "" {
		claims["sid"] = sid
	}
	hdr, _ := json.Marshal(map[string]string{"alg": "ES256", "typ": "JWT", "kid": h.kid})
	cl, _ := json.Marshal(claims)
	input := b64(hdr) + "." + b64(cl)
	sig, err := signES256(h.jwtKey, input)
	if err != nil {
		return ""
	}
	return input + "." + b64(sig)
}

func signES256(k *ecdsa.PrivateKey, input string) ([]byte, error) {
	sum := sha256.Sum256([]byte(input))
	r, s, err := ecdsa.Sign(rand.Reader, k, sum[:])
	if err != nil {
		return nil, err
	}
	out := make([]byte, 64)
	r.FillBytes(out[:32])
	s.FillBytes(out[32:])
	return out, nil
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// --- revocation polling ---

// pollers shares one poller per control socket between all edge_auth
// instances (one per protected app, recreated on each config load).
var pollers = caddy.NewUsagePool()

type poller struct {
	client   *http.Client
	host     string
	path     string // the revocation list, with the realm if any
	interval time.Duration
	logger   *zap.Logger

	set    atomic.Pointer[map[string]struct{}]
	before atomic.Pointer[map[string]int64] // email or "*" → unix time
	etag   string
	cancel context.CancelFunc
	once   sync.Once
	// started is when the poller (in practice: the edge process) started
	// and synced whether a revocation list has been fetched since.
	started time.Time
	synced  atomic.Bool
}

func startPoller(client *http.Client, host, path string, interval time.Duration, logger *zap.Logger) *poller {
	ctx, cancel := context.WithCancel(context.Background())
	p := &poller{client: client, host: host, path: path, interval: interval, logger: logger, cancel: cancel, started: time.Now().Truncate(time.Second)}
	empty := map[string]struct{}{}
	p.set.Store(&empty)
	// Fetch once before serving; failures are retried in the background,
	// and until one succeeds cookies issued before the start are refused
	// (see unverified).
	fctx, fcancel := context.WithTimeout(ctx, time.Second)
	if err := p.fetch(fctx); err != nil {
		logger.Warn("fetching session revocations failed; sessions from before this start need a new sign-in until it succeeds", zap.Error(err))
	}
	fcancel()
	go p.run(ctx)
	return p
}

// unverified reports whether a cookie issued at iat cannot be checked yet:
// no revocation list has been fetched since the edge started, so it may
// have been revoked while the edge was down. Such cookies are treated as
// absent (the browser goes back through the portal, which re-issues one if
// the portal session is still valid). Cookies minted after the start came
// through the control plane, which knew the current revocations.
func (p *poller) unverified(iat time.Time) bool {
	return !p.synced.Load() && iat.Before(p.started)
}

func (p *poller) revoked(sid string) bool {
	_, ok := (*p.set.Load())[sid]
	return ok
}

// revokedBefore reports whether a cookie issued at iat for email falls
// under a "revoked before" cut-off (access.revoked_before, org-wide
// sign-outs relayed by the hosted panel).
func (p *poller) revokedBefore(email string, iat time.Time) bool {
	m := p.before.Load()
	if m == nil || len(*m) == 0 {
		return false
	}
	for _, k := range []string{email, "*"} {
		if t, ok := (*m)[k]; ok && iat.Unix() < t {
			return true
		}
	}
	return false
}

func (p *poller) run(ctx context.Context) {
	t := time.NewTicker(p.interval)
	defer t.Stop()
	failing := false
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		fctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		err := p.fetch(fctx)
		cancel()
		if err != nil && !failing && ctx.Err() == nil {
			p.logger.Warn("fetching session revocations failed; using the last known list", zap.Error(err))
		}
		failing = err != nil
	}
}

func (p *poller) fetch(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+p.host+p.path, nil)
	if err != nil {
		return err
	}
	if p.etag != "" {
		req.Header.Set("If-None-Match", p.etag)
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusNotModified:
		p.synced.Store(true)
		return nil
	case http.StatusOK:
	default:
		return fmt.Errorf("control plane returned %s", resp.Status)
	}
	var body struct {
		SIDs   []string         `json:"sids"`
		Before map[string]int64 `json:"before"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 16<<20)).Decode(&body); err != nil {
		return err
	}
	set := make(map[string]struct{}, len(body.SIDs))
	for _, s := range body.SIDs {
		set[s] = struct{}{}
	}
	p.set.Store(&set)
	before := body.Before
	p.before.Store(&before)
	p.etag = resp.Header.Get("ETag")
	p.synced.Store(true)
	return nil
}

// Destruct implements caddy.Destructor (called when the last user is gone).
func (p *poller) Destruct() error {
	p.once.Do(p.cancel)
	return nil
}

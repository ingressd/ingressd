// SPDX-License-Identifier: Apache-2.0

// Package edgechallenge implements http.handlers.edge_challenge: a
// JavaScript proof-of-work interstitial that keeps simple bots and request
// floods away from an app without any third-party service.
//
// A challenged visitor gets a page with a signed token. Their browser finds
// a nonce such that SHA-256(token + nonce) starts with `difficulty` zero
// bits and posts it to VerifyPath. The handler checks the work and sets an
// HMAC-signed clearance cookie bound to the client's network (IPv4 /24 or
// IPv6 /64), user agent and host, valid for TTL.
package edgechallenge

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(Challenge{})
}

const (
	ModeOff         = "off" // only rate rules trigger the challenge
	ModeSuspicious  = "suspicious"
	ModeAlways      = "always"
	ModeUnderAttack = "under_attack"

	// VerifyPath receives solved challenges on every challenged host.
	VerifyPath = "/.edge/challenge/verify"

	// tokenMaxAge bounds how long a challenge may take to solve.
	tokenMaxAge = 10 * time.Minute
)

// Challenge is the edge_challenge handler.
type Challenge struct {
	// Mode is off, suspicious, always or under_attack.
	Mode string `json:"mode,omitempty"`
	// Difficulty is the number of leading zero bits required (default 16).
	Difficulty int `json:"difficulty,omitempty"`
	// TTL is the clearance cookie lifetime (default 24h).
	TTL caddy.Duration `json:"ttl,omitempty"`
	// Key is the HMAC key, hex encoded (at least 16 bytes).
	Key string `json:"key"`
	// GoodBots lets crawlers verified by forward-confirmed reverse DNS
	// (Googlebot, Bingbot) through.
	GoodBots bool `json:"good_bots,omitempty"`
	// ExemptPaths are never challenged (path matcher syntax, e.g. /api/*).
	ExemptPaths []string `json:"exempt_paths,omitempty"`
	// RateRules challenge clients that exceed a request rate.
	RateRules []RateRule `json:"rate_rules,omitempty"`
	// SuspiciousRate is how many requests per minute one IP may make
	// without clearance before it counts as suspicious (default 60).
	SuspiciousRate int `json:"suspicious_rate,omitempty"`
	// DecisionHeader is a request header that, when non-empty, marks the
	// request as suspicious (e.g. a CrowdSec remediation set upstream).
	// Default X-Crowdsec-Decision.
	DecisionHeader string `json:"decision_header,omitempty"`
	// CookieName defaults to __edge_clearance.
	CookieName string `json:"cookie_name,omitempty"`

	key      []byte
	exempt   caddyhttp.MatchPath
	rules    []compiledRule
	resolver resolver
	now      func() time.Time
	logger   *zap.Logger
}

// RateRule challenges clients exceeding Requests per Window on Path.
type RateRule struct {
	Path     string         `json:"path"`
	Requests int            `json:"requests"`
	Window   caddy.Duration `json:"window"`
	// Key is ip, ip_path, header:<name> or email.
	Key string `json:"key,omitempty"`
}

type compiledRule struct {
	RateRule
	match caddyhttp.MatchPath
	id    string
}

func (Challenge) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.edge_challenge",
		New: func() caddy.Module { return new(Challenge) },
	}
}

func (c *Challenge) Provision(ctx caddy.Context) error {
	c.logger = ctx.Logger()
	if c.Mode == "" {
		c.Mode = ModeSuspicious
	}
	if c.Difficulty == 0 {
		c.Difficulty = 16
	}
	if c.TTL == 0 {
		c.TTL = caddy.Duration(24 * time.Hour)
	}
	if c.SuspiciousRate == 0 {
		c.SuspiciousRate = 60
	}
	if c.DecisionHeader == "" {
		c.DecisionHeader = "X-Crowdsec-Decision"
	}
	if c.CookieName == "" {
		c.CookieName = "__edge_clearance"
	}
	k, err := hex.DecodeString(c.Key)
	if err != nil || len(k) < 16 {
		return errors.New("edge_challenge: key must be at least 16 bytes, hex encoded")
	}
	c.key = k
	c.exempt = caddyhttp.MatchPath(c.ExemptPaths)
	if err := c.exempt.Provision(ctx); err != nil {
		return err
	}
	c.rules = nil
	for _, r := range c.RateRules {
		m := caddyhttp.MatchPath{r.Path}
		if err := m.Provision(ctx); err != nil {
			return err
		}
		// Counters persist across config reloads, keyed by the rule.
		id := fmt.Sprintf("%s|%d|%d|%s", r.Path, r.Requests, r.Window, r.Key)
		c.rules = append(c.rules, compiledRule{RateRule: r, match: m, id: id})
	}
	if c.resolver == nil {
		c.resolver = net.DefaultResolver
	}
	if c.now == nil {
		c.now = time.Now
	}
	return nil
}

func (c *Challenge) Validate() error {
	switch c.Mode {
	case ModeOff, ModeSuspicious, ModeAlways, ModeUnderAttack:
	default:
		return fmt.Errorf("edge_challenge: unknown mode %q", c.Mode)
	}
	if c.Difficulty < 1 || c.Difficulty > 32 {
		return fmt.Errorf("edge_challenge: difficulty must be 1-32, got %d", c.Difficulty)
	}
	for _, r := range c.RateRules {
		if r.Requests < 1 || r.Window <= 0 {
			return fmt.Errorf("edge_challenge: rate rule %s needs requests and window", r.Path)
		}
	}
	return nil
}

func (c *Challenge) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	if r.URL.Path == VerifyPath {
		return c.verify(w, r)
	}
	if len(c.ExemptPaths) > 0 && c.exempt.Match(r) {
		return next.ServeHTTP(w, r)
	}
	ip := clientIP(r)
	cleared := c.cleared(r, ip)
	if !cleared && c.GoodBots && c.isGoodBot(r.Context(), ip, r.UserAgent()) {
		return next.ServeHTTP(w, r)
	}
	// Rate rules count every request, cleared or not: one solved challenge
	// must not switch them off for the cookie's lifetime. A cleared client
	// over a rule's rate is challenged again (the rule's action).
	rateHit := c.countRates(r, ip)
	reason := ""
	switch {
	case cleared:
	case c.Mode == ModeAlways || c.Mode == ModeUnderAttack:
		reason = c.Mode
	case c.Mode == ModeSuspicious:
		reason = c.suspicious(r, ip)
	}
	if reason == "" && rateHit != "" {
		reason = rateHit
	}
	if reason == "" {
		return next.ServeHTTP(w, r)
	}
	c.logger.Debug("challenging request", zap.String("ip", ip.String()), zap.String("reason", reason))
	return c.serveChallenge(w, r, ip)
}

// suspicious returns why a request looks automated, or "".
func (c *Challenge) suspicious(r *http.Request, ip netip.Addr) string {
	switch {
	case r.UserAgent() == "":
		return "no user agent"
	case r.Header.Get("Accept") == "":
		return "no accept header"
	case r.Header.Get("Accept-Language") == "":
		return "no accept-language header"
	case r.Header.Get(c.DecisionHeader) != "":
		return "crowdsec decision"
	}
	if counters.hit("susp|"+netKey(ip), c.SuspiciousRate, time.Minute, c.now()) {
		return "request rate"
	}
	return ""
}

// countRates records the request against the rate rules and returns the
// first one exceeded, or "".
func (c *Challenge) countRates(r *http.Request, ip netip.Addr) string {
	hit := ""
	for _, rule := range c.rules {
		if !rule.match.Match(r) {
			continue
		}
		var k string
		switch {
		case rule.Key == "ip_path":
			k = netKey(ip) + " " + r.URL.Path
		case rule.Key == "email":
			if k = r.Header.Get("X-Edge-User-Email"); k == "" {
				continue
			}
		case strings.HasPrefix(rule.Key, "header:"):
			k = r.Header.Get(strings.TrimPrefix(rule.Key, "header:"))
		default:
			k = netKey(ip)
		}
		if counters.hit("rule|"+rule.id+"|"+k, rule.Requests, time.Duration(rule.Window), c.now()) && hit == "" {
			hit = "rate rule " + rule.Path
		}
	}
	return hit
}

// clientIP is the client address Caddy determined (honouring trusted proxies).
func clientIP(r *http.Request) netip.Addr {
	s, _ := caddyhttp.GetVar(r.Context(), caddyhttp.ClientIPVarKey).(string)
	if s == "" {
		s, _, _ = net.SplitHostPort(r.RemoteAddr)
	}
	a, _ := netip.ParseAddr(s)
	return a.Unmap()
}

// netKey is the unit per-client counters are kept for: the address for
// IPv4 and the /64 for IPv6, since one subscriber usually holds a whole
// /64 and could otherwise rotate addresses to reset its counters.
func netKey(ip netip.Addr) string {
	if ip.Is6() {
		pfx, _ := ip.Prefix(64)
		return pfx.String()
	}
	return ip.String()
}

// binding ties tokens and cookies to the client's network, user agent and host.
func binding(r *http.Request, ip netip.Addr) string {
	bits := 24
	if ip.Is6() {
		bits = 64
	}
	pfx, _ := ip.Prefix(bits)
	ua := sha256.Sum256([]byte(r.UserAgent()))
	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return pfx.String() + "|" + hex.EncodeToString(ua[:8]) + "|" + strings.ToLower(host)
}

var b64 = base64.RawURLEncoding

func (c *Challenge) mac(parts ...string) string {
	m := hmac.New(sha256.New, c.key)
	m.Write([]byte(strings.Join(parts, "|")))
	return b64.EncodeToString(m.Sum(nil)[:18])
}

// clearance returns a cookie value valid until exp.
func (c *Challenge) clearance(bind string, exp time.Time) string {
	e := strconv.FormatInt(exp.Unix(), 10)
	return e + "." + c.mac("clear", e, bind)
}

func (c *Challenge) cleared(r *http.Request, ip netip.Addr) bool {
	ck, err := r.Cookie(c.CookieName)
	if err != nil {
		return false
	}
	e, sig, ok := strings.Cut(ck.Value, ".")
	if !ok {
		return false
	}
	exp, err := strconv.ParseInt(e, 10, 64)
	if err != nil || c.now().Unix() >= exp {
		return false
	}
	return hmac.Equal([]byte(sig), []byte(c.mac("clear", e, binding(r, ip))))
}

// newToken issues a challenge: <unix>.<random>.<difficulty>.<mac>.
func (c *Challenge) newToken(bind string) string {
	var rnd [12]byte
	_, _ = randRead(rnd[:])
	p := fmt.Sprintf("%d.%s.%d", c.now().Unix(), b64.EncodeToString(rnd[:]), c.Difficulty)
	return p + "." + c.mac("chal", p, bind)
}

// checkToken verifies a token's signature and age, returning its difficulty.
func (c *Challenge) checkToken(tok, bind string) (int, error) {
	parts := strings.Split(tok, ".")
	if len(parts) != 4 {
		return 0, errors.New("malformed token")
	}
	p := strings.Join(parts[:3], ".")
	if !hmac.Equal([]byte(parts[3]), []byte(c.mac("chal", p, bind))) {
		return 0, errors.New("bad signature")
	}
	ts, err1 := strconv.ParseInt(parts[0], 10, 64)
	d, err2 := strconv.Atoi(parts[2])
	if err1 != nil || err2 != nil {
		return 0, errors.New("malformed token")
	}
	age := c.now().Sub(time.Unix(ts, 0))
	if age > tokenMaxAge || age < -time.Minute {
		return 0, errors.New("token expired")
	}
	return d, nil
}

// LeadingZeroBits counts the leading zero bits of b.
func LeadingZeroBits(b []byte) int {
	n := 0
	for _, x := range b {
		if x == 0 {
			n += 8
			continue
		}
		for x&0x80 == 0 {
			n++
			x <<= 1
		}
		break
	}
	return n
}

// Solve finds a nonce for a token (used by tests and tooling).
func Solve(token string, difficulty int) string {
	for i := 0; ; i++ {
		n := strconv.Itoa(i)
		h := sha256.Sum256([]byte(token + n))
		if LeadingZeroBits(h[:]) >= difficulty {
			return n
		}
	}
}

func (c *Challenge) verify(w http.ResponseWriter, r *http.Request) error {
	if r.Method != http.MethodPost {
		return caddyhttp.Error(http.StatusMethodNotAllowed, nil)
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	if err := r.ParseForm(); err != nil {
		return caddyhttp.Error(http.StatusBadRequest, err)
	}
	ip := clientIP(r)
	bind := binding(r, ip)
	tok, nonce := r.PostForm.Get("token"), r.PostForm.Get("nonce")
	d, err := c.checkToken(tok, bind)
	if err == nil && d < c.Difficulty {
		err = errors.New("difficulty too low")
	}
	if err == nil && (nonce == "" || len(nonce) > 20 || strings.Trim(nonce, "0123456789") != "") {
		err = errors.New("bad nonce")
	}
	if err == nil {
		h := sha256.Sum256([]byte(tok + nonce))
		if LeadingZeroBits(h[:]) < d {
			err = errors.New("insufficient work")
		}
	}
	if err != nil {
		c.logger.Debug("challenge verification failed", zap.String("ip", ip.String()), zap.Error(err))
		// Show a fresh challenge.
		return c.serveChallenge(w, r, ip)
	}
	exp := c.now().Add(time.Duration(c.TTL))
	http.SetCookie(w, &http.Cookie{
		Name:     c.CookieName,
		Value:    c.clearance(bind, exp),
		Path:     "/",
		Expires:  exp,
		MaxAge:   int(time.Duration(c.TTL).Seconds()),
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
	})
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, safeReturn(r.PostForm.Get("return")), http.StatusSeeOther)
	return nil
}

// safeReturn only allows local paths, so the form cannot be used as an
// open redirect.
func safeReturn(s string) string {
	if !strings.HasPrefix(s, "/") || strings.HasPrefix(s, "//") || strings.HasPrefix(s, "/\\") || strings.ContainsAny(s, "\r\n") {
		return "/"
	}
	return s
}

func (c *Challenge) serveChallenge(w http.ResponseWriter, r *http.Request, ip netip.Addr) error {
	ret := r.URL.RequestURI()
	if r.URL.Path == VerifyPath {
		ret = safeReturn(r.PostForm.Get("return"))
	}
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Robots-Tag", "noindex")
	h.Set("X-Edge-Challenge", c.Mode)
	h.Set("Content-Security-Policy", "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'")
	w.WriteHeader(http.StatusForbidden)
	return pageTmpl.Execute(w, pageData{
		Token:       c.newToken(binding(r, ip)),
		Difficulty:  c.Difficulty,
		Return:      ret,
		Action:      VerifyPath,
		UnderAttack: c.Mode == ModeUnderAttack,
	})
}

// resolver is the subset of *net.Resolver used for good-bot verification.
type resolver interface {
	LookupAddr(ctx context.Context, addr string) ([]string, error)
	LookupHost(ctx context.Context, host string) ([]string, error)
}

var (
	_ caddy.Provisioner           = (*Challenge)(nil)
	_ caddy.Validator             = (*Challenge)(nil)
	_ caddyhttp.MiddlewareHandler = (*Challenge)(nil)
)

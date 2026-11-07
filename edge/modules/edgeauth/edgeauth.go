// SPDX-License-Identifier: Apache-2.0

// Package edgeauth is the edge_auth Caddy handler (PLAN §7.2). It sits in
// front of every protected app and:
//
//   - verifies the per-app session cookie offline (PASETO v4.local),
//   - redirects browsers without a valid cookie to the login portal,
//   - completes sign-in at /.ingressd/callback by exchanging a one-time code
//     with the control plane over its unix socket,
//   - clears the cookie at /.ingressd/logout,
//   - authenticates machines with Edge-Client-Id / Edge-Client-Secret,
//   - evaluates bypass, service_auth and network-only deny policies,
//   - strips spoofable identity headers and injects X-Edge-User-Email and a
//     signed Edge-Jwt-Assertion (ES256) for origins,
//   - polls the control socket for revoked sessions, so revocation takes
//     effect within seconds without a config reload.
//
// Its configuration is rendered by internal/auth.BuildEdgeConfig; the key
// derivation and token formats here must match internal/auth.
package edgeauth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"html"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"path"
	"slices"
	"strings"
	"time"

	"aidanwoods.dev/go-paseto"
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/oschwald/maxminddb-golang"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(Handler{})
}

// Handler is the http.handlers.edge_auth module.
type Handler struct {
	// App is the app's name; it scopes the cookie and its key.
	App string `json:"app"`
	// Realm (shared nodes) also scopes the cookie key, and selects the
	// realm's revocation list.
	Realm string `json:"realm,omitempty"`
	// Audience is the identity assertion's aud ("" means App).
	Audience string `json:"audience,omitempty"`
	// PortalURL is the login portal, e.g. https://auth.example.com.
	PortalURL string `json:"portal_url"`
	// SessionKey is the base64 master key the cookie and service-token
	// keys are derived from. JWTKey is a base64 PKCS#8 P-256 private key.
	SessionKey string `json:"session_key"`
	JWTKey     string `json:"jwt_key"`
	// ControlSocket is the control plane's unix socket and ControlHost the
	// Host used for requests on it.
	ControlSocket string `json:"control_socket,omitempty"`
	ControlHost   string `json:"control_host,omitempty"`
	// Policies by name; Default is the app's list and Paths override it.
	Policies      map[string]Policy `json:"policies,omitempty"`
	Default       []string          `json:"default,omitempty"`
	Paths         []PathRule        `json:"paths,omitempty"`
	ServiceTokens []ServiceToken    `json:"service_tokens,omitempty"`
	// PollInterval is how often revocations are fetched (default 2s).
	PollInterval caddy.Duration `json:"poll_interval,omitempty"`
	// CountryDB is a MaxMind country database for country selectors;
	// without one they never match (as in the control plane).
	CountryDB string `json:"country_db,omitempty"`

	cookieName string
	flowCookie string
	cookieKey  paseto.V4SymmetricKey
	hmacKey    []byte
	jwtKey     *ecdsa.PrivateKey
	kid        string
	compiled   map[string]*compiledPolicy
	tokens     map[string]ServiceToken
	// headerTokens are the header tokens by canonical header name.
	headerTokens map[string][]ServiceToken
	client       *http.Client
	poller       *poller
	pollerKey    string
	geo          *geoDB
	logger       *zap.Logger
}

// Policy mirrors internal/auth.EdgePolicy. Every policy is evaluated on
// every request; Offline ones (no email selectors) also for anonymous
// requests, the others only once the user has a session.
type Policy struct {
	Action  string     `json:"action"`
	Version string     `json:"version"`
	Offline bool       `json:"offline,omitempty"`
	Include []Selector `json:"include,omitempty"`
	Require []Selector `json:"require,omitempty"`
	Exclude []Selector `json:"exclude,omitempty"`
}

// Selector mirrors internal/auth.EdgeSelector: its fields are alternatives
// (internal/auth sets one kind per selector; groups become emails and
// email domains).
type Selector struct {
	Everyone     bool     `json:"everyone,omitempty"`
	Never        bool     `json:"never,omitempty"`
	Email        []string `json:"email,omitempty"`
	EmailDomain  []string `json:"email_domain,omitempty"`
	IP           []string `json:"ip,omitempty"`
	Country      []string `json:"country,omitempty"`
	ServiceToken []string `json:"service_token,omitempty"`
	// Attr matches the sign-in facts in the app cookie ("<kind>:<value>",
	// pkg/config.Attr), e.g. "discord_guild:123" or "login_method:steam".
	Attr []string `json:"attr,omitempty"`
}

type PathRule struct {
	Match    string   `json:"match"`
	Policies []string `json:"policies"`
}

type ServiceToken struct {
	Name     string `json:"name"`
	ClientID string `json:"client_id,omitempty"`
	// Header (header tokens): the request header carrying the secret
	// alone. It is removed from every request.
	Header   string `json:"header,omitempty"`
	Verifier string `json:"verifier"`
	Expires  int64  `json:"expires,omitempty"`
}

func (Handler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.edge_auth",
		New: func() caddy.Module { return new(Handler) },
	}
}

// Headers that only edge_auth may set. Incoming copies are always removed.
var identityHeaders = []string{"X-Edge-User", "X-Edge-User-Email", "Edge-Jwt-Assertion", "X-Edge-Service-Token", "X-Edge-Session-Id"}

const (
	callbackPath = "/.ingressd/callback"
	logoutPath   = "/.ingressd/logout"
	// Sign-ins started before an upgrade still come back to the old paths.
	legacyCallbackPath = "/.homeedge/callback" // legacy homeedge name, remove after 2027-01
	legacyLogoutPath   = "/.homeedge/logout"   // legacy homeedge name, remove after 2027-01
)

func (h *Handler) Provision(ctx caddy.Context) error {
	h.logger = ctx.Logger()
	if h.App == "" || h.PortalURL == "" {
		return errors.New("app and portal_url are required")
	}
	master, err := base64.StdEncoding.DecodeString(h.SessionKey)
	if err != nil || len(master) < 32 {
		return errors.New("session_key must be at least 32 bytes, base64")
	}
	ck, err := paseto.V4SymmetricKeyFromBytes(derive(master, appCookieInfo(h.Realm, h.App)))
	if err != nil {
		return err
	}
	h.cookieKey = ck
	h.hmacKey = derive(master, kdfPrefix+"edge_auth/service-token")
	h.cookieName = "__edge_" + h.App
	h.flowCookie = "__edge_signin_" + h.App

	der, err := base64.StdEncoding.DecodeString(h.JWTKey)
	if err != nil {
		return fmt.Errorf("jwt_key: %w", err)
	}
	k, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return fmt.Errorf("jwt_key: %w", err)
	}
	ek, ok := k.(*ecdsa.PrivateKey)
	if !ok || ek.Curve != elliptic.P256() {
		return errors.New("jwt_key must be an ECDSA P-256 key")
	}
	h.jwtKey = ek
	if h.kid, err = keyID(&ek.PublicKey); err != nil {
		return err
	}

	h.compiled = map[string]*compiledPolicy{}
	for name, p := range h.Policies {
		cp, err := compile(p)
		if err != nil {
			return fmt.Errorf("policy %s: %w", name, err)
		}
		h.compiled[name] = cp
	}
	h.tokens = map[string]ServiceToken{}
	h.headerTokens = map[string][]ServiceToken{}
	for _, t := range h.ServiceTokens {
		if t.Header != "" {
			k := http.CanonicalHeaderKey(t.Header)
			h.headerTokens[k] = append(h.headerTokens[k], t)
			continue
		}
		h.tokens[t.ClientID] = t
	}
	if h.CountryDB != "" {
		v, _, err := geoDBs.LoadOrNew(h.CountryDB, func() (caddy.Destructor, error) {
			r, err := maxminddb.Open(h.CountryDB)
			if err != nil {
				return nil, err
			}
			return &geoDB{Reader: r}, nil
		})
		if err != nil {
			// Country selectors never match then, as in the control plane.
			h.logger.Error("opening the country database failed; country selectors will not match", zap.Error(err))
		} else {
			h.geo = v.(*geoDB)
		}
	}

	if h.ControlHost == "" {
		h.ControlHost = "access.ingressd.internal"
	}
	if h.ControlSocket != "" {
		sock := h.ControlSocket
		h.client = &http.Client{
			Timeout: 5 * time.Second,
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					var d net.Dialer
					return d.DialContext(ctx, "unix", sock)
				},
				MaxIdleConns: 4,
			},
		}
		interval := time.Duration(h.PollInterval)
		if interval <= 0 {
			interval = 2 * time.Second
		}
		path := "/v1/revocations"
		if h.Realm != "" {
			path += "?realm=" + url.QueryEscape(h.Realm)
		}
		h.pollerKey = sock + "|" + h.ControlHost + "|" + h.Realm
		v, _, err := pollers.LoadOrNew(h.pollerKey, func() (caddy.Destructor, error) {
			return startPoller(h.client, h.ControlHost, path, interval, h.logger), nil
		})
		if err != nil {
			return err
		}
		h.poller = v.(*poller)
	}
	return nil
}

func (h *Handler) Cleanup() error {
	if h.geo != nil {
		_, _ = geoDBs.Delete(h.CountryDB)
	}
	if h.pollerKey != "" {
		_, err := pollers.Delete(h.pollerKey)
		return err
	}
	return nil
}

// geoDBs shares one open country database per path between handlers.
var geoDBs = caddy.NewUsagePool()

type geoDB struct{ *maxminddb.Reader }

func (g *geoDB) Destruct() error { return g.Close() }

// country returns the ISO country code for ip, or "".
func (h *Handler) country(ip netip.Addr) string {
	if h.geo == nil || !ip.IsValid() {
		return ""
	}
	var rec struct {
		Country struct {
			ISOCode string `maxminddb:"iso_code"`
		} `maxminddb:"country"`
	}
	if err := h.geo.Lookup(net.IP(ip.AsSlice()), &rec); err != nil {
		return ""
	}
	return rec.Country.ISOCode
}

// kdfPrefix starts every HKDF info string. It is part of the key format
// shared by the control plane, edge_auth and the panel: changing it would
// invalidate every session cookie, auth code and service-token verifier, so
// it keeps the pre-rename name until a key-rotation migration replaces it.
const kdfPrefix = "homeedge/" // legacy homeedge name, remove after 2027-01 (key-derivation label)

// appCookieInfo must match pkg/access.AppCookieInfo.
func appCookieInfo(realm, app string) string {
	if realm == "" {
		return kdfPrefix + "edge_auth/cookie/" + app
	}
	return kdfPrefix + "edge_auth/realm/" + realm + "/cookie/" + app
}

// derive must match internal/auth.derive (HKDF-SHA256, no salt).
func derive(master []byte, info string) []byte {
	k, err := hkdf.Key(sha256.New, master, nil, info, 32)
	if err != nil {
		panic(err)
	}
	return k
}

// keyID must match internal/auth.KeyID.
func keyID(pub *ecdsa.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(der)
	return base64.RawURLEncoding.EncodeToString(sum[:])[:16], nil
}

// session is a verified app cookie.
type session struct {
	sid   string
	email string
	// attrs are the sign-in facts, with "login_method:<method>".
	attrs   []string
	grants  map[string]string
	expires time.Time
	issued  time.Time
}

// freshCookie is how old a cookie must be before a request it does not
// cover goes back to the portal: a cookie the portal has only just issued
// would come straight back (a redirect loop, e.g. while the edge and the
// control plane briefly disagree about a country), so it gets a 403.
const freshCookie = 30 * time.Second

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	stripIdentityHeaders(r.Header)
	clientID, clientSecret := r.Header.Get("Edge-Client-Id"), r.Header.Get("Edge-Client-Secret")
	r.Header.Del("Edge-Client-Id")
	r.Header.Del("Edge-Client-Secret")
	// Header tokens: read and remove their headers, so the secret never
	// reaches the origin (whether or not it is valid).
	headerToken, headerPresented := "", false
	for name, ts := range h.headerTokens {
		if v := r.Header.Get(name); v != "" {
			headerPresented = true
			if headerToken == "" {
				headerToken = h.verifyHeaderToken(ts, v)
			}
		}
		r.Header.Del(name)
	}
	sess := h.session(r)

	// Path rules are matched on the canonical path, so /ADMIN/x, /%61dmin/x
	// and /x/%2e%2e/admin/x all hit /admin/*. Spellings an origin might
	// resolve differently (backslashes, ";" parameters, encoded slashes, NUL,
	// double encoding) are refused when the app has path rules.
	p, err := CanonicalPath(r.URL.EscapedPath())
	if err != nil {
		if len(h.Paths) > 0 {
			return h.deny(w, http.StatusBadRequest, "Invalid request path.")
		}
		p = cleanPath(r.URL.Path)
	}
	switch p {
	case callbackPath, legacyCallbackPath:
		return h.callback(w, r)
	case logoutPath, legacyLogoutPath:
		return h.logout(w, r)
	}

	list := h.Default
	for _, pr := range h.Paths {
		if PathRuleMatch(pr.Match, p) {
			list = pr.Policies
			break
		}
	}
	if len(list) == 0 {
		if sess != nil {
			h.injectUser(r, sess)
		}
		return next.ServeHTTP(w, r)
	}

	// The policy list is evaluated like the engine does (first match wins)
	// for the request as it is now: the client address and its country are
	// checked on every request, so a cookie obtained from an allowed
	// network does not work from elsewhere.
	id := identity{ip: clientIP(r)}
	if clientID != "" {
		id.token = h.verifyServiceToken(clientID, clientSecret)
	}
	if id.token == "" {
		id.token = headerToken
	}
	if sess != nil {
		id.email = sess.email
		id.attrs = sess.attrs
	}
	countryDone := false
	hasAllow := false
policies:
	for _, name := range list {
		pol := h.compiled[name]
		if pol == nil {
			continue
		}
		if pol.Action == "allow" {
			hasAllow = true
		}
		// Who the user is is only known from a session; until then
		// policies about identities are the portal's to enforce.
		if !pol.Offline && sess == nil {
			continue
		}
		if pol.usesCountry && !countryDone {
			id.country, countryDone = h.country(id.ip), true
		}
		switch pol.Action {
		case "bypass":
			if pol.match(id) {
				if sess != nil {
					h.injectUser(r, sess)
				}
				return next.ServeHTTP(w, r)
			}
		case "service_auth":
			if id.token != "" && pol.match(id) {
				h.injectService(r, id.token)
				return next.ServeHTTP(w, r)
			}
		case "deny":
			if pol.match(id) {
				return h.deny(w, http.StatusForbidden, "Access denied.")
			}
		case "allow":
			// The grant proves the email passed the portal for this
			// version of the policy; the network parts are checked now.
			// (Configs rendered before selectors were sent for allow
			// policies have no include list: the grant alone counts.)
			legacy := len(pol.include) == 0
			if sess == nil || (!legacy && !pol.match(id)) {
				continue
			}
			if pol.Version != "" && sess.grants[name] == pol.Version {
				h.injectUser(r, sess)
				return next.ServeHTTP(w, r)
			}
			if !legacy {
				// It applies to this user now but the cookie has no grant
				// for it (signed in elsewhere, or the policy changed): let
				// the portal decide rather than a later policy.
				break policies
			}
		}
	}
	token := id.token
	if (clientID != "" || headerPresented) && token == "" {
		return h.deny(w, http.StatusUnauthorized, "Invalid service token.")
	}
	if hasAllow {
		if sess != nil && time.Since(sess.issued) < freshCookie {
			return h.deny(w, http.StatusForbidden, "Access denied.")
		}
		if r.Method == http.MethodGet || r.Method == http.MethodHead {
			http.Redirect(w, r, h.loginURL(w, r), http.StatusFound)
			return nil
		}
		return h.deny(w, http.StatusUnauthorized, "Sign-in required.")
	}
	return h.deny(w, http.StatusForbidden, "Access denied.")
}

// stripIdentityHeaders removes client copies of the identity headers,
// including "_" spellings (CGI-style origins read them as the same header),
// and takes those names out of Connection, where they would make the proxy
// drop the values edge_auth sets as hop-by-hop headers.
func stripIdentityHeaders(hdr http.Header) {
	isIdentity := func(name string) bool {
		name = strings.ReplaceAll(strings.TrimSpace(name), "_", "-")
		return slices.ContainsFunc(identityHeaders, func(h string) bool { return strings.EqualFold(h, name) })
	}
	for k := range hdr {
		if isIdentity(k) {
			delete(hdr, k)
		}
	}
	var keep []string
	changed := false
	for _, v := range hdr.Values("Connection") {
		for _, opt := range strings.Split(v, ",") {
			if isIdentity(opt) {
				changed = true
				continue
			}
			keep = append(keep, strings.TrimSpace(opt))
		}
	}
	if changed {
		hdr.Set("Connection", strings.Join(keep, ", "))
	}
}

// session verifies the app cookie and removes it from the request so it
// never reaches the origin.
func (h *Handler) session(r *http.Request) *session {
	cookies := r.Cookies()
	var value string
	var keep []string
	for _, c := range cookies {
		if c.Name == h.cookieName {
			value = c.Value
			continue
		}
		keep = append(keep, c.Name+"="+c.Value)
	}
	if value == "" {
		return nil
	}
	r.Header.Del("Cookie")
	if len(keep) > 0 {
		r.Header.Set("Cookie", strings.Join(keep, "; "))
	}
	tok, err := paseto.NewParser().ParseV4Local(h.cookieKey, value, []byte("edge_auth:"+h.App))
	if err != nil {
		return nil
	}
	s := &session{}
	app, _ := tok.GetString("app")
	s.sid, _ = tok.GetString("sid")
	s.email, _ = tok.GetString("email")
	s.expires, _ = tok.GetExpiration()
	iat, _ := tok.GetIssuedAt()
	s.issued = iat
	_ = tok.Get("pols", &s.grants)
	method, _ := tok.GetString("m")
	if method == "" {
		method = "email" // cookies from before login methods
	}
	_ = tok.Get("attrs", &s.attrs)
	s.attrs = append(s.attrs, "login_method:"+strings.ToLower(method))
	if app != h.App || s.sid == "" || s.email == "" {
		return nil
	}
	if h.poller != nil && (h.poller.unverified(iat) || h.poller.revoked(s.sid) || h.poller.revokedBefore(s.email, iat)) {
		return nil
	}
	return s
}

func (h *Handler) verifyServiceToken(id, secret string) string {
	t, ok := h.tokens[id]
	if !ok || secret == "" {
		return ""
	}
	if t.Expires != 0 && time.Now().Unix() >= t.Expires {
		return ""
	}
	m := hmac.New(sha256.New, h.hmacKey)
	m.Write([]byte(secret))
	got := hex.EncodeToString(m.Sum(nil))
	if subtle.ConstantTimeCompare([]byte(got), []byte(t.Verifier)) != 1 {
		return ""
	}
	return t.Name
}

// verifyHeaderToken checks a header value against the tokens using that
// header (HMAC verifiers, constant-time compare) and returns the token's
// name, or "".
func (h *Handler) verifyHeaderToken(ts []ServiceToken, value string) string {
	m := hmac.New(sha256.New, h.hmacKey)
	m.Write([]byte(value))
	got := []byte(hex.EncodeToString(m.Sum(nil)))
	name := ""
	now := time.Now().Unix()
	for _, t := range ts {
		if subtle.ConstantTimeCompare(got, []byte(t.Verifier)) == 1 && (t.Expires == 0 || now < t.Expires) && name == "" {
			name = t.Name
		}
	}
	return name
}

func (h *Handler) injectUser(r *http.Request, s *session) {
	// The session user is an email address, or "<method>:<id>" for sign-ins
	// that proved none (Steam): only addresses go in X-Edge-User-Email.
	email := ""
	if strings.Contains(s.email, "@") {
		email = s.email
		r.Header.Set("X-Edge-User-Email", email)
	}
	r.Header.Set("X-Edge-User", s.email)
	r.Header.Set("Edge-Jwt-Assertion", h.assertion(s.email, email, s.sid, s.expires))
}

func (h *Handler) injectService(r *http.Request, name string) {
	r.Header.Set("X-Edge-Service-Token", name)
	r.Header.Set("Edge-Jwt-Assertion", h.assertion("service-token:"+name, "", "", time.Time{}))
}

// loginURL sends the browser to the portal. It binds the sign-in to this
// browser: a random nonce goes into a short-lived cookie on the app host
// and its hash ("n") to the portal, which seals it into the callback code;
// the callback only redeems a code whose nonce matches the cookie, so a
// code minted for someone else's session cannot be planted (login
// fixation). An existing nonce is reused so parallel tabs all work.
func (h *Handler) loginURL(w http.ResponseWriter, r *http.Request) string {
	nonce := ""
	if c, err := r.Cookie(h.flowCookie); err == nil && validNonce(c.Value) {
		nonce = c.Value
	} else {
		var b [32]byte
		_, _ = rand.Read(b[:])
		nonce = b64(b[:])
	}
	http.SetCookie(w, &http.Cookie{Name: h.flowCookie, Value: nonce, Path: flowCookiePath, MaxAge: int(flowTTL.Seconds()),
		HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
	rd := "https://" + r.Host + r.URL.RequestURI()
	q := url.Values{"app": {h.App}, "rd": {rd}}.Encode() + "&n=" + nonceHash(nonce) // base64url needs no escaping
	return strings.TrimSuffix(h.PortalURL, "/") + "/login?" + q
}

const (
	// flowCookiePath scopes the nonce cookie to the callback.
	flowCookiePath = "/.ingressd/"
	// flowTTL bounds how long a sign-in may take (email code included).
	flowTTL = 30 * time.Minute
)

// nonceHash must match pkg/access.FlowNonceHash.
func nonceHash(nonce string) string {
	sum := sha256.Sum256([]byte(nonce))
	return b64(sum[:])
}

func validNonce(s string) bool {
	b, err := base64.RawURLEncoding.DecodeString(s)
	return err == nil && len(b) == 32
}

// logout clears the app cookie and continues to the portal's sign-out. It
// is POST-only (from the same origin) so other sites cannot sign users
// out; GET shows a confirmation form.
func (h *Handler) logout(w http.ResponseWriter, r *http.Request) error {
	portal := strings.TrimSuffix(h.PortalURL, "/")
	w.Header().Set("Cache-Control", "no-store")
	switch r.Method {
	case http.MethodPost:
	case http.MethodGet, http.MethodHead:
		// form-action must allow the redirect to the portal that follows.
		origin := portal
		if u, err := url.Parse(portal); err == nil {
			origin = u.Scheme + "://" + u.Host
		}
		w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self' "+origin+"; frame-ancestors 'none'; base-uri 'none'")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, `<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Sign out</title>`+
			`<style>body{font-family:-apple-system,"Segoe UI",Roboto,sans-serif;max-width:360px;margin:15vh auto;padding:0 16px}button{padding:10px 16px;font-size:16px}</style>`+
			`<h1>Sign out</h1><form method="post" action="`+logoutPath+`"><button type="submit">Sign out</button></form>`+"\n")
		return nil
	default:
		w.Header().Set("Allow", "GET, HEAD, POST")
		return h.deny(w, http.StatusMethodNotAllowed, "Method not allowed.")
	}
	if !sameOrigin(r) {
		return h.deny(w, http.StatusForbidden, "Cross-site request rejected.")
	}
	http.SetCookie(w, &http.Cookie{Name: h.cookieName, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
	http.Redirect(w, r, portal+"/logout", http.StatusSeeOther)
	return nil
}

// sameOrigin reports whether a POST came from a page on the request's own
// host: Origin, else Sec-Fetch-Site, else Referer; with none it is refused.
// Like the portal's check (internal/auth), but stricter about
// Sec-Fetch-Site: sibling apps on the same site are other origins.
func sameOrigin(r *http.Request) bool {
	host := r.Host
	if hh, _, err := net.SplitHostPort(host); err == nil {
		host = hh
	}
	if o := r.Header.Get("Origin"); o != "" && o != "null" {
		u, err := url.Parse(o)
		return err == nil && strings.EqualFold(u.Hostname(), host)
	}
	if s := r.Header.Get("Sec-Fetch-Site"); s != "" {
		return s == "same-origin"
	}
	if ref := r.Header.Get("Referer"); ref != "" {
		u, err := url.Parse(ref)
		return err == nil && strings.EqualFold(u.Hostname(), host)
	}
	return false
}

func (h *Handler) deny(w http.ResponseWriter, status int, msg string) error {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	fmt.Fprintf(w, "<!doctype html><title>%d</title><h1>%s</h1>\n", status, html.EscapeString(msg))
	return nil
}

func clientIP(r *http.Request) netip.Addr {
	s, _ := caddyhttp.GetVar(r.Context(), caddyhttp.ClientIPVarKey).(string)
	if s == "" {
		s = r.RemoteAddr
		if host, _, err := net.SplitHostPort(s); err == nil {
			s = host
		}
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}
	}
	return a.Unmap()
}

// cleanPath is the fallback for ambiguous paths of apps without path rules
// (only the callback and logout paths are matched then).
func cleanPath(p string) string {
	if p == "" {
		return "/"
	}
	c := path.Clean("/" + p)
	if strings.HasSuffix(p, "/") && c != "/" {
		c += "/"
	}
	return c
}

// --- policies ---

// identity is what policies are evaluated against; zero fields never match
// the selectors that need them (as pkg/access.Identity).
type identity struct {
	email   string
	ip      netip.Addr
	country string
	token   string
	attrs   []string
}

type compiledPolicy struct {
	Policy
	include, require, exclude []compiledSelector
	usesCountry               bool
}

type compiledSelector struct {
	everyone  bool
	never     bool
	emails    []string
	domains   []string
	prefixes  []netip.Prefix
	countries []string
	tokens    []string
	attrs     []string
}

func compile(p Policy) (*compiledPolicy, error) {
	cp := &compiledPolicy{Policy: p}
	var err error
	if cp.include, err = compileSelectors(p.Include); err != nil {
		return nil, err
	}
	if cp.require, err = compileSelectors(p.Require); err != nil {
		return nil, err
	}
	if cp.exclude, err = compileSelectors(p.Exclude); err != nil {
		return nil, err
	}
	for _, sels := range [][]compiledSelector{cp.include, cp.require, cp.exclude} {
		for _, s := range sels {
			cp.usesCountry = cp.usesCountry || len(s.countries) > 0
		}
	}
	return cp, nil
}

func compileSelectors(sels []Selector) ([]compiledSelector, error) {
	out := make([]compiledSelector, 0, len(sels))
	for _, s := range sels {
		cs := compiledSelector{everyone: s.Everyone, never: s.Never, tokens: s.ServiceToken, attrs: s.Attr}
		for _, v := range s.Email {
			cs.emails = append(cs.emails, strings.ToLower(v))
		}
		for _, v := range s.EmailDomain {
			cs.domains = append(cs.domains, strings.ToLower(v))
		}
		for _, v := range s.Country {
			cs.countries = append(cs.countries, strings.ToUpper(v))
		}
		for _, v := range s.IP {
			p, err := netip.ParsePrefix(v)
			if err != nil {
				a, aerr := netip.ParseAddr(v)
				if aerr != nil {
					return nil, fmt.Errorf("invalid ip %q", v)
				}
				p = netip.PrefixFrom(a, a.BitLen())
			}
			cs.prefixes = append(cs.prefixes, p.Masked())
		}
		out = append(out, cs)
	}
	return out, nil
}

func (s compiledSelector) match(id identity) bool {
	if s.never {
		return false
	}
	if s.everyone {
		return true
	}
	if id.email != "" {
		email := strings.ToLower(id.email)
		if slices.Contains(s.emails, email) {
			return true
		}
		if at := strings.LastIndexByte(email, '@'); at >= 0 && slices.Contains(s.domains, email[at+1:]) {
			return true
		}
	}
	if id.ip.IsValid() {
		ip := id.ip.Unmap()
		for _, p := range s.prefixes {
			if p.Contains(ip) {
				return true
			}
		}
	}
	if id.country != "" && slices.Contains(s.countries, strings.ToUpper(id.country)) {
		return true
	}
	if id.token != "" && slices.Contains(s.tokens, id.token) {
		return true
	}
	for _, a := range id.attrs {
		if slices.Contains(s.attrs, a) {
			return true
		}
	}
	return false
}

// match is the engine's rule (pkg/access): any include, all requires and
// no excludes; an empty include list never matches.
func (p *compiledPolicy) match(id identity) bool {
	any := false
	for _, s := range p.include {
		if s.match(id) {
			any = true
			break
		}
	}
	if !any {
		return false
	}
	for _, s := range p.require {
		if !s.match(id) {
			return false
		}
	}
	for _, s := range p.exclude {
		if s.match(id) {
			return false
		}
	}
	return true
}

var (
	_ caddy.Provisioner           = (*Handler)(nil)
	_ caddy.CleanerUpper          = (*Handler)(nil)
	_ caddyhttp.MiddlewareHandler = (*Handler)(nil)
)

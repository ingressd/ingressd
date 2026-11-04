// SPDX-License-Identifier: Apache-2.0

package edgeauth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"aidanwoods.dev/go-paseto"
	"github.com/caddyserver/caddy/v2/caddytest"

	_ "github.com/caddyserver/caddy/v2/modules/standard"
)

// Shared test vector with internal/auth (TestDeriveVector): if this
// changes, cookies minted by the control plane stop verifying here.
func TestDeriveVector(t *testing.T) {
	master := []byte("0123456789abcdef0123456789abcdef")
	got := hex.EncodeToString(derive(master, kdfPrefix+"edge_auth/cookie/web"))
	if got != deriveVector {
		t.Fatalf("derive = %s, want %s", got, deriveVector)
	}
}

const deriveVector = "c21d56724026cde83c7e95aa589b69a54386518c301d9ac3bec055f9cc372795"

type fixture struct {
	master  []byte
	jwt     *ecdsa.PrivateKey
	sock    string
	mu      sync.Mutex
	revoked []string
	rev     int
	down    bool   // the revocation list is unavailable
	nonce   string // of the last code exchange
}

func newFixture(t *testing.T) *fixture {
	f := &fixture{master: make([]byte, 32)}
	rand.Read(f.master)
	var err error
	if f.jwt, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
		t.Fatal(err)
	}
	// Unix socket paths are limited to ~108 bytes; TempDir can be long.
	dir, err := os.MkdirTemp("", "ea")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	f.sock = filepath.Join(dir, "c.sock")
	ln, err := net.Listen("unix", f.sock)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/exchange", func(w http.ResponseWriter, r *http.Request) {
		var req exchangeRequest
		json.NewDecoder(r.Body).Decode(&req)
		f.mu.Lock()
		f.nonce = req.Nonce
		f.mu.Unlock()
		if req.Code == "denied" && req.IP != "" { // the control plane evaluates the policies for the visitor's IP
			http.Error(w, "not allowed: dave@example.com may not access this app", http.StatusForbidden)
			return
		}
		if req.Code != "good" || req.App != "web" || r.Host != "access.ingressd.internal" {
			http.Error(w, "invalid code", http.StatusForbidden)
			return
		}
		exp := time.Now().Add(time.Hour)
		json.NewEncoder(w).Encode(exchangeResponse{
			Token:   f.seal(t, "sid-cb", "carol@example.com", map[string]string{"members": "v1"}, exp),
			Expires: exp.Unix(),
			RD:      "https://" + req.Host + "/after?x=1",
		})
	})
	mux.HandleFunc("GET /v1/revocations", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if f.down {
			http.Error(w, "starting", http.StatusServiceUnavailable)
			return
		}
		etag := `"` + string(rune('a'+f.rev)) + `"`
		w.Header().Set("ETag", etag)
		if r.Header.Get("If-None-Match") == etag {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"revision": f.rev, "sids": f.revoked})
	})
	srv := &http.Server{Handler: mux}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return f
}

func (f *fixture) revoke(sid string) {
	f.mu.Lock()
	f.revoked = append(f.revoked, sid)
	f.rev++
	f.mu.Unlock()
}

func (f *fixture) seal(t *testing.T, sid, email string, grants map[string]string, exp time.Time) string {
	return f.sealAt(t, time.Now(), sid, email, grants, exp)
}

func (f *fixture) sealAt(t *testing.T, iat time.Time, sid, email string, grants map[string]string, exp time.Time) string {
	key, err := paseto.V4SymmetricKeyFromBytes(derive(f.master, kdfPrefix+"edge_auth/cookie/web"))
	if err != nil {
		t.Fatal(err)
	}
	tok := paseto.NewToken()
	tok.SetIssuedAt(iat)
	tok.SetExpiration(exp)
	tok.SetString("sid", sid)
	tok.SetString("email", email)
	tok.SetString("app", "web")
	tok.Set("pols", grants)
	return tok.V4Encrypt(key, []byte("edge_auth:web"))
}

func (f *fixture) config(t *testing.T, mods ...func(h map[string]any)) string {
	der, err := x509.MarshalPKCS8PrivateKey(f.jwt)
	if err != nil {
		t.Fatal(err)
	}
	m := hmac.New(sha256.New, derive(f.master, kdfPrefix+"edge_auth/service-token"))
	m.Write([]byte("hook-secret"))
	verifier := hex.EncodeToString(m.Sum(nil))
	h := map[string]any{
		"handler":        "edge_auth",
		"app":            "web",
		"portal_url":     "https://auth.example.test",
		"session_key":    base64.StdEncoding.EncodeToString(f.master),
		"jwt_key":        base64.StdEncoding.EncodeToString(der),
		"control_socket": f.sock,
		"control_host":   "access.ingressd.internal",
		"poll_interval":  "100ms",
		"default":        []string{"blocked-net", "members"},
		"paths": []map[string]any{
			{"match": "/public/*", "policies": []string{"public"}},
			{"match": "/hook/*", "policies": []string{"hook"}},
			{"match": "/old/*", "policies": []string{"old-hook"}},
			{"match": "/blocked/*", "policies": []string{"deny-all", "public"}},
			{"match": "/office/*", "policies": []string{"office"}},
			{"match": "/local/*", "policies": []string{"office", "local"}},
			{"match": "/no-mallory/*", "policies": []string{"no-mallory", "members"}},
			{"match": "/legacy/*", "policies": []string{"legacy"}},
			{"match": "/order/*", "policies": []string{"local", "deny-all"}},
		},
		"policies": map[string]any{
			"members": map[string]any{"action": "allow", "version": "v1", "include": []any{map[string]any{"email_domain": []string{"example.com"}}}},
			// allow alice require ip: the test client is on loopback.
			"office": map[string]any{"action": "allow", "version": "o1",
				"include": []any{map[string]any{"email": []string{"alice@example.com"}}},
				"require": []any{map[string]any{"ip": []string{"10.0.0.0/8"}}}},
			"local": map[string]any{"action": "allow", "version": "l1",
				"include": []any{map[string]any{"email": []string{"alice@example.com"}}},
				"require": []any{map[string]any{"ip": []string{"127.0.0.0/8", "::1"}}}},
			"no-mallory": map[string]any{"action": "deny", "version": "n",
				"include": []any{map[string]any{"email": []string{"mallory@example.com"}}},
				"require": []any{map[string]any{"ip": []string{"127.0.0.0/8", "::1"}}}},
			"legacy":      map[string]any{"action": "allow", "version": "g"}, // rendered before allow policies had selectors
			"deny-all":    map[string]any{"action": "deny", "version": "d", "offline": true, "include": []any{map[string]any{"everyone": true}}},
			"public":      map[string]any{"action": "bypass", "version": "p", "offline": true, "include": []any{map[string]any{"everyone": true}}},
			"blocked-net": map[string]any{"action": "deny", "version": "b", "offline": true, "include": []any{map[string]any{"ip": []string{"192.0.2.0/24"}}}},
			"hook":        map[string]any{"action": "service_auth", "version": "h", "offline": true, "include": []any{map[string]any{"service_token": []string{"hook"}}}},
			"old-hook":    map[string]any{"action": "service_auth", "version": "o", "offline": true, "include": []any{map[string]any{"service_token": []string{"old"}}}},
		},
		"service_tokens": []map[string]any{
			{"name": "hook", "client_id": "hook.access", "verifier": verifier},
			{"name": "old", "client_id": "old.access", "verifier": verifier, "expires": time.Now().Add(-time.Hour).Unix()},
		},
	}
	for _, m := range mods {
		m(h)
	}
	echo := map[string]any{
		"handler": "static_response",
		"body":    "email={http.request.header.X-Edge-User-Email} svc={http.request.header.X-Edge-Service-Token} cookie={http.request.header.Cookie} jwt={http.request.header.Edge-Jwt-Assertion}",
	}
	cfg := map[string]any{
		"admin": map[string]any{"listen": "localhost:2939"},
		"apps": map[string]any{"http": map[string]any{
			"http_port": 9381, "https_port": 9444,
			"servers": map[string]any{"srv0": map[string]any{
				"listen":          []string{":9381"},
				"automatic_https": map[string]any{"disable": true},
				"routes":          []any{map[string]any{"handle": []any{h, echo}}},
			}},
		}},
	}
	b, _ := json.Marshal(cfg)
	return string(b)
}

type client struct {
	t *testing.T
	c *http.Client
}

func (c client) get(path string, hdr map[string]string) (*http.Response, string) {
	c.t.Helper()
	req, _ := http.NewRequest(http.MethodGet, "http://localhost:9381"+path, nil)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	return c.do(req)
}

func (c client) do(req *http.Request) (*http.Response, string) {
	c.t.Helper()
	resp, err := c.c.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, string(b)
}

func TestEdgeAuth(t *testing.T) {
	f := newFixture(t)
	tester := caddytest.NewTester(t).WithDefaultOverrides(caddytest.Config{AdminPort: 2939})
	tester.InitServer(f.config(t), "json")
	c := client{t, &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}

	cookie := func(v string) map[string]string { return map[string]string{"Cookie": "__edge_web=" + v + "; other=1"} }
	valid := f.seal(t, "sid-1", "alice@example.com", map[string]string{"members": "v1"}, time.Now().Add(time.Hour))

	t.Run("no cookie redirects to portal", func(t *testing.T) {
		resp, _ := c.get("/x?y=1", nil)
		loc := resp.Header.Get("Location")
		if resp.StatusCode != http.StatusFound || !strings.HasPrefix(loc, "https://auth.example.test/login?") ||
			!strings.Contains(loc, "app=web") || !strings.Contains(loc, "rd=https%3A%2F%2Flocalhost%3A9381%2Fx%3Fy%3D1") {
			t.Fatalf("status %d location %q", resp.StatusCode, loc)
		}
	})

	t.Run("sign-in is bound to the browser", func(t *testing.T) {
		resp, _ := c.get("/x", nil)
		var flow *http.Cookie
		for _, ck := range resp.Cookies() {
			if ck.Name == "__edge_signin_web" {
				flow = ck
			}
		}
		if flow == nil || !flow.HttpOnly || !flow.Secure || flow.SameSite != http.SameSiteLaxMode || flow.Path != "/.ingressd/" || flow.MaxAge <= 0 {
			t.Fatalf("nonce cookie %+v", flow)
		}
		u, _ := url.Parse(resp.Header.Get("Location"))
		sum := sha256.Sum256([]byte(flow.Value))
		if n := u.Query().Get("n"); n != base64.RawURLEncoding.EncodeToString(sum[:]) {
			t.Fatalf("n = %q, want the nonce's hash", n)
		}
		// A second redirect (another tab) keeps the same nonce.
		resp, _ = c.get("/y", map[string]string{"Cookie": "__edge_signin_web=" + flow.Value})
		if u2, _ := url.Parse(resp.Header.Get("Location")); u2.Query().Get("n") != u.Query().Get("n") {
			t.Fatal("nonce replaced by a parallel sign-in")
		}
		// The callback hands the nonce to the control plane and clears it.
		resp, _ = c.get("/.ingressd/callback?code=good", map[string]string{"Cookie": "__edge_signin_web=" + flow.Value})
		f.mu.Lock()
		got := f.nonce
		f.mu.Unlock()
		if resp.StatusCode != http.StatusFound || got != flow.Value {
			t.Fatalf("callback: status %d, nonce sent %q", resp.StatusCode, got)
		}
		cleared := false
		for _, ck := range resp.Cookies() {
			cleared = cleared || (ck.Name == "__edge_signin_web" && ck.MaxAge < 0)
		}
		if !cleared {
			t.Fatal("nonce cookie not cleared after sign-in")
		}
	})

	t.Run("non-GET without cookie is 401", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodPost, "http://localhost:9381/x", nil)
		if resp, _ := c.do(req); resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("status %d", resp.StatusCode)
		}
	})

	t.Run("valid cookie passes with identity", func(t *testing.T) {
		hdr := cookie(valid)
		hdr["X-Edge-User-Email"] = "mallory@evil.test"
		resp, body := c.get("/x", hdr)
		if resp.StatusCode != 200 || !strings.Contains(body, "email=alice@example.com ") {
			t.Fatalf("status %d body %q", resp.StatusCode, body)
		}
		if !strings.Contains(body, "cookie=other=1 ") {
			t.Errorf("app cookie forwarded to origin: %q", body)
		}
		jwt := body[strings.Index(body, "jwt=")+4:]
		claims := verifyJWT(t, &f.jwt.PublicKey, jwt)
		if claims["aud"] != "web" || claims["email"] != "alice@example.com" || claims["sid"] != "sid-1" {
			t.Errorf("claims %v", claims)
		}
	})

	t.Run("stale policy version redirects", func(t *testing.T) {
		old := f.sealAt(t, time.Now().Add(-time.Minute), "sid-2", "alice@example.com", map[string]string{"members": "v0"}, time.Now().Add(time.Hour))
		if resp, _ := c.get("/x", cookie(old)); resp.StatusCode != http.StatusFound {
			t.Fatalf("status %d", resp.StatusCode)
		}
	})

	t.Run("expired cookie redirects", func(t *testing.T) {
		exp := f.seal(t, "sid-3", "alice@example.com", map[string]string{"members": "v1"}, time.Now().Add(-time.Minute))
		if resp, _ := c.get("/x", cookie(exp)); resp.StatusCode != http.StatusFound {
			t.Fatalf("status %d", resp.StatusCode)
		}
	})

	t.Run("bypass path open and spoofed header stripped", func(t *testing.T) {
		resp, body := c.get("/public/a", map[string]string{"X-Edge-User-Email": "mallory@evil.test", "Edge-Jwt-Assertion": "forged"})
		if resp.StatusCode != 200 || !strings.Contains(body, "email= ") || !strings.HasSuffix(body, "jwt=") {
			t.Fatalf("status %d body %q", resp.StatusCode, body)
		}
	})

	t.Run("dot segments cannot reach bypass rules", func(t *testing.T) {
		if resp, _ := c.get("/public/../x", nil); resp.StatusCode != http.StatusFound {
			t.Fatalf("status %d", resp.StatusCode)
		}
	})

	t.Run("service token", func(t *testing.T) {
		resp, body := c.get("/hook/run", map[string]string{"Edge-Client-Id": "hook.access", "Edge-Client-Secret": "hook-secret"})
		if resp.StatusCode != 200 || !strings.Contains(body, "svc=hook ") {
			t.Fatalf("status %d body %q", resp.StatusCode, body)
		}
		if resp, _ := c.get("/hook/run", map[string]string{"Edge-Client-Id": "hook.access", "Edge-Client-Secret": "wrong"}); resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("wrong secret: status %d", resp.StatusCode)
		}
		if resp, _ := c.get("/hook/run", nil); resp.StatusCode != http.StatusForbidden {
			t.Fatalf("no token: status %d", resp.StatusCode)
		}
		if resp, _ := c.get("/old/run", map[string]string{"Edge-Client-Id": "old.access", "Edge-Client-Secret": "hook-secret"}); resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("expired token: status %d", resp.StatusCode)
		}
		// A service token is not a user session.
		if resp, _ := c.get("/x", map[string]string{"Edge-Client-Id": "hook.access", "Edge-Client-Secret": "hook-secret"}); resp.StatusCode == 200 {
			t.Fatal("service token accepted on an allow-only path")
		}
	})

	t.Run("network conditions of allow policies are checked on every request", func(t *testing.T) {
		grants := map[string]string{"office": "o1", "local": "l1"}
		ck := f.sealAt(t, time.Now().Add(-time.Minute), "sid-o", "alice@example.com", grants, time.Now().Add(time.Hour))
		// A cookie for "allow alice require ip 10/8" from another network.
		if resp, _ := c.get("/office/x", cookie(ck)); resp.StatusCode != http.StatusFound {
			t.Fatalf("office from loopback: status %d", resp.StatusCode)
		}
		resp, body := c.get("/local/x", cookie(ck))
		if resp.StatusCode != 200 || !strings.Contains(body, "email=alice@example.com ") {
			t.Fatalf("local: status %d body %q", resp.StatusCode, body)
		}
		// The identity still counts: a cookie for bob carrying the same
		// grants (which the portal would never issue him) fails too.
		bob := f.sealAt(t, time.Now().Add(-time.Minute), "sid-b", "bob@example.com", grants, time.Now().Add(time.Hour))
		if resp, _ := c.get("/local/x", cookie(bob)); resp.StatusCode != http.StatusFound {
			t.Fatalf("bob: status %d", resp.StatusCode)
		}
		// A cookie the portal has only just issued is not sent back there
		// (no redirect loop when edge and portal briefly disagree).
		fresh := f.seal(t, "sid-of", "alice@example.com", grants, time.Now().Add(time.Hour))
		if resp, _ := c.get("/office/x", cookie(fresh)); resp.StatusCode != http.StatusForbidden {
			t.Fatalf("fresh cookie, other network: status %d", resp.StatusCode)
		}
		// No grant, no entry, even when the policy would match.
		nog := f.sealAt(t, time.Now().Add(-time.Minute), "sid-n", "alice@example.com", map[string]string{"members": "v1"}, time.Now().Add(time.Hour))
		if resp, _ := c.get("/local/x", cookie(nog)); resp.StatusCode != http.StatusFound {
			t.Fatalf("no grant: status %d", resp.StatusCode)
		}
	})

	t.Run("an allow policy that applies but has no grant goes to the portal", func(t *testing.T) {
		// local applies to alice on loopback, but her cookie predates it:
		// the portal decides, not the deny-all after it.
		ck := f.sealAt(t, time.Now().Add(-time.Minute), "sid-r", "alice@example.com", map[string]string{"members": "v1"}, time.Now().Add(time.Hour))
		if resp, _ := c.get("/order/x", cookie(ck)); resp.StatusCode != http.StatusFound {
			t.Fatalf("no grant: status %d", resp.StatusCode)
		}
		ck = f.sealAt(t, time.Now().Add(-time.Minute), "sid-r2", "alice@example.com", map[string]string{"local": "l1"}, time.Now().Add(time.Hour))
		if resp, _ := c.get("/order/x", cookie(ck)); resp.StatusCode != 200 {
			t.Fatalf("granted: status %d", resp.StatusCode)
		}
		// Bob's identity does not match local: the next policy decides.
		ck = f.sealAt(t, time.Now().Add(-time.Minute), "sid-r3", "bob@example.com", map[string]string{"local": "l1"}, time.Now().Add(time.Hour))
		if resp, _ := c.get("/order/x", cookie(ck)); resp.StatusCode != http.StatusForbidden {
			t.Fatalf("bob: status %d", resp.StatusCode)
		}
	})

	t.Run("deny policies with identities use the session email", func(t *testing.T) {
		m := f.seal(t, "sid-m", "mallory@example.com", map[string]string{"members": "v1"}, time.Now().Add(time.Hour))
		if resp, _ := c.get("/no-mallory/x", cookie(m)); resp.StatusCode != http.StatusForbidden {
			t.Fatalf("mallory: status %d", resp.StatusCode)
		}
		if resp, _ := c.get("/no-mallory/x", cookie(valid)); resp.StatusCode != 200 {
			t.Fatalf("alice: status %d", resp.StatusCode)
		}
		// Anonymous: left to the portal (sign-in), not a blanket 403.
		if resp, _ := c.get("/no-mallory/x", nil); resp.StatusCode != http.StatusFound {
			t.Fatalf("anonymous: status %d", resp.StatusCode)
		}
	})

	t.Run("legacy allow policy without selectors uses the grant", func(t *testing.T) {
		ck := f.seal(t, "sid-g", "alice@example.com", map[string]string{"legacy": "g"}, time.Now().Add(time.Hour))
		if resp, _ := c.get("/legacy/x", cookie(ck)); resp.StatusCode != 200 {
			t.Fatalf("status %d", resp.StatusCode)
		}
	})

	t.Run("network deny policy", func(t *testing.T) {
		if resp, _ := c.get("/blocked/x", nil); resp.StatusCode != http.StatusForbidden {
			t.Fatalf("status %d", resp.StatusCode)
		}
	})

	t.Run("callback exchanges code for cookie", func(t *testing.T) {
		resp, _ := c.get("/.ingressd/callback?code=good", nil)
		if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "/after?x=1" {
			t.Fatalf("status %d location %q", resp.StatusCode, resp.Header.Get("Location"))
		}
		var got *http.Cookie
		for _, ck := range resp.Cookies() {
			if ck.Name == "__edge_web" {
				got = ck
			}
		}
		if got == nil || !got.HttpOnly || !got.Secure || got.SameSite != http.SameSiteLaxMode {
			t.Fatalf("cookie %+v", got)
		}
		_, body := c.get("/x", cookie(got.Value))
		if !strings.Contains(body, "email=carol@example.com ") {
			t.Fatalf("body %q", body)
		}
		if resp, _ := c.get("/.ingressd/callback?code=bad", nil); resp.StatusCode != http.StatusForbidden {
			t.Fatalf("bad code: status %d", resp.StatusCode)
		}
		if resp, body := c.get("/.ingressd/callback?code=denied", nil); resp.StatusCode != http.StatusForbidden ||
			!strings.Contains(body, "Access denied: dave@example.com is not allowed to access this app.") {
			t.Fatalf("denied: status %d body %q", resp.StatusCode, body)
		}
	})

	t.Run("logout is a same-origin POST", func(t *testing.T) {
		resp, body := c.get("/.ingressd/logout", cookie(valid))
		if resp.StatusCode != 200 || resp.Header.Get("Set-Cookie") != "" || !strings.Contains(body, `<form method="post" action="/.ingressd/logout">`) ||
			!strings.Contains(resp.Header.Get("Content-Security-Policy"), "form-action 'self' https://auth.example.test;") {
			t.Fatalf("GET: status %d headers %v body %q", resp.StatusCode, resp.Header, body)
		}
		post := func(hdr map[string]string) *http.Response {
			req, _ := http.NewRequest(http.MethodPost, "http://localhost:9381/.ingressd/logout", nil)
			for k, v := range cookie(valid) {
				req.Header.Set(k, v)
			}
			for k, v := range hdr {
				req.Header.Set(k, v)
			}
			resp, _ := c.do(req)
			return resp
		}
		for _, hdr := range []map[string]string{
			{"Origin": "https://evil.example"},
			{"Sec-Fetch-Site": "same-site"},
			{"Referer": "https://evil.example/x"},
			nil,
		} {
			if resp := post(hdr); resp.StatusCode != http.StatusForbidden || resp.Header.Get("Set-Cookie") != "" {
				t.Errorf("POST %v: status %d", hdr, resp.StatusCode)
			}
		}
		for _, hdr := range []map[string]string{
			{"Origin": "http://localhost:9381"},
			{"Origin": "null", "Sec-Fetch-Site": "same-origin"},
			{"Referer": "http://localhost:9381/app"},
		} {
			resp := post(hdr)
			if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "https://auth.example.test/logout" ||
				!strings.Contains(resp.Header.Get("Set-Cookie"), "Max-Age=0") {
				t.Fatalf("POST %v: status %d headers %v", hdr, resp.StatusCode, resp.Header)
			}
		}
	})

	t.Run("revocation takes effect without reload", func(t *testing.T) {
		f.revoke("sid-1")
		deadline := time.Now().Add(3 * time.Second)
		for {
			resp, _ := c.get("/x", cookie(valid))
			if resp.StatusCode == http.StatusFound {
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("revoked session still accepted (status %d)", resp.StatusCode)
			}
			time.Sleep(50 * time.Millisecond)
		}
	})
}

func verifyJWT(t *testing.T, pub *ecdsa.PublicKey, jwt string) map[string]any {
	t.Helper()
	parts := strings.Split(strings.TrimSpace(jwt), ".")
	if len(parts) != 3 {
		t.Fatalf("malformed JWT %q", jwt)
	}
	sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if len(sig) != 64 || !ecdsa.Verify(pub, sum[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		t.Fatal("JWT signature does not verify")
	}
	var claims map[string]any
	b, _ := base64.RawURLEncoding.DecodeString(parts[1])
	json.Unmarshal(b, &claims)
	return claims
}

func TestPolicyMatch(t *testing.T) {
	p, err := compile(Policy{
		Include: []Selector{{IP: []string{"10.0.0.0/8"}}, {ServiceToken: []string{"a"}}},
		Require: []Selector{{IP: []string{"10.1.0.0/16", "192.0.2.1"}}},
		Exclude: []Selector{{IP: []string{"10.1.2.0/24"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		ip, token string
		want      bool
	}{
		{"10.1.1.1", "", true},
		{"10.2.1.1", "", false}, // fails require
		{"10.1.2.3", "", false}, // excluded
		{"192.0.2.1", "a", true},
		{"192.0.2.1", "", false},
		{"", "a", false},
	} {
		if got := p.match(identity{ip: parseAddr(tc.ip), token: tc.token}); got != tc.want {
			t.Errorf("match(%q, %q) = %v, want %v", tc.ip, tc.token, got, tc.want)
		}
	}
}

// The edge evaluates a policy exactly like pkg/access: any include, all
// requires, no excludes; one kind per selector; email matching ignores case.
func TestPolicyIdentityAndNetwork(t *testing.T) {
	staffOffice, _ := compile(Policy{ // allow email=staff require ip=office
		Include: []Selector{{Email: []string{"Staff@Example.com"}}, {EmailDomain: []string{"corp.test"}}},
		Require: []Selector{{IP: []string{"10.0.0.0/8"}}, {Country: []string{"gb", "IE"}}},
		Exclude: []Selector{{Email: []string{"fired@corp.test"}}, {IP: []string{"10.66.0.0/16"}}},
	})
	mixedInclude, _ := compile(Policy{ // include is any-of: alice anywhere, anyone in the office
		Include: []Selector{{Email: []string{"alice@example.com"}}, {IP: []string{"10.0.0.0/8"}}},
	})
	never, _ := compile(Policy{Include: []Selector{{Everyone: true}}, Require: []Selector{{Never: true}}})
	for _, tc := range []struct {
		name string
		p    *compiledPolicy
		id   identity
		want bool
	}{
		{"office, GB", staffOffice, identity{email: "staff@example.com", ip: parseAddr("10.1.1.1"), country: "GB"}, true},
		{"domain member", staffOffice, identity{email: "bob@CORP.test", ip: parseAddr("10.1.1.1"), country: "IE"}, true},
		{"home network", staffOffice, identity{email: "staff@example.com", ip: parseAddr("198.51.100.7"), country: "GB"}, false},
		{"office, unknown country", staffOffice, identity{email: "staff@example.com", ip: parseAddr("10.1.1.1")}, false},
		{"excluded subnet", staffOffice, identity{email: "staff@example.com", ip: parseAddr("10.66.1.1"), country: "GB"}, false},
		{"excluded email", staffOffice, identity{email: "fired@corp.test", ip: parseAddr("10.1.1.1"), country: "GB"}, false},
		{"other email", staffOffice, identity{email: "eve@example.com", ip: parseAddr("10.1.1.1"), country: "GB"}, false},
		{"no email", staffOffice, identity{ip: parseAddr("10.1.1.1"), country: "GB"}, false},
		{"IPv4-mapped", staffOffice, identity{email: "staff@example.com", ip: parseAddr("::ffff:10.1.1.1"), country: "GB"}, true},
		{"include by email", mixedInclude, identity{email: "alice@example.com", ip: parseAddr("198.51.100.7")}, true},
		{"include by network", mixedInclude, identity{email: "bob@example.com", ip: parseAddr("10.2.2.2")}, true},
		{"include by network, left the office", mixedInclude, identity{email: "bob@example.com", ip: parseAddr("198.51.100.7")}, false},
		{"never", never, identity{email: "a@b.test", ip: parseAddr("10.1.1.1")}, false},
	} {
		if got := tc.p.match(tc.id); got != tc.want {
			t.Errorf("%s: match = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func parseAddr(s string) netip.Addr {
	a, _ := netip.ParseAddr(s)
	return a
}

// After a restart, cookies from before it are refused until the edge has
// fetched the revocation list once: they may have been revoked meanwhile.
func TestRevocationsUnknownAfterRestart(t *testing.T) {
	f := newFixture(t)
	f.down = true
	tester := caddytest.NewTester(t).WithDefaultOverrides(caddytest.Config{AdminPort: 2939})
	tester.InitServer(f.config(t), "json")
	c := client{t, &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
	grants := map[string]string{"members": "v1"}
	old := f.sealAt(t, time.Now().Add(-time.Hour), "sid-old", "alice@example.com", grants, time.Now().Add(time.Hour))
	fresh := f.seal(t, "sid-new", "alice@example.com", grants, time.Now().Add(time.Hour))
	ck := func(v string) map[string]string { return map[string]string{"Cookie": "__edge_web=" + v} }
	if resp, _ := c.get("/x", ck(old)); resp.StatusCode != http.StatusFound {
		t.Fatalf("pre-restart cookie before the first sync: status %d", resp.StatusCode)
	}
	if resp, _ := c.get("/x", ck(fresh)); resp.StatusCode != 200 {
		t.Fatalf("cookie issued after the start: status %d", resp.StatusCode)
	}
	f.mu.Lock()
	f.down = false
	f.mu.Unlock()
	deadline := time.Now().Add(3 * time.Second)
	for {
		resp, _ := c.get("/x", ck(old))
		if resp.StatusCode == 200 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("pre-restart cookie still refused after the list came back (status %d)", resp.StatusCode)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestUnverified(t *testing.T) {
	start := time.Now().Truncate(time.Second)
	p := &poller{started: start}
	if !p.unverified(start.Add(-time.Second)) || p.unverified(start) || p.unverified(start.Add(time.Minute)) {
		t.Fatal("before the first sync")
	}
	p.synced.Store(true)
	if p.unverified(start.Add(-time.Hour)) {
		t.Fatal("after the first sync")
	}
}

func TestRevokedBefore(t *testing.T) {
	p := &poller{}
	if p.revokedBefore("a@x.test", time.Unix(1, 0)) {
		t.Fatal("no list yet, but revoked")
	}
	m := map[string]int64{"a@x.test": 1000, "*": 500}
	p.before.Store(&m)
	for _, tc := range []struct {
		email string
		iat   int64
		want  bool
	}{
		{"a@x.test", 999, true},
		{"a@x.test", 1000, false},
		{"b@x.test", 499, true}, // everyone before 500
		{"b@x.test", 600, false},
	} {
		if got := p.revokedBefore(tc.email, time.Unix(tc.iat, 0)); got != tc.want {
			t.Errorf("revokedBefore(%s, %d) = %v, want %v", tc.email, tc.iat, got, tc.want)
		}
	}
}

// An app that protects only /admin/* (empty default list): no spelling of
// an admin path may pass through unauthenticated.
func TestEdgeAuthPathRuleBypass(t *testing.T) {
	f := newFixture(t)
	tester := caddytest.NewTester(t).WithDefaultOverrides(caddytest.Config{AdminPort: 2939})
	tester.InitServer(f.config(t, func(h map[string]any) {
		delete(h, "default")
		h["paths"] = []map[string]any{{"match": "/admin/*", "policies": []string{"members"}}}
	}), "json")
	c := client{t, &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
	for _, p := range []string{"/x", "/", "/admin", "/administrator", "/admin%20/x"} {
		if resp, _ := c.get(p, nil); resp.StatusCode != http.StatusOK {
			t.Errorf("%s: status %d, want 200 (public)", p, resp.StatusCode)
		}
	}
	for _, p := range []string{"/admin/x", "/ADMIN/x", "/Admin/", "/%61dmin/x", "//admin//x", "/x/%2e%2e/admin/x", "/x/.%2E/admin/x", "/./admin/x"} {
		if resp, _ := c.get(p, nil); resp.StatusCode != http.StatusFound {
			t.Errorf("%s: status %d, want 302 to the portal", p, resp.StatusCode)
		}
	}
	for _, p := range []string{"/admin%2fx", "/x/..%2Fadmin/x", "/admin%5cx", "/x/..;/admin/x", "/admin;a=b/x", "/admin%3bx", "/admin%00x", "/x/%252e%252e/admin/x", "/admin/%zz", "/admin\\x", "/x\\..\\admin\\x"} {
		// Sent verbatim: the client must not normalise or reject them.
		req, _ := http.NewRequest(http.MethodGet, "http://localhost:9381/", nil)
		req.URL.Opaque = p
		if resp, _ := c.do(req); resp.StatusCode != http.StatusBadRequest {
			t.Errorf("%s: status %d, want 400", p, resp.StatusCode)
		}
	}
}

// Shared vector with pkg/access (TestFlowNonceHashVector).
func TestNonceHashVector(t *testing.T) {
	if got := nonceHash("abc"); got != "ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0" {
		t.Fatalf("nonceHash = %s", got)
	}
}

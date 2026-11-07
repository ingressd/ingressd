// SPDX-License-Identifier: Apache-2.0

package edgechallenge

import (
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddytest"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"

	_ "github.com/caddyserver/caddy/v2/modules/standard"
)

const testKey = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"

func TestLeadingZeroBits(t *testing.T) {
	for _, tc := range []struct {
		b    []byte
		want int
	}{
		{[]byte{0x80}, 0}, {[]byte{0x01}, 7}, {[]byte{0, 0x0f}, 12}, {[]byte{0, 0}, 16},
	} {
		if got := LeadingZeroBits(tc.b); got != tc.want {
			t.Errorf("LeadingZeroBits(%x) = %d, want %d", tc.b, got, tc.want)
		}
	}
	n := Solve("tok", 10)
	h := sha256.Sum256([]byte("tok" + n))
	if LeadingZeroBits(h[:]) < 10 {
		t.Fatal("Solve returned an invalid nonce")
	}
}

func newTestChallenge() *Challenge {
	return &Challenge{Mode: ModeAlways, Difficulty: 8, key: make([]byte, 32), now: time.Now, CookieName: "c", TTL: 3600e9}
}

func TestTokens(t *testing.T) {
	c := newTestChallenge()
	tok := c.newToken("bind")
	if d, err := c.checkToken(tok, "bind"); err != nil || d != 8 {
		t.Fatalf("checkToken = %d, %v", d, err)
	}
	if _, err := c.checkToken(tok, "other"); err == nil {
		t.Fatal("token accepted for another binding")
	}
	if _, err := c.checkToken(strings.Replace(tok, ".8.", ".1.", 1), "bind"); err == nil {
		t.Fatal("token with lowered difficulty accepted")
	}
	c.now = func() time.Time { return time.Now().Add(time.Hour) }
	if _, err := c.checkToken(tok, "bind"); err == nil {
		t.Fatal("expired token accepted")
	}
}

func TestClearanceBinding(t *testing.T) {
	c := newTestChallenge()
	r, _ := http.NewRequest("GET", "http://web.example.test/", nil)
	r.RemoteAddr = "198.51.100.7:1234"
	r.Header.Set("User-Agent", "browser")
	ip := clientIP(r)
	v := c.clearance(binding(r, ip), time.Now().Add(time.Hour))
	r.AddCookie(&http.Cookie{Name: "c", Value: v})
	if !c.cleared(r, ip) {
		t.Fatal("valid cookie rejected")
	}
	// Same /24 still passes; another network or UA does not.
	r.RemoteAddr = "198.51.100.200:1"
	if !c.cleared(r, clientIP(r)) {
		t.Fatal("cookie rejected within the same /24")
	}
	r.RemoteAddr = "198.51.101.7:1"
	if c.cleared(r, clientIP(r)) {
		t.Fatal("cookie accepted from another network")
	}
	r.RemoteAddr = "198.51.100.7:1"
	r.Header.Set("User-Agent", "other")
	if c.cleared(r, clientIP(r)) {
		t.Fatal("cookie accepted with another user agent")
	}
	r.Header.Set("User-Agent", "browser")
	c.now = func() time.Time { return time.Now().Add(2 * time.Hour) }
	if c.cleared(r, clientIP(r)) {
		t.Fatal("expired cookie accepted")
	}
}

func TestSafeReturn(t *testing.T) {
	for in, want := range map[string]string{
		"/a?b=1": "/a?b=1", "//evil.com": "/", "https://evil.com": "/", "/\\evil.com": "/", "": "/",
	} {
		if got := safeReturn(in); got != want {
			t.Errorf("safeReturn(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCounter(t *testing.T) {
	s := newCounterSet()
	now := time.Now()
	for i := 0; i < 3; i++ {
		if s.hit("k", 3, time.Minute, now) {
			t.Fatalf("hit %d over limit", i+1)
		}
	}
	if !s.hit("k", 3, time.Minute, now) {
		t.Fatal("4th hit not over limit")
	}
	if s.hit("k", 3, time.Minute, now.Add(3*time.Minute)) {
		t.Fatal("counter did not reset")
	}
}

type fakeResolver map[string][]string

func (f fakeResolver) LookupAddr(_ context.Context, a string) ([]string, error) {
	if v, ok := f[a]; ok {
		return v, nil
	}
	return nil, errors.New("not found")
}

func (f fakeResolver) LookupHost(_ context.Context, h string) ([]string, error) {
	if v, ok := f[h]; ok {
		return v, nil
	}
	return nil, errors.New("not found")
}

func TestGoodBots(t *testing.T) {
	c := newTestChallenge()
	c.resolver = fakeResolver{
		"66.249.66.1":                     {"crawl-66-249-66-1.googlebot.com."},
		"crawl-66-249-66-1.googlebot.com": {"66.249.66.1"},
		"203.0.113.9":                     {"crawl-1.googlebot.com.evil.net."},
		"crawl-1.googlebot.com.evil.net":  {"203.0.113.9"},
		"203.0.113.10":                    {"fake.googlebot.com."},
		"fake.googlebot.com":              {"192.0.2.1"},
		"203.0.113.11":                    {"vm.bc.googleusercontent.com."},
		"vm.bc.googleusercontent.com":     {"203.0.113.11"},
	}
	ua := "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
	for ip, want := range map[string]bool{"66.249.66.1": true, "203.0.113.9": false, "203.0.113.10": false, "203.0.113.11": false} {
		if got := c.isGoodBot(context.Background(), netip.MustParseAddr(ip), ua); got != want {
			t.Errorf("isGoodBot(%s) = %v, want %v", ip, got, want)
		}
	}
	if c.isGoodBot(context.Background(), netip.MustParseAddr("66.249.66.1"), "curl/8") {
		t.Error("non-bot user agent accepted")
	}
}

const caddyConfig = `{
  "admin": {"listen": "localhost:2998"},
  "apps": {"http": {"http_port": 9180, "servers": {"s": {"listen": [":9180"], "routes": [
    {"match": [{"host": ["always.test"]}], "handle": [
      {"handler": "edge_challenge", "mode": "always", "difficulty": 8, "key": "` + testKey + `", "exempt_paths": ["/api/*"]},
      {"handler": "static_response", "body": "ok"}]},
    {"match": [{"host": ["suspicious.test"]}], "handle": [
      {"handler": "edge_challenge", "mode": "suspicious", "difficulty": 8, "key": "` + testKey + `"},
      {"handler": "static_response", "body": "ok"}]},
    {"match": [{"host": ["rate.test"]}], "handle": [
      {"handler": "edge_challenge", "mode": "off", "difficulty": 8, "key": "` + testKey + `",
       "rate_rules": [{"path": "/login", "requests": 2, "window": "1m"}]},
      {"handler": "static_response", "body": "ok"}]}
  ]}}}}
}`

var tokenRe = regexp.MustCompile(`name="token" value="([^"]+)"`)

func roundTrip(t *testing.T, req *http.Request) (*http.Response, string) {
	t.Helper()
	resp, err := http.DefaultTransport.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, string(b)
}

func get(t *testing.T, host, path string, hdr map[string]string, cookie *http.Cookie) (*http.Response, string) {
	t.Helper()
	req, _ := http.NewRequest("GET", "http://localhost:9180"+path, nil)
	req.Host = host
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	if cookie != nil {
		req.AddCookie(cookie)
	}
	return roundTrip(t, req)
}

func TestChallengeFlow(t *testing.T) {
	tester := caddytest.NewTester(t).WithDefaultOverrides(caddytest.Config{AdminPort: 2998})
	tester.InitServer(caddyConfig, "json")

	resp, body := get(t, "always.test", "/page?x=1", nil, nil)
	if resp.StatusCode != 403 || !strings.Contains(body, "<noscript>") {
		t.Fatalf("want challenge page, got %d: %.200s", resp.StatusCode, body)
	}
	m := tokenRe.FindStringSubmatch(body)
	if m == nil {
		t.Fatal("no token in challenge page")
	}
	tok := m[1]

	post := func(nonce string) *http.Response {
		form := url.Values{"token": {tok}, "nonce": {nonce}, "return": {"/page?x=1"}}
		req, _ := http.NewRequest("POST", "http://localhost:9180"+VerifyPath, strings.NewReader(form.Encode()))
		req.Host = "always.test"
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		resp, _ := roundTrip(t, req)
		return resp
	}
	if bad := "x1"; post(bad).StatusCode != 403 {
		t.Fatal("malformed nonce accepted")
	}
	resp = post(Solve(tok, 8))
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/page?x=1" {
		t.Fatalf("verify: %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	var ck *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == "__edge_clearance" {
			ck = c
		}
	}
	if ck == nil || !ck.HttpOnly {
		t.Fatalf("no HttpOnly clearance cookie: %v", resp.Cookies())
	}
	if resp, body := get(t, "always.test", "/page", nil, ck); resp.StatusCode != 200 || body != "ok" {
		t.Fatalf("with clearance: %d %q", resp.StatusCode, body)
	}
	// The cookie is bound to the host.
	if resp, _ := get(t, "suspicious.test", "/", nil, &http.Cookie{Name: ck.Name, Value: ck.Value}); resp.StatusCode != 403 {
		t.Fatalf("cookie accepted on another host: %d", resp.StatusCode)
	}
	if resp, _ := get(t, "always.test", "/api/x", nil, nil); resp.StatusCode != 200 {
		t.Fatalf("exempt path challenged: %d", resp.StatusCode)
	}

	browser := map[string]string{"User-Agent": "Mozilla/5.0", "Accept": "text/html", "Accept-Language": "en-GB"}
	if resp, _ := get(t, "suspicious.test", "/", browser, nil); resp.StatusCode != 200 {
		t.Fatalf("browser-like request challenged: %d", resp.StatusCode)
	}
	if resp, _ := get(t, "suspicious.test", "/", map[string]string{"User-Agent": "curl/8", "Accept": "*/*"}, nil); resp.StatusCode != 403 {
		t.Fatalf("curl-like request not challenged: %d", resp.StatusCode)
	}

	for i := 1; i <= 3; i++ {
		resp, _ := get(t, "rate.test", "/login", nil, nil)
		want := 200
		if i == 3 {
			want = 403
		}
		if resp.StatusCode != want {
			t.Fatalf("rate rule request %d: %d, want %d", i, resp.StatusCode, want)
		}
	}
	if resp, _ := get(t, "rate.test", "/other", nil, nil); resp.StatusCode != 200 {
		t.Fatalf("path outside rate rule challenged: %d", resp.StatusCode)
	}
}

// serve runs one request through c directly (no Caddy server), from addr.
func serve(t *testing.T, c *Challenge, addr, path string, ck *http.Cookie) int {
	t.Helper()
	r := httptest.NewRequest("GET", "http://rl.test"+path, nil)
	r.RemoteAddr = addr
	r.Header.Set("User-Agent", "browser")
	if ck != nil {
		r.AddCookie(ck)
	}
	r = r.WithContext(context.WithValue(r.Context(), caddy.ReplacerCtxKey, caddy.NewReplacer()))
	w := httptest.NewRecorder()
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) error { w.WriteHeader(200); return nil })
	if err := c.ServeHTTP(w, r, next); err != nil {
		t.Fatal(err)
	}
	return w.Code
}

func rateChallenge(t *testing.T, path string) *Challenge {
	t.Helper()
	c := newTestChallenge()
	c.Mode = ModeOff
	m := caddyhttp.MatchPath{path}
	c.rules = []compiledRule{{RateRule: RateRule{Path: path, Requests: 2, Window: caddy.Duration(time.Minute)}, match: m, id: t.Name()}}
	c.logger = zap.NewNop()
	return c
}

// A solved challenge must not switch rate rules off for the cookie's TTL.
func TestRateRulesApplyToClearedClients(t *testing.T) {
	c := rateChallenge(t, "/login")
	r := httptest.NewRequest("GET", "http://rl.test/login", nil)
	r.RemoteAddr = "198.51.100.7:1"
	r.Header.Set("User-Agent", "browser")
	ck := &http.Cookie{Name: "c", Value: c.clearance(binding(r, clientIP(r)), time.Now().Add(time.Hour))}
	for i, want := range []int{200, 200, 403, 403} {
		if got := serve(t, c, "198.51.100.7:1", "/login", ck); got != want {
			t.Fatalf("cleared request %d: %d, want %d", i+1, got, want)
		}
	}
	if got := serve(t, c, "198.51.100.7:1", "/other", ck); got != 200 {
		t.Fatalf("cleared request outside the rule: %d", got)
	}
}

// IPv6 clients are counted per /64, so rotating addresses does not help.
func TestRateRulesCountIPv6Per64(t *testing.T) {
	c := rateChallenge(t, "/login")
	for i, addr := range []string{"[2001:db8:1:2::1]:1", "[2001:db8:1:2::2]:1", "[2001:db8:1:2:ffff::3]:1"} {
		want := 200
		if i == 2 {
			want = 403
		}
		if got := serve(t, c, addr, "/login", nil); got != want {
			t.Fatalf("request %d from %s: %d, want %d", i+1, addr, got, want)
		}
	}
	if got := serve(t, c, "[2001:db8:1:3::1]:1", "/login", nil); got != 200 {
		t.Fatalf("another /64 shares the counter: %d", got)
	}
	// IPv4 stays per address.
	for _, addr := range []string{"192.0.2.1:1", "192.0.2.2:1", "192.0.2.3:1"} {
		if got := serve(t, c, addr, "/login", nil); got != 200 {
			t.Fatalf("%s: %d", addr, got)
		}
	}
}

func TestNetKey(t *testing.T) {
	for in, want := range map[string]string{
		"192.0.2.7":            "192.0.2.7",
		"2001:db8:1:2:3:4:5:6": "2001:db8:1:2::/64",
		"2001:db8:1:2::9":      "2001:db8:1:2::/64",
	} {
		if got := netKey(netip.MustParseAddr(in)); got != want {
			t.Errorf("netKey(%s) = %s, want %s", in, got, want)
		}
	}
}

func TestCounterBounded(t *testing.T) {
	defer func(n int) { maxCounters = n }(maxCounters)
	maxCounters = 3
	s := newCounterSet()
	now := time.Now()
	for _, k := range []string{"a", "b", "c"} {
		if s.hit(k, 5, time.Minute, now) {
			t.Fatalf("%s over limit", k)
		}
	}
	if !s.hit("d", 5, time.Minute, now) || len(s.m) != 3 {
		t.Fatalf("full set took a new key (%d counters)", len(s.m))
	}
	if s.hit("a", 5, time.Minute, now) {
		t.Fatal("existing counter affected by a full set")
	}
	// Once the others expire there is room again.
	later := now.Add(3 * time.Minute)
	if s.hit("d", 5, time.Minute, later.Add(2*time.Second)) || len(s.m) != 1 {
		t.Fatalf("expired counters not swept (%d)", len(s.m))
	}
	// Long keys are hashed.
	s.hit(strings.Repeat("x", 5000), 5, time.Minute, later)
	for k := range s.m {
		if len(k) > maxKeyLen {
			t.Fatalf("key of %d bytes stored", len(k))
		}
	}
}

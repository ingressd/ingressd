// SPDX-License-Identifier: Apache-2.0

package edgefallback

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2/caddytest"

	_ "github.com/caddyserver/caddy/v2/modules/standard"
)

// Ports unlikely to collide with other packages' caddytests running in parallel.
const (
	adminPort = 2919
	httpPort  = 9119
)

func writeSnapshot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	dir := filepath.Join(root, "20300101T000000Z")
	os.MkdirAll(filepath.Join(dir, "files"), 0o755)
	files := map[string]string{"files/index": "<html>snapshot home</html>", "files/css": "body{}", "files/docs": "<html>docs index</html>"}
	for name, body := range files {
		os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644)
	}
	m := manifest{ID: "20300101T000000Z", Entries: map[string]entry{
		"/":          {Status: 200, ContentType: "text/html; charset=utf-8", File: "files/index"},
		"/style.css": {Status: 200, ContentType: "text/css", File: "files/css"},
		"/docs/":     {Status: 200, ContentType: "text/html", File: "files/docs"},
		"/old":       {Status: 301, Location: "/"},
	}}
	b, _ := json.Marshal(m)
	os.WriteFile(filepath.Join(dir, "manifest.json"), b, 0o644)
	if err := os.Symlink("20300101T000000Z", filepath.Join(root, "latest")); err != nil {
		t.Fatal(err)
	}
	return root
}

func TestFallback(t *testing.T) {
	root := writeSnapshot(t)
	empty := t.TempDir()
	route := func(host, mode, dir, upstream string) string {
		return fmt.Sprintf(`{"match":[{"host":["%s"]}],"handle":[{"handler":"edge_fallback","root":%q,"mode":"%s"},%s],"terminal":true}`, host, dir, mode, upstream)
	}
	down := `{"handler":"reverse_proxy","upstreams":[{"dial":"127.0.0.1:1"}]}`
	live := `{"handler":"static_response","status_code":200,"body":"live"}`
	unavailable := `{"handler":"static_response","status_code":503,"body":"busy"}`
	routes := strings.Join([]string{
		route("down.test", "fallback", root, down),
		route("up.test", "fallback", root, live),
		route("busy.test", "fallback", root, unavailable),
		route("mirror.test", "static_mirror", root, live),
		route("nosnap.test", "fallback", empty, unavailable),
		route("nosnapmirror.test", "static_mirror", empty, live),
	}, ",")
	tester := caddytest.NewTester(t).WithDefaultOverrides(caddytest.Config{AdminPort: adminPort})
	tester.InitServer(fmt.Sprintf(`{
		"admin": {"listen": "localhost:%d"},
		"apps": {"http": {"http_port": %d, "servers": {"t": {"listen": [":%d"], "automatic_https": {"disable": true}, "routes": [%s]}}}}
	}`, adminPort, httpPort, httpPort, routes), "json")

	get := func(host, path string) (*http.Response, string) {
		t.Helper()
		req, _ := http.NewRequest("GET", fmt.Sprintf("http://localhost:%d%s", httpPort, path), nil)
		req.Host = host
		resp, err := (&http.Transport{}).RoundTrip(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp, string(b)
	}
	check := func(host, path string, status int, body, served, ctype string) {
		t.Helper()
		resp, got := get(host, path)
		if resp.StatusCode != status || !strings.Contains(got, body) {
			t.Errorf("%s%s: %d %q, want %d containing %q", host, path, resp.StatusCode, got, status, body)
		}
		if h := resp.Header.Get(ServedFromHeader); h != served {
			t.Errorf("%s%s: %s = %q, want %q", host, path, ServedFromHeader, h, served)
		}
		if ctype != "" && resp.Header.Get("Content-Type") != ctype {
			t.Errorf("%s%s: Content-Type = %q, want %q", host, path, resp.Header.Get("Content-Type"), ctype)
		}
	}

	check("down.test", "/", 200, "snapshot home", "snapshot", "text/html; charset=utf-8")
	check("down.test", "/style.css", 200, "body{}", "snapshot", "text/css")
	check("down.test", "/docs", 200, "docs index", "snapshot", "")
	check("down.test", "/missing", 404, "not in the cached copy", "snapshot", "")
	check("busy.test", "/", 200, "snapshot home", "snapshot", "")
	check("up.test", "/", 200, "live", "", "")
	check("mirror.test", "/", 200, "snapshot home", "snapshot", "")
	check("nosnap.test", "/", 503, "busy", "", "")
	check("nosnapmirror.test", "/", 200, "live", "", "")

	resp, _ := get("down.test", "/old")
	if resp.StatusCode != 301 || resp.Header.Get("Location") != "/" {
		t.Errorf("redirect entry: %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
}

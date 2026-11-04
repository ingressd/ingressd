// SPDX-License-Identifier: Apache-2.0

package crawler

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ingressd/ingressd/pkg/config"
)

func testSite(t *testing.T) *httptest.Server {
	t.Helper()
	pages := map[string]struct{ ctype, body string }{
		"/":                    {"text/html; charset=utf-8", `<html><head><link rel="stylesheet" href="/style.css"><link rel="alternate" href="/feed"></head><body><a href="about.html">About</a> <a href="https://elsewhere.example/x">ext</a> <a href="/private/secret.html">p</a> <a href="/old">old</a> <a href="/data.json">data</a><img srcset="/img/a.png 1x, /img/b.png 2x"></body></html>`},
		"/about.html":          {"text/html", `<html><body class="x"><p>About us</p><script src="/app.js"></script></body></html>`},
		"/style.css":           {"text/css", `body { background: url("/img/bg.png") } @import "/extra.css";`},
		"/extra.css":           {"text/css", `p{}`},
		"/img/a.png":           {"image/png", "PNG-A"},
		"/img/b.png":           {"image/png", "PNG-B"},
		"/img/bg.png":          {"image/png", "PNG-BG"},
		"/app.js":              {"text/javascript", "console.log(1)"},
		"/hidden.html":         {"text/html", "<html><body>only in sitemap</body></html>"},
		"/new":                 {"text/html", "<html><body>new</body></html>"},
		"/data.json":           {"application/json", "{}"},
		"/private/secret.html": {"text/html", "secret"},
		"/robots.txt":          {"text/plain", "User-agent: *\nDisallow: /private/\n"},
		"/sitemap.xml":         {"application/xml", `<?xml version="1.0"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><url><loc>http://site.example.test/hidden.html</loc></url><url><loc>http://other.example/nope</loc></url></urlset>`},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != "site.example.test" {
			http.Error(w, "wrong host "+r.Host, 400)
			return
		}
		if r.URL.Path == "/old" {
			http.Redirect(w, r, "/new", http.StatusMovedPermanently)
			return
		}
		p, ok := pages[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", p.ctype)
		fmt.Fprint(w, p.body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func testConfig(t *testing.T, origin, extra string) *config.Config {
	t.Helper()
	cfg, err := config.Parse([]byte(fmt.Sprintf(`
version: 1
edge: { acme: { ca: internal } }
apps:
  site:
    hosts: [site.example.test]
    origin: %s
    always_online: { enabled: true, banner: true%s }
`, origin, extra)))
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	return cfg
}

func TestSnapshot(t *testing.T) {
	srv := testSite(t)
	state := t.TempDir()
	cfg := testConfig(t, srv.URL, ", crawl: { keep: 2 }")

	res, err := Snapshot(context.Background(), cfg, "site", state, Options{})
	if err != nil {
		t.Fatal(err)
	}
	m, err := Latest(filepath.Join(state, "snapshots", "site"))
	if err != nil {
		t.Fatal(err)
	}
	if m.ID != res.ID {
		t.Fatalf("latest = %s, want %s", m.ID, res.ID)
	}
	for _, want := range []string{"/", "/about.html", "/style.css", "/extra.css", "/img/a.png", "/img/b.png", "/img/bg.png", "/app.js", "/hidden.html", "/old", "/new"} {
		if _, ok := m.Entries[want]; !ok {
			t.Errorf("missing %s", want)
		}
	}
	for _, unwanted := range []string{"/private/secret.html", "/data.json", "/feed", "/nope", "/x"} {
		if _, ok := m.Entries[unwanted]; ok {
			t.Errorf("unexpected %s", unwanted)
		}
	}
	if e := m.Entries["/old"]; e.Status != 301 || e.Location != "/new" {
		t.Errorf("redirect entry = %+v", e)
	}
	if e := m.Entries["/style.css"]; e.ContentType != "text/css" {
		t.Errorf("css content type = %q", e.ContentType)
	}
	about, _ := os.ReadFile(filepath.Join(res.Dir, m.Entries["/about.html"].File))
	if !strings.Contains(string(about), `<body class="x"><div data-edge-banner`) || !strings.Contains(string(about), BannerText) {
		t.Errorf("banner not injected after <body>: %s", about)
	}
	png, _ := os.ReadFile(filepath.Join(res.Dir, m.Entries["/img/bg.png"].File))
	if string(png) != "PNG-BG" {
		t.Errorf("image body = %q", png)
	}

	// keep: 2 prunes the oldest; latest always points at the newest.
	tick := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < 2; i++ {
		tick = tick.Add(time.Hour)
		now := tick
		if _, err := Snapshot(context.Background(), cfg, "site", state, Options{Now: func() time.Time { return now }}); err != nil {
			t.Fatal(err)
		}
	}
	list, err := List(filepath.Join(state, "snapshots", "site"))
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 || !list[1].Latest || list[1].ID != "20300101T020000Z" {
		t.Fatalf("snapshots after pruning = %+v", list)
	}
}

func TestSnapshotLimitsAndMirrorBanner(t *testing.T) {
	srv := testSite(t)
	state := t.TempDir()
	cfg := testConfig(t, srv.URL, ", mode: static_mirror, crawl: { max_pages: 3 }")
	res, err := Snapshot(context.Background(), cfg, "site", state, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if res.Pages != 3 || !res.Truncated {
		t.Fatalf("pages=%d truncated=%v, want 3 and true", res.Pages, res.Truncated)
	}
	m, _ := Latest(filepath.Join(state, "snapshots", "site"))
	index, _ := os.ReadFile(filepath.Join(res.Dir, m.Entries["/"].File))
	if strings.Contains(string(index), "data-edge-banner") {
		t.Error("static_mirror snapshots must not carry the offline banner")
	}
}

func TestSnapshotRefusesProtectedOrUnreachable(t *testing.T) {
	cfg := testConfig(t, "http://127.0.0.1:1", "")
	if _, err := Snapshot(context.Background(), cfg, "site", t.TempDir(), Options{}); err == nil || !strings.Contains(err.Error(), "reachable") {
		t.Fatalf("unreachable origin: err = %v", err)
	}
}

func TestRobots(t *testing.T) {
	r := parseRobots("User-agent: Googlebot\nDisallow: /\n\nUser-agent: *\nDisallow: /a/\nAllow: /a/ok\nSitemap: http://x/s.xml\n")
	for path, want := range map[string]bool{"/": true, "/a/": false, "/a/x": false, "/a/ok.html": true, "/b": true} {
		if got := r.allowed(path); got != want {
			t.Errorf("allowed(%s) = %v, want %v", path, got, want)
		}
	}
	if len(r.sitemaps) != 1 {
		t.Errorf("sitemaps = %v", r.sitemaps)
	}
	if parseRobots("User-agent: ingressd\nDisallow: /\nUser-agent: *\nAllow: /\n").allowed("/x") {
		t.Error("ingressd-specific group ignored")
	}
}

func TestDue(t *testing.T) {
	at := func(h, m int) time.Time { return time.Date(2030, 5, 1, h, m, 0, 0, time.Local) }
	if !Due("0 4 * * *", at(4, 0)) || Due("0 4 * * *", at(4, 1)) || !Due("*/15 * * * *", at(9, 45)) {
		t.Error("Due mismatch")
	}
	if Due("bogus", at(4, 0)) {
		t.Error("invalid schedule is due")
	}
}

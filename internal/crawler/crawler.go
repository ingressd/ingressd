// SPDX-License-Identifier: Apache-2.0

// Package crawler takes Always Online snapshots of public apps (DESIGN.md
// §12.2). It fetches pages straight from the app's origins over the tunnel
// (the dial addresses the edge proxy uses), never through the public edge,
// and stores them for edge_fallback to serve when the origin is down.
package crawler

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/ingressd/ingressd/internal/render"
	"github.com/ingressd/ingressd/pkg/config"
)

// UserAgent identifies the crawler; robots.txt rules for "ingressd" or "*" apply.
const UserAgent = "ingressd-snapshot/1 (Always Online)"

// BannerText is injected into snapshot HTML when always_online.banner is set.
const BannerText = "You're viewing a cached copy; the site is temporarily offline."

// Options tune a crawl. Zero values are fine.
type Options struct {
	// Timeout per request. Default 15s.
	Timeout time.Duration
	// Now returns the snapshot time (tests).
	Now func() time.Time
}

// Result describes a finished snapshot.
type Result struct {
	ID        string
	Dir       string
	Origin    string // origin name used
	Pages     int
	Bytes     int64
	Truncated bool
}

// Snapshot crawls one app and stores a new snapshot under
// <stateDir>/snapshots/<app>, making it the latest.
func Snapshot(ctx context.Context, cfg *config.Config, appName, stateDir string, opts Options) (*Result, error) {
	app, ok := cfg.Apps[appName]
	if !ok {
		return nil, fmt.Errorf("unknown app %q", appName)
	}
	if !app.AlwaysOnlineEnabled() {
		return nil, fmt.Errorf("app %q does not have always_online enabled", appName)
	}
	if !cfg.IsPublicApp(app) {
		return nil, fmt.Errorf("app %q is not public; refusing to snapshot it", appName)
	}
	ao := app.AlwaysOnline
	maxBytes, err := config.ParseSize(ao.Crawl.MaxBytes)
	if err != nil {
		return nil, err
	}
	targets, err := render.OriginTargets(cfg, app)
	if err != nil {
		return nil, err
	}
	if len(targets) == 0 {
		return nil, fmt.Errorf("app %q has no active origin", appName)
	}
	var hosts []string
	for _, h := range app.Hosts {
		if !strings.HasPrefix(h, "*.") {
			hosts = append(hosts, h)
		}
	}
	if len(hosts) == 0 {
		return nil, fmt.Errorf("app %q has no non-wildcard host to crawl", appName)
	}
	if opts.Timeout == 0 {
		opts.Timeout = 15 * time.Second
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}

	dir := render.SnapshotDir(stateDir, appName)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	unlock, err := lock(dir)
	if err != nil {
		return nil, err
	}
	defer unlock()
	cleanTmp(dir)

	c := &crawl{
		ctx:      ctx,
		hosts:    hosts,
		maxPages: ao.Crawl.MaxPages,
		maxBytes: maxBytes,
		banner:   ao.Banner && ao.Mode == config.AlwaysOnlineFallback,
		seen:     map[string]bool{},
	}
	// Use the first origin that answers.
	var lastErr error
	for _, t := range targets {
		c.base = &url.URL{Scheme: t.Scheme, Host: hosts[0]}
		c.client = originClient(t, hosts[0], opts.Timeout)
		if lastErr = c.probe(); lastErr == nil {
			c.origin = t.Name
			break
		}
	}
	if c.origin == "" {
		return nil, fmt.Errorf("no origin of app %q is reachable: %w", appName, lastErr)
	}

	now := opts.Now()
	id := newID(dir, now)
	c.tmp = filepath.Join(dir, ".tmp-"+id)
	if err := os.MkdirAll(filepath.Join(c.tmp, FilesDir), 0o755); err != nil {
		return nil, err
	}
	defer os.RemoveAll(c.tmp) // no-op once published
	c.man = Manifest{ID: id, App: appName, Host: hosts[0], Created: now.UTC(), Entries: map[string]Entry{}}

	if err := c.run(ao.Crawl.Start); err != nil {
		return nil, err
	}
	if len(c.man.Entries) == 0 {
		return nil, fmt.Errorf("nothing to snapshot: no start page of app %q could be fetched", appName)
	}
	b, err := json.MarshalIndent(c.man, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(c.tmp, ManifestFile), b, 0o644); err != nil {
		return nil, err
	}
	if err := publish(dir, c.tmp, id, ao.Crawl.Keep); err != nil {
		return nil, err
	}
	return &Result{ID: id, Dir: filepath.Join(dir, id), Origin: c.origin, Pages: c.man.Pages, Bytes: c.man.Bytes, Truncated: c.man.Truncated}, nil
}

// originClient dials the origin's tunnel address whatever the URL host is,
// so requests carry the app's public Host (and SNI) but never leave via the
// public edge. Redirects are recorded, not followed.
func originClient(t render.OriginTarget, host string, timeout time.Duration) *http.Client {
	d := &net.Dialer{Timeout: 5 * time.Second}
	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return d.DialContext(ctx, network, t.Dial)
		},
		// Like the edge proxy until origin TLS modes land: encrypted, unverified.
		TLSClientConfig:     &tls.Config{ServerName: host, InsecureSkipVerify: true}, //nolint:gosec
		DisableCompression:  false,
		MaxIdleConnsPerHost: 4,
	}
	return &http.Client{
		Transport:     tr,
		Timeout:       timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

type crawl struct {
	ctx      context.Context
	client   *http.Client
	base     *url.URL
	hosts    []string
	origin   string
	maxPages int
	maxBytes int64
	banner   bool
	robots   robots
	tmp      string
	man      Manifest
	seen     map[string]bool
	queue    []string
}

// probe fetches robots.txt, which also proves the origin is reachable.
func (c *crawl) probe() error {
	resp, err := c.get("/robots.txt")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	c.robots = robots{}
	if resp.StatusCode == http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512<<10))
		c.robots = parseRobots(string(b))
	}
	return nil
}

func (c *crawl) get(ref string) (*http.Response, error) {
	u, err := c.base.Parse(ref)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(c.ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", UserAgent)
	return c.client.Do(req)
}

func (c *crawl) run(start []string) error {
	for _, s := range start {
		c.enqueue(c.base.String(), s)
	}
	// sitemap.xml (and any listed in robots.txt) only feed the queue.
	for _, sm := range append([]string{"/sitemap.xml"}, c.robots.sitemaps...) {
		c.readSitemap(sm, 0)
	}
	for len(c.queue) > 0 {
		if err := c.ctx.Err(); err != nil {
			return err
		}
		if c.maxPages > 0 && c.man.Pages >= c.maxPages {
			c.man.Truncated = true
			break
		}
		key := c.queue[0]
		c.queue = c.queue[1:]
		if stop := c.fetch(key); stop {
			break
		}
	}
	return nil
}

// enqueue adds a link (resolved against page) if it is same-host, allowed by
// robots.txt and new. It returns the key ("/path?query").
func (c *crawl) enqueue(page, ref string) {
	key, ok := c.key(page, ref)
	if !ok || c.seen[key] {
		return
	}
	c.seen[key] = true
	if !c.robots.allowed(key) {
		return
	}
	c.queue = append(c.queue, key)
}

func (c *crawl) key(page, ref string) (string, bool) {
	ref = strings.TrimSpace(ref)
	if ref == "" || strings.HasPrefix(ref, "#") {
		return "", false
	}
	pu, err := url.Parse(page)
	if err != nil {
		return "", false
	}
	u, err := pu.Parse(ref)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return "", false
	}
	if !c.sameHost(u.Hostname()) {
		return "", false
	}
	k := u.EscapedPath()
	if k == "" {
		k = "/"
	}
	if u.RawQuery != "" {
		k += "?" + u.RawQuery
	}
	return k, true
}

func (c *crawl) sameHost(h string) bool {
	for _, x := range c.hosts {
		if strings.EqualFold(h, x) {
			return true
		}
	}
	return false
}

func (c *crawl) readSitemap(ref string, depth int) {
	if depth > 2 {
		return
	}
	key, ok := c.key(c.base.String(), ref)
	if !ok {
		return
	}
	resp, err := c.get(key)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 10<<20))
	locs, index := parseSitemap(b)
	for _, l := range locs {
		if index {
			c.readSitemap(l, depth+1)
		} else {
			c.enqueue(c.base.String(), l)
		}
	}
}

// fetch downloads one URL and stores it. It returns true when the size
// budget is exhausted and the crawl must stop.
func (c *crawl) fetch(key string) (stop bool) {
	resp, err := c.get(key)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	pageURL := c.base.String() + key

	switch resp.StatusCode {
	case http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther, http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
		loc := resp.Header.Get("Location")
		target, ok := c.key(pageURL, loc)
		if !ok {
			return false
		}
		c.man.Entries[key] = Entry{Status: resp.StatusCode, Location: target}
		c.man.Pages++
		c.enqueue(pageURL, target)
		return false
	case http.StatusOK:
	default:
		return false
	}

	ctype := resp.Header.Get("Content-Type")
	kind := classify(ctype)
	if kind == kindOther {
		return false
	}
	remaining := c.maxBytes - c.man.Bytes
	body, err := io.ReadAll(io.LimitReader(resp.Body, remaining+1))
	if err != nil {
		return false
	}
	if int64(len(body)) > remaining {
		c.man.Truncated = true
		return true
	}

	switch kind {
	case kindHTML:
		for _, l := range htmlLinks(body) {
			c.enqueue(pageURL, l)
		}
		if c.banner {
			body = injectBanner(body)
		}
	case kindCSS:
		for _, l := range cssLinks(string(body)) {
			c.enqueue(pageURL, l)
		}
	}

	sum := sha256.Sum256([]byte(key))
	file := filepath.ToSlash(filepath.Join(FilesDir, hex.EncodeToString(sum[:16])))
	if err := os.WriteFile(filepath.Join(c.tmp, file), body, 0o644); err != nil {
		return false
	}
	c.man.Entries[key] = Entry{Status: http.StatusOK, ContentType: ctype, File: file}
	c.man.Pages++
	c.man.Bytes += int64(len(body))
	return false
}

type kind int

const (
	kindOther kind = iota
	kindHTML
	kindCSS
	kindAsset
)

// classify keeps HTML, CSS, JS, images and fonts.
func classify(ctype string) kind {
	mt, _, err := mime.ParseMediaType(ctype)
	if err != nil {
		return kindOther
	}
	switch {
	case mt == "text/html" || mt == "application/xhtml+xml":
		return kindHTML
	case mt == "text/css":
		return kindCSS
	case mt == "text/javascript", mt == "application/javascript", mt == "application/x-javascript",
		strings.HasPrefix(mt, "image/"), strings.HasPrefix(mt, "font/"),
		strings.HasPrefix(mt, "application/font-"), strings.HasPrefix(mt, "application/x-font-"),
		mt == "application/vnd.ms-fontobject":
		return kindAsset
	}
	return kindOther
}

var bodyTagRe = regexp.MustCompile(`(?is)<body\b[^>]*>`)

// bannerHTML is self-contained so it renders without the site's CSS.
const bannerHTML = `<div data-edge-banner style="position:sticky;top:0;z-index:2147483647;margin:0;padding:8px 12px;background:#fff3cd;color:#664d03;border-bottom:1px solid #ffe69c;font:14px/1.4 system-ui,sans-serif;text-align:center">` + BannerText + `</div>`

func injectBanner(body []byte) []byte {
	if loc := bodyTagRe.FindIndex(body); loc != nil {
		out := make([]byte, 0, len(body)+len(bannerHTML))
		out = append(out, body[:loc[1]]...)
		out = append(out, bannerHTML...)
		return append(out, body[loc[1]:]...)
	}
	return append([]byte(bannerHTML), body...)
}

// ErrNoSnapshot is returned by Latest when an app has no snapshot yet.
var ErrNoSnapshot = errors.New("no snapshot yet")

// Latest returns the manifest the latest pointer refers to.
func Latest(dir string) (*Manifest, error) {
	id, err := os.Readlink(filepath.Join(dir, LatestLink))
	if err != nil {
		return nil, ErrNoSnapshot
	}
	return ReadManifest(filepath.Join(dir, id))
}

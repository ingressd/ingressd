// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"
	"net/textproto"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/robfig/cron/v3"
)

// Always Online modes.
const (
	AlwaysOnlineFallback     = "fallback"      // serve the snapshot only when the origin fails
	AlwaysOnlineStaticMirror = "static_mirror" // always serve the snapshot (zero origin load)
)

// MaxStaleIfError caps cache.stale_if_error. The edge keeps expired cache
// entries this long for every app (one shared store), and serves them for an
// app's own stale_if_error window when its origin fails.
const MaxStaleIfError = 7 * 24 * time.Hour

// Cache is an app's response cache (DESIGN.md §12.1).
type Cache struct {
	Enabled bool `yaml:"enabled"`
	// DefaultTTL applies when the origin sends no max-age/s-maxage. Default 5m.
	DefaultTTL Duration `yaml:"default_ttl"`
	// StaleIfError serves an expired entry this long after expiry when the
	// origin is down. 0 disables it. Default 1h.
	StaleIfError *Duration `yaml:"stale_if_error"`
	// BypassPaths are path prefixes that are never cached (e.g. /api/).
	BypassPaths []string `yaml:"bypass_paths"`
	// Vary lists request headers that are part of the cache key.
	// Default [Accept-Encoding]. Cookies are never part of the key.
	Vary []string `yaml:"vary"`
}

// AlwaysOnline serves crawled snapshots of an app when its origin is down
// (DESIGN.md §12.2).
type AlwaysOnline struct {
	Enabled bool   `yaml:"enabled"`
	Mode    string `yaml:"mode"` // fallback (default) | static_mirror
	Crawl   Crawl  `yaml:"crawl"`
	// Banner injects a "cached copy" notice into snapshot HTML (fallback mode).
	Banner bool `yaml:"banner"`
}

type Crawl struct {
	Schedule string   `yaml:"schedule"`  // cron, default "0 4 * * *"
	Start    []string `yaml:"start"`     // start paths, default [/]; sitemap.xml is always read
	MaxPages int      `yaml:"max_pages"` // URLs fetched per snapshot, default 1000
	MaxBytes string   `yaml:"max_bytes"` // total snapshot size, default 256MB
	Keep     int      `yaml:"keep"`      // snapshots kept, default 3
}

// IsPublicApp reports whether every page of an app is reachable without
// login, which Always Online requires (a snapshot must never leak protected
// pages). That holds when the app and each of its path rules either have no
// policies or start with an unconditional bypass: policies are first-match,
// so nothing after it can ever apply.
func (c *Config) IsPublicApp(a App) bool {
	lists := [][]string{a.Access}
	for _, p := range a.Paths {
		lists = append(lists, p.Access)
	}
	for _, l := range lists {
		if len(l) > 0 && !c.openPolicy(l[0]) {
			return false
		}
	}
	return true
}

// openPolicy reports whether a policy bypasses login for everyone.
func (c *Config) openPolicy(name string) bool {
	p, ok := c.Policies[name]
	if !ok || p.Action != "bypass" || len(p.Require) > 0 || len(p.Exclude) > 0 {
		return false
	}
	return slices.ContainsFunc(p.Include, func(s Selector) bool { return s.Everyone })
}

// CacheEnabled reports whether the app has caching on.
func (a App) CacheEnabled() bool { return a.Cache != nil && a.Cache.Enabled }

// AlwaysOnlineEnabled reports whether the app has Always Online on.
func (a App) AlwaysOnlineEnabled() bool { return a.AlwaysOnline != nil && a.AlwaysOnline.Enabled }

func (c *Config) applyCacheDefaults() {
	for name, a := range c.Apps {
		if ch := a.Cache; ch != nil {
			if ch.DefaultTTL == 0 {
				ch.DefaultTTL = Duration(5 * time.Minute)
			}
			if ch.StaleIfError == nil {
				d := Duration(time.Hour)
				ch.StaleIfError = &d
			}
			if ch.Vary == nil {
				ch.Vary = []string{"Accept-Encoding"}
			}
		}
		if ao := a.AlwaysOnline; ao != nil {
			if ao.Mode == "" {
				ao.Mode = AlwaysOnlineFallback
			}
			cr := &ao.Crawl
			if cr.Schedule == "" {
				cr.Schedule = "0 4 * * *"
			}
			if len(cr.Start) == 0 {
				cr.Start = []string{"/"}
			}
			if cr.MaxPages == 0 {
				cr.MaxPages = 1000
			}
			if cr.MaxBytes == "" {
				cr.MaxBytes = "256MB"
			}
			if cr.Keep == 0 {
				cr.Keep = 3
			}
		}
		c.Apps[name] = a
	}
}

func (c *Config) validateCache(v *validator) {
	for _, name := range sortedKeys(c.Apps) {
		a := c.Apps[name]
		p := "apps." + name
		if ch := a.Cache; ch != nil {
			cp := p + ".cache"
			if ch.DefaultTTL < 0 {
				v.add(cp+".default_ttl", "must not be negative")
			}
			if s := ch.StaleIfError; s != nil && (*s < 0 || time.Duration(*s) > MaxStaleIfError) {
				v.add(cp+".stale_if_error", "must be between 0 and %s", FormatDuration(MaxStaleIfError))
			}
			for i, bp := range ch.BypassPaths {
				if !strings.HasPrefix(bp, "/") {
					v.add(fmt.Sprintf("%s.bypass_paths[%d]", cp, i), "must start with /, got %q", bp)
				}
			}
			for i, h := range ch.Vary {
				if h == "" || textproto.CanonicalMIMEHeaderKey(h) == "" || strings.ContainsAny(h, " :\t") || strings.EqualFold(h, "Cookie") {
					v.add(fmt.Sprintf("%s.vary[%d]", cp, i), "invalid header name %q (cookies are never part of the key)", h)
				}
			}
		}
		ao := a.AlwaysOnline
		if ao == nil {
			continue
		}
		ap := p + ".always_online"
		if ao.Enabled && !c.IsPublicApp(a) {
			v.add(ap, "only allowed for public apps (no policies, or a bypass-everyone policy first); snapshots would leak protected pages")
		}
		switch ao.Mode {
		case AlwaysOnlineFallback, AlwaysOnlineStaticMirror:
		default:
			v.add(ap+".mode", "must be fallback or static_mirror, got %q", ao.Mode)
		}
		if _, err := cron.ParseStandard(ao.Crawl.Schedule); err != nil {
			v.add(ap+".crawl.schedule", "invalid cron expression %q: %v", ao.Crawl.Schedule, err)
		}
		for i, s := range ao.Crawl.Start {
			if !strings.HasPrefix(s, "/") {
				v.add(fmt.Sprintf("%s.crawl.start[%d]", ap, i), "must be a path starting with /, got %q", s)
			}
		}
		if ao.Crawl.MaxPages < 0 {
			v.add(ap+".crawl.max_pages", "must not be negative")
		}
		if _, err := ParseSize(ao.Crawl.MaxBytes); err != nil {
			v.add(ap+".crawl.max_bytes", "%v", err)
		}
		if ao.Crawl.Keep < 1 {
			v.add(ap+".crawl.keep", "must be at least 1")
		}
		if ao.Enabled && !hasExactHost(a.Hosts) {
			v.add(ap, "needs at least one non-wildcard host to crawl")
		}
	}
}

func hasExactHost(hosts []string) bool {
	for _, h := range hosts {
		if !strings.HasPrefix(h, "*.") {
			return true
		}
	}
	return false
}

// ParseDuration is time.ParseDuration plus a "d" (24h) unit, e.g. "7d" or "1d12h".
func ParseDuration(s string) (time.Duration, error) {
	if i := strings.IndexByte(s, 'd'); i > 0 {
		days, err := strconv.Atoi(s[:i])
		if err != nil || days < 0 {
			return 0, fmt.Errorf("invalid duration %q", s)
		}
		d := time.Duration(days) * 24 * time.Hour
		if rest := s[i+1:]; rest != "" {
			r, err := time.ParseDuration(rest)
			if err != nil {
				return 0, fmt.Errorf("invalid duration %q", s)
			}
			d += r
		}
		return d, nil
	}
	return time.ParseDuration(s)
}

// FormatDuration prints whole days as "7d" and anything else like time.Duration.
func FormatDuration(d time.Duration) string {
	day := 24 * time.Hour
	if d >= day && d%day == 0 {
		return strconv.Itoa(int(d/day)) + "d"
	}
	return d.String()
}

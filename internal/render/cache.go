// SPDX-License-Identifier: Apache-2.0

package render

import (
	"fmt"
	"path/filepath"
	"time"

	"github.com/ingressd/ingressd/pkg/config"
)

// Response caching (cache-handler/Souin) and Always Online serving
// (edge_fallback), DESIGN.md §12. Per-app request chain, innermost last:
//
//	… security → edge_fallback → [bypass?] cache → proxy
//
// edge_fallback sits outside the cache so a failing origin is answered first
// by a stale cache entry (stale-if-error) and only then by the snapshot.

// CacheName is the name in Cache-Status response headers.
const CacheName = "ingressd"

// SnapshotDir is where Always Online snapshots of an app are stored. The
// crawler writes it and edge_fallback reads it.
func SnapshotDir(stateDir, app string) string {
	return filepath.Join(stateDir, "snapshots", app)
}

// CacheDir holds the shared on-disk cache store (Badger).
func CacheDir(stateDir string) string { return filepath.Join(stateDir, "cache") }

// sessionCookieRe matches Cookie headers that carry a likely session or
// auth cookie; such requests bypass the cache. Other cookies (analytics,
// preferences) do not prevent caching, and cookies are never in the key.
const sessionCookieRe = `(?i)(^|;\s*)[^=;]*(sess|auth|token|login|jwt|sid|remember)[^=;]*=`

// withCacheAndFallback wraps the app's final (proxy) handler with the cache
// and the Always Online fallback.
func withCacheAndFallback(name string, app config.App, opts Options, hs []obj) []obj {
	if len(hs) == 0 || (!app.CacheEnabled() && !app.AlwaysOnlineEnabled()) {
		return hs
	}
	head, proxy := hs[:len(hs)-1:len(hs)-1], hs[len(hs)-1]
	if app.CacheEnabled() {
		proxy = cacheSubroute(app.Cache, opts, proxy)
	}
	if ao := app.AlwaysOnline; app.AlwaysOnlineEnabled() {
		head = append(head, obj{
			"handler": "edge_fallback",
			"root":    SnapshotDir(opts.StateDir, name),
			"mode":    ao.Mode,
		})
	}
	return append(head, proxy)
}

// cacheSubroute runs the cache in front of proxy unless the request must
// bypass it (Authorization, session cookies, bypass_paths).
func cacheSubroute(c *config.Cache, opts Options, proxy obj) obj {
	bypass := []obj{
		{"header": obj{"Authorization": []string{}}},
		{"header_regexp": obj{"Cookie": obj{"pattern": sessionCookieRe}}},
	}
	if len(c.BypassPaths) > 0 {
		var paths []string
		for _, p := range c.BypassPaths {
			paths = append(paths, p+"*")
		}
		bypass = append(bypass, obj{"path": paths})
	}

	var cached []obj
	if s := time.Duration(*c.StaleIfError); s > 0 {
		// Souin serves a stale entry on upstream errors only when the request
		// or the stored response allows it; add the app's window to every
		// request (client directives are kept: "add", not "set").
		cached = append(cached, obj{"handler": "headers", "request": obj{
			"add": obj{"Cache-Control": []string{fmt.Sprintf("stale-if-error=%d", int(s.Seconds()))}},
		}})
	}
	// cache-handler reads per-handler settings only from Configuration.DefaultCache
	// (its top-level JSON fields are ignored once the global app is merged in).
	dc := obj{
		"cache_name":         CacheName,
		"ttl":                time.Duration(c.DefaultTTL).String(),
		"stale":              config.MaxStaleIfError.String(),
		"allowed_http_verbs": []string{"GET", "HEAD"},
		"badger":             badgerStore(opts),
	}
	if len(c.Vary) > 0 {
		dc["key"] = obj{"headers": c.Vary}
	}
	h := obj{"handler": "cache", "Configuration": obj{"DefaultCache": dc}}
	cached = append(cached, h,
		// Souin would store responses that set cookies; mark them private
		// (inside the cache, so it sees the header) so sessions never leak.
		obj{"handler": "headers", "response": obj{
			"require":  obj{"headers": obj{"Set-Cookie": []string{}}},
			"add":      obj{"Cache-Control": []string{"private"}},
			"deferred": true,
		}},
	)
	return obj{"handler": "subroute", "routes": []obj{
		{"match": []obj{{"not": bypass}}, "handle": cached},
		{"handle": []obj{proxy}},
	}}
}

// badgerStore is the single on-disk store every app's cache handler shares.
// Its settings (including "stale") must be identical across handlers: Souin
// opens one Badger instance per (dir, stale) and a second one on the same
// directory would fail to lock it.
func badgerStore(opts Options) obj {
	dir := CacheDir(opts.StateDir)
	return obj{
		"found": true,
		"path":  dir,
		"configuration": obj{
			"Dir":              dir,
			"ValueDir":         dir,
			"MemTableSize":     16 << 20,
			"ValueLogFileSize": 64 << 20,
			"BlockCacheSize":   32 << 20,
		},
	}
}

// renderCacheApp configures the global cache app when any app caches. Its
// purge API is served only on Caddy's admin socket (admin.api.souin), never
// on the public listener: handlers get no "api" config.
func renderCacheApp(cfg *config.Config) obj {
	for _, a := range cfg.Apps {
		if a.CacheEnabled() {
			return obj{"api": obj{"souin": obj{"enable": true}}}
		}
	}
	return nil
}

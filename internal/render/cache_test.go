// SPDX-License-Identifier: Apache-2.0

package render

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestCacheAndFallbackChain(t *testing.T) {
	p := renderTest(t)
	var root struct {
		Apps map[string]json.RawMessage `json:"apps"`
	}
	if err := json.Unmarshal(p.Caddy, &root); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(root.Apps["cache"]), `"enable": true`) {
		t.Errorf("cache app missing purge API: %s", root.Apps["cache"])
	}
	s := string(p.Caddy)
	// edge_fallback must wrap the cache, which must wrap the proxy.
	fb := strings.Index(s, `"handler": "edge_fallback"`)
	ch := strings.Index(s, `"handler": "cache"`)
	rp := strings.Index(s[ch:], `"handler": "reverse_proxy"`)
	if fb < 0 || ch < fb || rp < 0 {
		t.Fatalf("want edge_fallback → cache → reverse_proxy, got offsets %d %d %d", fb, ch, rp)
	}
	for _, want := range []string{
		`"root": "/var/lib/ingressd/snapshots/site"`,
		`"path": "/var/lib/ingressd/cache"`,
		`"stale-if-error=604800"`,
		`"ttl": "10m0s"`,
		`"/api/*"`,
		`"Authorization": []`,
		`"Set-Cookie": []`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("caddy config missing %s", want)
		}
	}
	// Apps without cache/always_online are untouched.
	if strings.Count(s, `"handler": "edge_fallback"`) != 1 || strings.Count(s, `"handler": "cache"`) != 1 {
		t.Error("cache/fallback rendered for apps that do not enable them")
	}
	// The purge API must never be configured on a public handler.
	if strings.Count(s, `"api"`) != 1 {
		t.Error(`"api" appears outside the global cache app`)
	}
}

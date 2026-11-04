// SPDX-License-Identifier: Apache-2.0

package config

import (
	"strings"
	"testing"
	"time"
)

func TestCacheDefaultsAndDays(t *testing.T) {
	c := mustParse(t, baseYAML+`
    cache: { enabled: true, stale_if_error: 2d }
    always_online: { enabled: true }
`)
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	a := c.Apps["web"]
	if time.Duration(*a.Cache.StaleIfError) != 48*time.Hour || time.Duration(a.Cache.DefaultTTL) != 5*time.Minute {
		t.Errorf("cache = %+v", a.Cache)
	}
	if a.Cache.Vary[0] != "Accept-Encoding" {
		t.Errorf("vary default = %v", a.Cache.Vary)
	}
	ao := a.AlwaysOnline
	if ao.Mode != AlwaysOnlineFallback || ao.Crawl.Schedule != "0 4 * * *" || ao.Crawl.Keep != 3 || ao.Crawl.Start[0] != "/" {
		t.Errorf("always_online defaults = %+v", ao)
	}
}

func TestCacheValidation(t *testing.T) {
	cases := map[string]string{
		`cache: { enabled: true, stale_if_error: 30d }`:                "apps.web.cache.stale_if_error",
		`cache: { enabled: true, bypass_paths: [api] }`:                "apps.web.cache.bypass_paths[0]",
		`cache: { enabled: true, vary: [Cookie] }`:                     "apps.web.cache.vary[0]",
		`always_online: { enabled: true, mode: mirror }`:               "apps.web.always_online.mode",
		`always_online: { enabled: true, crawl: { schedule: daily } }`: "apps.web.always_online.crawl.schedule",
		`always_online: { enabled: true, crawl: { start: [index] } }`:  "apps.web.always_online.crawl.start[0]",
		`always_online: { enabled: true, crawl: { max_bytes: lots } }`: "apps.web.always_online.crawl.max_bytes",
		"access: [admins]\n    always_online: { enabled: true }":       "apps.web.always_online: only allowed for public apps",
	}
	for snippet, want := range cases {
		err := mustParse(t, baseYAML+"    "+snippet+"\n").Validate()
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: err = %v, want %s", snippet, err, want)
		}
	}
	// Apps with a leading bypass-everyone policy are covered by TestIsPublicApp.
	if err := mustParse(t, baseYAML+"    always_online: { enabled: true }\n").Validate(); err != nil {
		t.Errorf("app without policies: %v", err)
	}
}

func TestIsPublicApp(t *testing.T) {
	const policies = `
policies:
  public: { action: bypass, include: [{ everyone: true }] }
  office: { action: bypass, include: [{ ip: [10.0.0.0/8] }] }
  admins: { action: allow, include: [{ email: [a@example.com] }] }
`
	for snippet, want := range map[string]bool{
		"":                         true,
		"access: [public]":         true,
		"access: [public, admins]": true, // first match always wins
		"access: [admins]":         false,
		"access: [admins, public]": false,
		"access: [office]":         false, // bypass, but not for everyone
		"paths: [{ match: /x, access: [admins] }]": false,
	} {
		c := mustParse(t, baseYAML+"    "+snippet+"\n"+policies)
		if got := c.IsPublicApp(c.Apps["web"]); got != want {
			t.Errorf("%q: IsPublicApp = %v, want %v", snippet, got, want)
		}
	}
}

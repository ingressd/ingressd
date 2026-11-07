// SPDX-License-Identifier: Apache-2.0

package main

import (
	"strings"
	"testing"

	coreruleset "github.com/corazawaf/coraza-coreruleset/v4"
	"github.com/corazawaf/coraza/v3"
)

// The directives internal/render emits for a default block-mode app.
const wafTestDirectives = `Include @coraza.conf-recommended
Include @crs-setup.conf.example
SecRuleEngine On
SecAction "id:900000,phase:1,pass,t:none,nolog,setvar:tx.blocking_paranoia_level=1"
SecAction "id:900110,phase:1,pass,t:none,nolog,setvar:tx.inbound_anomaly_score_threshold=5,setvar:tx.outbound_anomaly_score_threshold=4"
Include @owasp_crs/*.conf
`

func TestWAFRuleSet(t *testing.T) {
	waf, err := coraza.NewWAF(coraza.NewWAFConfig().WithRootFS(coreruleset.FS).WithDirectives(wafTestDirectives))
	if err != nil {
		t.Fatal(err)
	}
	const form = "application/x-www-form-urlencoded"
	for _, tc := range []struct {
		name, method, uri, contentType, body string
		blocked                              bool
	}{
		{"page", "GET", "/", "", "", false},
		{"query", "GET", "/search?q=blue+shoes&page=2", "", "", false},
		{"asset path", "GET", "/static/js/app.min.js", "", "", false},
		{"api path", "GET", "/api/v1/users/42/bin/list", "", "", false},
		{"form", "POST", "/login", form, "user=alice&remember=1", false},
		{"form with charset", "POST", "/login", form + "; charset=UTF-8", "user=alice", false},
		{"json", "POST", "/api/items", "application/json", `{"name":"lamp","qty":2}`, false},
		{"json suffix", "POST", "/api/items", "application/vnd.api+json", `{"data":{"type":"items"}}`, false},
		{"unlisted charset", "POST", "/login", form + "; charset=utf-7", "user=alice", true},
		{"unlisted charset, upper-case parameter", "POST", "/login", form + "; CHARSET=utf-7", "user=alice", true},
		{"unlisted charset, mixed-case parameter", "POST", "/login", form + "; ChArSeT=utf-7", "user=alice", true},
		{"sql injection", "GET", "/search?q=1%27%20OR%20%271%27%3D%271", "", "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tx := waf.NewTransaction()
			defer tx.Close()
			tx.ProcessConnection("192.0.2.1", 50000, "192.0.2.2", 443)
			tx.ProcessURI(tc.uri, tc.method, "HTTP/1.1")
			tx.AddRequestHeader("Host", "app.example.com")
			tx.AddRequestHeader("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/140.0")
			tx.AddRequestHeader("Accept", "text/html,application/json")
			if tc.contentType != "" {
				tx.AddRequestHeader("Content-Type", tc.contentType)
			}
			it := tx.ProcessRequestHeaders()
			if it == nil {
				if _, _, err := tx.ReadRequestBodyFrom(strings.NewReader(tc.body)); err != nil {
					t.Fatal(err)
				}
				if it, err = tx.ProcessRequestBody(); err != nil {
					t.Fatal(err)
				}
			}
			if got := it != nil; got != tc.blocked {
				t.Fatalf("blocked = %v, want %v (%+v)", got, tc.blocked, it)
			}
		})
	}
}

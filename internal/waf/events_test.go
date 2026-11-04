// SPDX-License-Identifier: Apache-2.0

package waf

import (
	"strings"
	"testing"

	"github.com/ingressd/ingressd/pkg/config"
)

// Trimmed records from a real Coraza v3 JSON audit log.
const auditLog = `{"transaction":{"timestamp":"2026/11/02 21:50:40","unix_timestamp":1793656240833922382,"id":"OGnPgqeiGSoEKJlM","client_ip":"198.51.100.2","client_port":0,"host_ip":"","host_port":0,"server_id":"shop.example.test","request":{"method":"GET","protocol":"HTTP/2.0","uri":"/search?q=1%27%20OR%20%271%27%3D%271","http_version":"","headers":{"host":["shop.example.test"],"user-agent":["Mozilla/5.0"]},"body":"","files":null,"args":{},"length":0},"response":{"protocol":"","status":0,"headers":{},"body":""},"highest_severity":"","is_interrupted":true},"messages":[{"actionset":"OWASP_CRS/4.25.0","message":"SQL Injection Attack Detected via libinjection","data":{"file":"@owasp_crs/REQUEST-942-APPLICATION-ATTACK-SQLI.conf","line":5894,"id":942100,"rev":"","msg":"SQL Injection Attack Detected via libinjection","data":"Matched Data: s&sos found within ARGS:q: 1' OR '1'='1","severity":2,"ver":"OWASP_CRS/4.25.0","maturity":0,"accuracy":0,"tags":["attack-sqli","paranoia-level/1","OWASP_CRS"]}},{"actionset":"OWASP_CRS/4.25.0","message":"Inbound Anomaly Score Exceeded (Total Score: 5)","data":{"id":949110,"msg":"Inbound Anomaly Score Exceeded (Total Score: 5)","data":"","severity":0,"tags":["anomaly-evaluation","OWASP_CRS"]}}]}
not json
{"transaction":{"id":"plain403","server_id":"shop.example.test","is_interrupted":false,"response":{"status":403}},"messages":[]}
{"transaction":{"unix_timestamp":1793656250000000000,"id":"DetectOnly1","client_ip":"198.51.100.2","server_id":"docs.example.test","request":{"method":"GET","uri":"/?q=%3Cscript%3E","headers":{"host":["docs.example.test"]}},"response":{"status":200},"is_interrupted":false},"messages":[{"data":{"id":941100,"msg":"XSS Attack Detected via libinjection","data":"Matched Data: XSS data found within ARGS:q: <script>","severity":2,"tags":["attack-xss"]}}]}
`

func TestRead(t *testing.T) {
	events, err := Read(strings.NewReader(auditLog))
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 {
		t.Fatalf("got %d events, want 2 (records without rule matches skipped): %+v", len(events), events)
	}
	e := events[0]
	if e.ID != "OGnPgqeiGSoEKJlM" || e.Host != "shop.example.test" || e.ClientIP != "198.51.100.2" || !e.Blocked || e.Status != 403 {
		t.Errorf("event = %+v", e)
	}
	if e.Time.Unix() != 1793656240 || e.Path() != "/search" || e.Method != "GET" {
		t.Errorf("time/path = %v %q", e.Time, e.Path())
	}
	if len(e.Rules) != 2 || e.Rules[0].ID != 942100 || e.Rules[0].Target != "ARGS:q" || e.Rules[0].Severity != "critical" {
		t.Errorf("rules = %+v", e.Rules)
	}
	if e.Rules[0].Scoring() || !e.Rules[1].Scoring() {
		t.Error("Scoring misclassified rules")
	}
	if d := events[1]; d.Blocked || d.Status != 200 {
		t.Errorf("detect event = %+v", d)
	}

	cfg := &config.Config{Apps: map[string]config.App{
		"shop": {Hosts: []string{"shop.example.test"}},
		"docs": {Hosts: []string{"*.example.test"}},
	}}
	AssignApps(cfg, events)
	if events[0].App != "shop" || events[1].App != "docs" {
		t.Errorf("apps = %q, %q", events[0].App, events[1].App)
	}
}

func TestSuggestExclusion(t *testing.T) {
	events, _ := Read(strings.NewReader(auditLog))
	events[0].App = "shop"
	s, err := SuggestExclusion(events[0])
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(s, "        - { rule: 942100, path: /search, target: ARGS:q }") || strings.Contains(s, "949110") {
		t.Errorf("suggestion:\n%s", s)
	}
	// The snippet must be valid config for the app.
	body := strings.SplitN(s, "apps:\n", 2)[1]
	c, err := config.Parse([]byte("version: 1\nedge: { acme: { ca: internal } }\napps:\n" +
		strings.Replace(body, "    waf:\n", "    hosts: [shop.example.test]\n    origin: http://192.168.0.1\n    waf:\n", 1)))
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	if ex := c.Apps["shop"].WAF.Exclusions; len(ex) != 1 || ex[0].Rule != 942100 || ex[0].Target != "ARGS:q" {
		t.Errorf("parsed exclusions = %+v", ex)
	}
}

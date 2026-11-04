// SPDX-License-Identifier: Apache-2.0

// Package waf reads WAF events from Coraza's JSON audit log and proposes
// rule exclusions for false positives.
package waf

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/ingressd/ingressd/pkg/config"
)

// Event is one request the WAF blocked (or, in detect mode, would have
// blocked). It is the format shared with the UI and alerting.
type Event struct {
	ID       string    `json:"id"`
	Time     time.Time `json:"time"`
	App      string    `json:"app,omitempty"`
	Host     string    `json:"host"`
	ClientIP string    `json:"client_ip"`
	Method   string    `json:"method"`
	URI      string    `json:"uri"`
	// Status is the response status (403 when blocked).
	Status int `json:"status"`
	// Blocked is false for detect-mode events.
	Blocked bool        `json:"blocked"`
	Rules   []RuleMatch `json:"rules"`
}

// RuleMatch is one CRS rule that matched the request.
type RuleMatch struct {
	ID       int      `json:"id"`
	Msg      string   `json:"msg"`
	Data     string   `json:"data,omitempty"`
	Severity string   `json:"severity,omitempty"`
	Tags     []string `json:"tags,omitempty"`
	// Target is the matched variable, e.g. ARGS:q (parsed from Data).
	Target string `json:"target,omitempty"`
}

// Path is the request path without the query string.
func (e Event) Path() string {
	if u, err := url.ParseRequestURI(e.URI); err == nil {
		return u.Path
	}
	p, _, _ := strings.Cut(e.URI, "?")
	return p
}

// Scoring reports whether a rule is an anomaly-score evaluation or
// correlation rule rather than an attack detection.
func (r RuleMatch) Scoring() bool {
	return slices.Contains(r.Tags, "anomaly-evaluation") || (r.ID >= 949000 && r.ID < 950000) ||
		(r.ID >= 959000 && r.ID < 960000) || (r.ID >= 980000 && r.ID < 981000)
}

// The subset of Coraza's JSON audit log record we use.
type auditRecord struct {
	Transaction struct {
		Timestamp     string `json:"timestamp"`
		UnixTimestamp int64  `json:"unix_timestamp"`
		ID            string `json:"id"`
		ClientIP      string `json:"client_ip"`
		ServerID      string `json:"server_id"`
		IsInterrupted bool   `json:"is_interrupted"`
		Request       *struct {
			Method  string              `json:"method"`
			URI     string              `json:"uri"`
			Headers map[string][]string `json:"headers"`
		} `json:"request"`
		Response *struct {
			Status int `json:"status"`
		} `json:"response"`
	} `json:"transaction"`
	Messages []struct {
		Message string `json:"message"`
		Data    *struct {
			ID       int             `json:"id"`
			Msg      string          `json:"msg"`
			Data     string          `json:"data"`
			Severity json.RawMessage `json:"severity"`
			Tags     []string        `json:"tags"`
		} `json:"data"`
	} `json:"messages"`
}

var targetRe = regexp.MustCompile(`found within ([A-Z_]+(?::[A-Za-z0-9_.\[\]-]+)?)`)

var severities = []string{"emergency", "alert", "critical", "error", "warning", "notice", "info", "debug"}

func severity(raw json.RawMessage) string {
	var n int
	if json.Unmarshal(raw, &n) == nil && n >= 0 && n < len(severities) {
		return severities[n]
	}
	var s string
	_ = json.Unmarshal(raw, &s)
	return strings.ToLower(s)
}

// Read parses audit log lines, skipping malformed lines and records without
// rule matches (Coraza also logs plain 400/403 responses).
func Read(r io.Reader) ([]Event, error) {
	var out []Event
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 16<<20)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 || line[0] != '{' {
			continue
		}
		var rec auditRecord
		if json.Unmarshal(line, &rec) != nil {
			continue
		}
		if e, ok := toEvent(rec); ok {
			out = append(out, e)
		}
	}
	return out, sc.Err()
}

// ReadFile reads events from an audit log; a missing file has no events.
func ReadFile(path string) ([]Event, error) {
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return Read(f)
}

func toEvent(rec auditRecord) (Event, bool) {
	t := rec.Transaction
	e := Event{ID: t.ID, ClientIP: t.ClientIP, Blocked: t.IsInterrupted, Host: t.ServerID}
	if t.UnixTimestamp != 0 {
		// Coraza writes nanoseconds.
		e.Time = time.Unix(0, t.UnixTimestamp).UTC()
	}
	if rq := t.Request; rq != nil {
		e.Method, e.URI = rq.Method, rq.URI
		for k, v := range rq.Headers {
			if strings.EqualFold(k, "host") && len(v) > 0 {
				e.Host = v[0]
			}
		}
	}
	if t.Response != nil {
		e.Status = t.Response.Status
	}
	for _, m := range rec.Messages {
		d := m.Data
		if d == nil || d.ID == 0 {
			continue
		}
		rm := RuleMatch{ID: d.ID, Msg: d.Msg, Data: d.Data, Severity: severity(d.Severity), Tags: d.Tags}
		if s := targetRe.FindStringSubmatch(d.Data); s != nil {
			rm.Target = s[1]
		}
		e.Rules = append(e.Rules, rm)
	}
	if e.Blocked && e.Status == 0 {
		e.Status = 403
	}
	return e, len(e.Rules) > 0
}

// AssignApps fills Event.App from the config's app hosts.
func AssignApps(cfg *config.Config, events []Event) {
	for i := range events {
		events[i].App = AppForHost(cfg, events[i].Host)
	}
}

// AppForHost returns the app serving host (exact before wildcard), or "".
func AppForHost(cfg *config.Config, host string) string {
	host = strings.ToLower(host)
	if h, _, ok := strings.Cut(host, ":"); ok && !strings.Contains(h, "]") {
		host = h
	}
	wild := ""
	for name, a := range cfg.Apps {
		for _, h := range a.Hosts {
			if h == host {
				return name
			}
			if strings.HasPrefix(h, "*.") && strings.HasSuffix(host, h[1:]) && !strings.Contains(strings.TrimSuffix(host, h[1:]), ".") {
				wild = name
			}
		}
	}
	return wild
}

// SuggestExclusion returns a YAML snippet with exclusions that would stop
// the event's detection rules from matching it again, scoped to its path
// and matched variable.
func SuggestExclusion(e Event) (string, error) {
	app := e.App
	if app == "" {
		app = "<app>"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "# Exclusion for WAF event %s (%s %s)\n", e.ID, e.Method, e.URI)
	fmt.Fprintf(&b, "# Review before applying: it lets these requests through without the rules below.\n")
	fmt.Fprintf(&b, "apps:\n  %s:\n    waf:\n      exclusions:\n", app)
	path := e.Path()
	if !validPath(path) {
		path = ""
	}
	n := 0
	seen := map[string]bool{}
	for _, r := range e.Rules {
		if r.Scoring() {
			continue
		}
		line := fmt.Sprintf("{ rule: %d", r.ID)
		if path != "" {
			line += ", path: " + path
		}
		if r.Target != "" {
			line += ", target: " + r.Target
		}
		line += " }"
		if seen[line] {
			continue
		}
		seen[line] = true
		fmt.Fprintf(&b, "        - %s  # %s\n", line, strings.ReplaceAll(r.Msg, "\n", " "))
		n++
	}
	if n == 0 {
		return "", fmt.Errorf("event %s has no detection rules to exclude", e.ID)
	}
	return b.String(), nil
}

// pathRe is the subset of config paths that is safe as a plain YAML flow scalar.
var pathRe = regexp.MustCompile(`^/[A-Za-z0-9_.~/%@$()+=-]*$`)

func validPath(p string) bool { return pathRe.MatchString(p) }

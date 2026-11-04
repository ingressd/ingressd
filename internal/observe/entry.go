// SPDX-License-Identifier: Apache-2.0

// Package observe ingests Caddy's JSON access logs and keeps them queryable
// (PLAN §13): a ring buffer for live tail, SQLite (<state-dir>/observe.db)
// for search with retention, per-minute aggregates per host for charts, and
// in-memory counters for Prometheus.
//
// Query API (used by the CLI, and by the dashboard/REST API in Phase 2):
//
//	(*Store).Query(ctx, Filter) ([]Entry, error)       // log search, newest first
//	(*Store).Stats(ctx, StatsQuery) (*Stats, error)     // totals, per host, time series
//	(*Store).Top(ctx, Filter, field, n) ([]Count, error) // top paths / clients / hosts / statuses
//	(*Observer).Recent(Filter, n) []Entry               // last entries from the ring buffer
//	(*Observer).Subscribe(ctx, Filter) <-chan Entry     // live tail
//	(*Observer).Handler() http.Handler                  // the same over HTTP (JSON / NDJSON)
//	(*Registry).ServeHTTP                               // Prometheus /metrics
package observe

import (
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"
)

// Entry is one handled request.
type Entry struct {
	Time     time.Time     `json:"time"`
	Host     string        `json:"host"`
	Method   string        `json:"method"`
	Path     string        `json:"path"` // request URI including query
	Proto    string        `json:"proto"`
	Status   int           `json:"status"`
	Bytes    int64         `json:"bytes"`    // response body size
	BytesIn  int64         `json:"bytes_in"` // request body size
	Duration time.Duration `json:"duration_ns"`
	ClientIP string        `json:"client_ip"`
	UA       string        `json:"user_agent,omitempty"`
}

// StatusClass returns 1..5 for 1xx..5xx (0 if unknown).
func (e Entry) StatusClass() int {
	if e.Status < 100 || e.Status > 599 {
		return 0
	}
	return e.Status / 100
}

// LogEvent is a non-access log line from Caddy (certificate obtain/renew).
type LogEvent struct {
	Time   time.Time
	Logger string
	Level  string
	Msg    string
	Fields map[string]any
}

// caddyLine is the subset of Caddy's JSON log format we read.
type caddyLine struct {
	Level   string  `json:"level"`
	TS      float64 `json:"ts"`
	Logger  string  `json:"logger"`
	Msg     string  `json:"msg"`
	Request *struct {
		RemoteIP string              `json:"remote_ip"`
		ClientIP string              `json:"client_ip"`
		Proto    string              `json:"proto"`
		Method   string              `json:"method"`
		Host     string              `json:"host"`
		URI      string              `json:"uri"`
		Headers  map[string][]string `json:"headers"`
	} `json:"request"`
	BytesRead int64   `json:"bytes_read"`
	Duration  float64 `json:"duration"`
	Size      int64   `json:"size"`
	Status    int     `json:"status"`
}

// parseLine decodes one Caddy log line into an access Entry or a LogEvent.
func parseLine(b []byte) (*Entry, *LogEvent, error) {
	var l caddyLine
	if err := json.Unmarshal(b, &l); err != nil {
		return nil, nil, err
	}
	sec, frac := math.Modf(l.TS)
	ts := time.Unix(int64(sec), int64(frac*1e9))
	if strings.HasPrefix(l.Logger, "http.log.access") {
		if l.Request == nil {
			return nil, nil, fmt.Errorf("access log line without request")
		}
		r := l.Request
		host := strings.ToLower(r.Host)
		if h, _, ok := strings.Cut(host, ":"); ok && !strings.Contains(h, "]") {
			host = h
		}
		e := &Entry{
			Time: ts, Host: host, Method: r.Method, Path: r.URI, Proto: r.Proto,
			Status: l.Status, Bytes: l.Size, BytesIn: l.BytesRead,
			Duration: time.Duration(l.Duration * float64(time.Second)),
			ClientIP: r.ClientIP,
		}
		if e.ClientIP == "" {
			e.ClientIP = r.RemoteIP
		}
		if ua := r.Headers["User-Agent"]; len(ua) > 0 {
			e.UA = ua[0]
		}
		return e, nil, nil
	}
	ev := &LogEvent{Time: ts, Logger: l.Logger, Level: l.Level, Msg: l.Msg, Fields: map[string]any{}}
	_ = json.Unmarshal(b, &ev.Fields)
	return nil, ev, nil
}

// Filter selects log entries. Zero fields match everything.
type Filter struct {
	Host string
	// Status is an exact code ("404"), a class ("5xx") or a range
	// ("400-499").
	Status   string
	Since    time.Time
	Until    time.Time
	Path     string // path prefix
	ClientIP string
	Method   string
	Limit    int // default 100 for Query
}

// statusRange parses Filter.Status into an inclusive range.
func (f Filter) statusRange() (lo, hi int, err error) {
	s := strings.ToLower(strings.TrimSpace(f.Status))
	switch {
	case s == "":
		return 0, 0, nil
	case len(s) == 3 && strings.HasSuffix(s, "xx") && s[0] >= '1' && s[0] <= '5':
		c := int(s[0]-'0') * 100
		return c, c + 99, nil
	case strings.Contains(s, "-"):
		a, b, _ := strings.Cut(s, "-")
		lo, err1 := strconv.Atoi(a)
		hi, err2 := strconv.Atoi(b)
		if err1 != nil || err2 != nil || lo > hi {
			return 0, 0, fmt.Errorf("invalid status range %q", f.Status)
		}
		return lo, hi, nil
	default:
		n, err := strconv.Atoi(s)
		if err != nil {
			return 0, 0, fmt.Errorf("invalid status %q (e.g. 404, 5xx, 400-499)", f.Status)
		}
		return n, n, nil
	}
}

// Validate reports a malformed filter.
func (f Filter) Validate() error {
	_, _, err := f.statusRange()
	return err
}

// Match reports whether e passes the filter (used by the ring buffer).
func (f Filter) Match(e Entry) bool {
	if f.Host != "" && !strings.EqualFold(f.Host, e.Host) {
		return false
	}
	if lo, hi, err := f.statusRange(); err == nil && lo != 0 && (e.Status < lo || e.Status > hi) {
		return false
	}
	if !f.Since.IsZero() && e.Time.Before(f.Since) {
		return false
	}
	if !f.Until.IsZero() && !e.Time.Before(f.Until) {
		return false
	}
	if f.Path != "" && !strings.HasPrefix(e.Path, f.Path) {
		return false
	}
	if f.ClientIP != "" && f.ClientIP != e.ClientIP {
		return false
	}
	if f.Method != "" && !strings.EqualFold(f.Method, e.Method) {
		return false
	}
	return true
}

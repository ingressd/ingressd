// SPDX-License-Identifier: Apache-2.0

package observe

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/ingressd/ingressd/pkg/config"
)

// ParseTime parses an absolute time (RFC 3339, "2006-01-02 15:04", or a
// date) or a duration ago ("15m", "36h", "7d") relative to now.
func ParseTime(s string, now time.Time) (time.Time, error) {
	if s == "" {
		return time.Time{}, nil
	}
	if d, err := config.ParsePeriod(s); err == nil {
		return now.Add(-d), nil
	}
	for _, layout := range []string{time.RFC3339, "2006-01-02 15:04", "2006-01-02T15:04", "2006-01-02"} {
		if t, err := time.ParseInLocation(layout, s, time.Local); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("invalid time %q (e.g. 15m, 7d, 2026-01-02 15:04)", s)
}

// FilterFromQuery reads a Filter from URL query parameters host, status,
// since, until, path, client_ip, method and limit.
func FilterFromQuery(q url.Values, now time.Time) (Filter, error) {
	f := Filter{Host: q.Get("host"), Status: q.Get("status"), Path: q.Get("path"),
		ClientIP: q.Get("client_ip"), Method: q.Get("method")}
	var err error
	if f.Since, err = ParseTime(q.Get("since"), now); err != nil {
		return f, err
	}
	if f.Until, err = ParseTime(q.Get("until"), now); err != nil {
		return f, err
	}
	if l := q.Get("limit"); l != "" {
		if f.Limit, err = strconv.Atoi(l); err != nil {
			return f, fmt.Errorf("invalid limit %q", l)
		}
	}
	return f, f.Validate()
}

// Handler serves the query API over HTTP (mounted on <run-dir>/ops.sock by
// serve, and on the admin API by Phase 2):
//
//	GET /v1/logs?host=&status=&since=&until=&path=&client_ip=&method=&limit=
//	    JSON array, newest first. With follow=1: NDJSON stream of the last
//	    `limit` entries from the ring buffer (oldest first), then new ones.
//	GET /v1/stats?since=&until=&host=&step=   Stats as JSON
//	GET /v1/top?field=path|client_ip|host|status|ua&n=10&<filter>
//	GET /metrics                               Prometheus (if reg != nil)
func (o *Observer) Handler(reg *Registry) http.Handler {
	mux := http.NewServeMux()
	if reg != nil {
		mux.Handle("GET /metrics", reg)
	}
	mux.HandleFunc("GET /v1/logs", func(w http.ResponseWriter, r *http.Request) {
		f, err := FilterFromQuery(r.URL.Query(), time.Now())
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if r.URL.Query().Get("follow") == "" {
			if o.opts.Store == nil {
				writeJSON(w, o.Recent(f, max(f.Limit, 100)))
				return
			}
			es, err := o.opts.Store.Query(r.Context(), f)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			writeJSON(w, es)
			return
		}
		w.Header().Set("Content-Type", "application/x-ndjson")
		fl, _ := w.(http.Flusher)
		enc := json.NewEncoder(w)
		ch := o.Subscribe(r.Context(), Filter{Host: f.Host, Status: f.Status, Path: f.Path, ClientIP: f.ClientIP, Method: f.Method})
		n := f.Limit
		if n <= 0 {
			n = 10
		}
		for _, e := range o.Recent(f, n) {
			_ = enc.Encode(e)
		}
		if fl != nil {
			fl.Flush()
		}
		for e := range ch {
			if err := enc.Encode(e); err != nil {
				return
			}
			if fl != nil {
				fl.Flush()
			}
		}
	})
	mux.HandleFunc("GET /v1/stats", func(w http.ResponseWriter, r *http.Request) {
		if o.opts.Store == nil {
			http.Error(w, "no store", http.StatusServiceUnavailable)
			return
		}
		q := r.URL.Query()
		now := time.Now()
		var sq StatsQuery
		var err error
		sq.Host = q.Get("host")
		if sq.Since, err = ParseTime(q.Get("since"), now); err == nil {
			sq.Until, err = ParseTime(q.Get("until"), now)
		}
		if err == nil && q.Get("step") != "" {
			sq.Step, err = time.ParseDuration(q.Get("step"))
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		st, err := o.opts.Store.Stats(r.Context(), sq)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, st)
	})
	mux.HandleFunc("GET /v1/top", func(w http.ResponseWriter, r *http.Request) {
		if o.opts.Store == nil {
			http.Error(w, "no store", http.StatusServiceUnavailable)
			return
		}
		f, err := FilterFromQuery(r.URL.Query(), time.Now())
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		n, _ := strconv.Atoi(r.URL.Query().Get("n"))
		if n <= 0 {
			n = 10
		}
		cs, err := o.opts.Store.Top(r.Context(), f, r.URL.Query().Get("field"), n)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, cs)
	})
	return mux
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

// SPDX-License-Identifier: Apache-2.0

package observe

import (
	"fmt"
	"io"
	"math"
	"net/http"
	"runtime"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ingressd/ingressd/internal/version"
)

// Collector writes metrics on every scrape.
type Collector func(x *Exposition)

// Registry serves Prometheus metrics (text exposition format 0.0.4) from
// registered collectors. Other phases register theirs with Register
// (e.g. health checks, WAF, L4 nft counters).
type Registry struct {
	mu         sync.Mutex
	collectors []Collector
}

// NewRegistry returns a registry with process metrics registered.
func NewRegistry() *Registry {
	r := &Registry{}
	start := time.Now()
	r.Register(func(x *Exposition) {
		x.Gauge("ingressd_build_info", "Build information.", 1, "version", version.String())
		x.Gauge("ingressd_start_time_seconds", "Unix time the control plane started.", float64(start.Unix()))
		x.Gauge("ingressd_goroutines", "Number of goroutines.", float64(runtime.NumGoroutine()))
		var ms runtime.MemStats
		runtime.ReadMemStats(&ms)
		x.Gauge("ingressd_memory_heap_bytes", "Heap bytes in use.", float64(ms.HeapAlloc))
	})
	return r
}

func (r *Registry) Register(c Collector) {
	r.mu.Lock()
	r.collectors = append(r.collectors, c)
	r.mu.Unlock()
}

// Write writes all metrics.
func (r *Registry) Write(w io.Writer) {
	r.mu.Lock()
	cs := slices.Clone(r.collectors)
	r.mu.Unlock()
	x := &Exposition{families: map[string]*family{}}
	for _, c := range cs {
		c(x)
	}
	x.write(w)
}

func (r *Registry) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	r.Write(w)
}

// Exposition accumulates samples grouped by metric family.
type Exposition struct {
	families map[string]*family
	order    []string
}

type family struct {
	name, typ, help string
	samples         []string
}

// Gauge adds a gauge sample; labels are key, value pairs.
func (x *Exposition) Gauge(name, help string, v float64, labels ...string) {
	x.add(name, "gauge", help, v, labels)
}

// Counter adds a counter sample (name should end in _total).
func (x *Exposition) Counter(name, help string, v float64, labels ...string) {
	x.add(name, "counter", help, v, labels)
}

func (x *Exposition) add(name, typ, help string, v float64, labels []string) {
	f := x.families[name]
	if f == nil {
		f = &family{name: name, typ: typ, help: help}
		x.families[name] = f
		x.order = append(x.order, name)
	}
	var b strings.Builder
	b.WriteString(name)
	if len(labels) > 0 {
		b.WriteByte('{')
		for i := 0; i+1 < len(labels); i += 2 {
			if i > 0 {
				b.WriteByte(',')
			}
			fmt.Fprintf(&b, "%s=%s", labels[i], strconv.Quote(labels[i+1]))
		}
		b.WriteByte('}')
	}
	b.WriteByte(' ')
	b.WriteString(formatFloat(v))
	f.samples = append(f.samples, b.String())
}

func formatFloat(v float64) string {
	switch {
	case math.IsInf(v, 1):
		return "+Inf"
	case math.IsInf(v, -1):
		return "-Inf"
	case math.IsNaN(v):
		return "NaN"
	}
	return strconv.FormatFloat(v, 'g', -1, 64)
}

func (x *Exposition) write(w io.Writer) {
	names := slices.Clone(x.order)
	sort.Strings(names)
	for _, n := range names {
		f := x.families[n]
		fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s %s\n", f.name, f.help, f.name, f.typ)
		for _, s := range f.samples {
			fmt.Fprintln(w, s)
		}
	}
}

var classLabels = [6]string{"unknown", "1xx", "2xx", "3xx", "4xx", "5xx"}

// Collector returns the access-log metrics: per-host request, status-class
// and byte counters, plus ingestion counters.
func (o *Observer) Collector() Collector {
	return func(x *Exposition) {
		x.Counter("ingressd_access_log_lines_total", "Access log entries ingested.", float64(o.Ingested()))
		x.Counter("ingressd_access_log_dropped_total", "Access log entries not stored (database backlog or errors).", float64(o.Dropped()))
		x.Counter("ingressd_access_log_invalid_total", "Unparseable log lines received.", float64(o.Invalid()))
		for _, h := range o.HostCounters() {
			for c := 1; c <= 5; c++ {
				if h.Status[c] > 0 {
					x.Counter("ingressd_http_requests_total", "HTTP requests handled by the edge, by host and status class.",
						float64(h.Status[c]), "host", h.Host, "code", classLabels[c])
				}
			}
			x.Counter("ingressd_http_response_bytes_total", "Response body bytes sent, by host.", float64(h.BytesOut), "host", h.Host)
			x.Counter("ingressd_http_request_bytes_total", "Request body bytes received, by host.", float64(h.BytesIn), "host", h.Host)
			x.Counter("ingressd_http_request_duration_seconds_sum", "Total request handling time, by host.",
				float64(h.durationUS)/1e6, "host", h.Host)
		}
	}
}

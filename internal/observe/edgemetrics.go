// SPDX-License-Identifier: Apache-2.0

package observe

import (
	"math/rand/v2"
	"strings"
	"time"
)

// Edge metrics for the node agent's metrics collector: a second meter next
// to usage (usage.go), drained on its own schedule so neither consumer
// steals the other's counts.

// maxLatencySamples bounds the latency reservoir per window.
const maxLatencySamples = 1024

// MetricsWindow is what the edge handled since the previous TakeMetrics.
type MetricsWindow struct {
	Requests     int64
	Status4xx    int64
	Status5xx    int64
	OriginErrors int64 // 502, 503, 504
	// Latencies is a uniform sample (at most maxLatencySamples) of request
	// durations; Seen is how many requests it was drawn from.
	Latencies []time.Duration
	Seen      int64
	// Hosts holds bytes and requests per exact host (bounded like usage).
	Hosts map[string]HostBytes
}

type HostBytes struct {
	Requests int64
	BytesIn  int64
	BytesOut int64
}

// add records e; o.mu is held.
func (w *MetricsWindow) add(e Entry) {
	w.Requests++
	switch e.StatusClass() {
	case 4:
		w.Status4xx++
	case 5:
		w.Status5xx++
	}
	if e.Status == 502 || e.Status == 503 || e.Status == 504 {
		w.OriginErrors++
	}
	w.Seen++
	if len(w.Latencies) < maxLatencySamples {
		w.Latencies = append(w.Latencies, e.Duration)
	} else if i := rand.Int64N(w.Seen); i < maxLatencySamples { //nolint:gosec // G404: reservoir sampling, not security
		w.Latencies[i] = e.Duration
	}
	if w.Hosts == nil {
		w.Hosts = map[string]HostBytes{}
	}
	h := strings.ToLower(e.Host)
	if _, ok := w.Hosts[h]; !ok && len(w.Hosts) >= maxUsageHosts {
		h = UsageOtherHost
	}
	hb := w.Hosts[h]
	hb.Requests++
	hb.BytesIn += e.BytesIn
	hb.BytesOut += e.Bytes
	w.Hosts[h] = hb
}

// TakeMetrics returns the edge metrics accumulated since the previous call
// and resets them.
func (o *Observer) TakeMetrics() MetricsWindow {
	o.mu.Lock()
	defer o.mu.Unlock()
	w := o.metrics
	o.metrics = MetricsWindow{}
	return w
}

// SPDX-License-Identifier: Apache-2.0

package health

import (
	"path/filepath"
	"time"
)

// HistoryWindow is how long full-resolution check results are kept.
const HistoryWindow = 24 * time.Hour

// maxSamples caps one origin's ring (24h at a 5s interval).
const maxSamples = 17280

// maxEvents is how many recent events the status file keeps.
const maxEvents = 500

// Sample is one check result.
type Sample struct {
	Time      time.Time `json:"t"`
	OK        bool      `json:"ok"`
	LatencyMS float64   `json:"ms,omitempty"`
}

// ring is a fixed-size ring of samples.
type ring struct {
	buf  []Sample
	next int
	full bool
}

func newRing(interval time.Duration) *ring {
	n := maxSamples
	if interval > 0 {
		n = min(n, int(HistoryWindow/interval)+1)
	}
	return &ring{buf: make([]Sample, max(n, 1))}
}

func (r *ring) add(s Sample) {
	r.buf[r.next] = s
	r.next = (r.next + 1) % len(r.buf)
	if r.next == 0 {
		r.full = true
	}
}

// since returns samples newer than t, oldest first.
func (r *ring) since(t time.Time) []Sample {
	var out []Sample
	n := r.next
	if r.full {
		n = len(r.buf)
	}
	start := 0
	if r.full {
		start = r.next
	}
	for i := range n {
		s := r.buf[(start+i)%len(r.buf)]
		if s.Time.After(t) {
			out = append(out, s)
		}
	}
	return out
}

// Status is the monitor's view of every pool, persisted to
// <state-dir>/pool-health.json for the CLI, the UI and restarts.
type Status struct {
	Updated time.Time             `json:"updated"`
	Pools   map[string]PoolStatus `json:"pools"`
	Tunnels map[string]TunnelInfo `json:"tunnels,omitempty"`
	// Events are the most recent health events, oldest first.
	Events []Event `json:"events,omitempty"`
}

type TunnelInfo struct {
	Up     bool   `json:"up"`
	Reason string `json:"reason,omitempty"`
}

type PoolStatus struct {
	Steering string `json:"steering"`
	// ActiveTier is the tier new sessions go to (0 when all are down).
	ActiveTier int `json:"active_tier"`
	// BestTier is the best tier with a healthy origin; lower than
	// ActiveTier while a failback is pending.
	BestTier int  `json:"best_tier"`
	AllDown  bool `json:"all_down,omitempty"`
	// FailbackPending is set while waiting to fail back: since when, and
	// whether it needs a manual failback.
	FailbackPending *time.Time     `json:"failback_pending,omitempty"`
	FailbackManual  bool           `json:"failback_manual,omitempty"`
	Override        *Force         `json:"override,omitempty"`
	Origins         []OriginStatus `json:"origins"`
}

type OriginStatus struct {
	Name     string `json:"name"`
	Tunnel   string `json:"tunnel,omitempty"`
	Address  string `json:"address"`
	Dial     string `json:"dial"`
	Priority int    `json:"priority"`
	Weight   int    `json:"weight"`
	// State is the effective state (runtime override, else config).
	State       string `json:"state"`
	ConfigState string `json:"config_state"`
	// Checked is false for pools without an active health check.
	Checked bool `json:"checked"`
	Healthy bool `json:"healthy"`
	// Reason explains Healthy=false (or a pending recovery).
	Reason      string    `json:"reason,omitempty"`
	Since       time.Time `json:"since"`
	LastCheck   time.Time `json:"last_check"`
	LastError   string    `json:"last_error,omitempty"`
	LatencyMS   float64   `json:"latency_ms,omitempty"`
	Checks24h   int       `json:"checks_24h"`
	Failures24h int       `json:"failures_24h"`
}

// LoadStatus reads the persisted status written by `ingressd serve`.
func LoadStatus(stateDir string) (*Status, error) {
	var s Status
	if err := readJSON(filepath.Join(stateDir, StatusFile), &s); err != nil {
		return nil, err
	}
	return &s, nil
}

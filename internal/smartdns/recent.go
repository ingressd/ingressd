// SPDX-License-Identifier: Apache-2.0

package smartdns

import (
	"sync"
	"time"
)

const recentSize = 512

// Lookup is one resolver query, kept for domain discovery: point a device at
// the resolver and every name it looks up shows here.
type Lookup struct {
	Time    time.Time `json:"time"`
	Client  string    `json:"client"`
	Site    string    `json:"site,omitempty"` // tunnel the query arrived on
	Name    string    `json:"name"`
	Type    string    `json:"type"`
	Routed  bool      `json:"routed"`
	Service string    `json:"service,omitempty"`
	Exit    string    `json:"exit,omitempty"`
	Result  string    `json:"result"`
}

// ring is a fixed-size ring buffer of lookups.
type ring struct {
	mu   sync.Mutex
	buf  []Lookup
	next int
	full bool
}

func newRing(n int) *ring { return &ring{buf: make([]Lookup, n)} }

func (r *ring) add(l Lookup) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.buf[r.next] = l
	r.next = (r.next + 1) % len(r.buf)
	if r.next == 0 {
		r.full = true
	}
}

// list returns up to limit entries, newest first (limit <= 0: all).
func (r *ring) list(limit int) []Lookup {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := r.next
	if r.full {
		n = len(r.buf)
	}
	if limit <= 0 || limit > n {
		limit = n
	}
	out := make([]Lookup, 0, limit)
	for i := 0; i < limit; i++ {
		idx := (r.next - 1 - i + len(r.buf)) % len(r.buf)
		out = append(out, r.buf[idx])
	}
	return out
}

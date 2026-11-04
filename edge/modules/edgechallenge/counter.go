// SPDX-License-Identifier: Apache-2.0

package edgechallenge

import (
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"time"
)

// counters is shared by all handler instances so rates survive reloads.
var counters = newCounterSet()

// counterSet holds sliding-window request counters (two fixed buckets,
// weighted by how far the current window has progressed).
type counterSet struct {
	mu        sync.Mutex
	m         map[string]*window
	lastSweep time.Time
}

type window struct {
	start     time.Time
	size      time.Duration
	prev, cur int
}

// maxCounters bounds the memory of the counters (a few hundred bytes
// each); maxKeyLen bounds a key (header values and paths are hashed).
var maxCounters = 200_000

const maxKeyLen = 128

func newCounterSet() *counterSet { return &counterSet{m: map[string]*window{}} }

// hit records one event for key and reports whether more than limit events
// happened within the last size. When the set is full of live counters a
// new key counts as over the limit (it is challenged) rather than evicting
// someone else's counter.
func (s *counterSet) hit(key string, limit int, size time.Duration, now time.Time) bool {
	if len(key) > maxKeyLen {
		sum := sha256.Sum256([]byte(key))
		key = key[:32] + "#" + hex.EncodeToString(sum[:16])
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweep(now)
	w := s.m[key]
	if w == nil && len(s.m) >= maxCounters {
		if now.Sub(s.lastSweep) >= time.Second { // at most one full scan a second
			s.lastSweep = time.Time{}
			s.sweep(now)
		}
		if len(s.m) >= maxCounters {
			return true
		}
	}
	if w == nil || w.size != size {
		w = &window{start: now, size: size}
		s.m[key] = w
	}
	switch el := now.Sub(w.start); {
	case el >= 2*size:
		w.start, w.prev, w.cur = now, 0, 0
	case el >= size:
		w.start, w.prev, w.cur = w.start.Add(size), w.cur, 0
	}
	w.cur++
	frac := float64(now.Sub(w.start)) / float64(size)
	return float64(w.prev)*(1-frac)+float64(w.cur) > float64(limit)
}

// sweep drops idle counters once a minute.
func (s *counterSet) sweep(now time.Time) {
	if now.Sub(s.lastSweep) < time.Minute {
		return
	}
	s.lastSweep = now
	for k, w := range s.m {
		if now.Sub(w.start) >= 2*w.size {
			delete(s.m, k)
		}
	}
}

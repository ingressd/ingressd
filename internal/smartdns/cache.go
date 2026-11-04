// SPDX-License-Identifier: Apache-2.0

package smartdns

import (
	"net/netip"
	"sync"
	"time"
)

const (
	// cacheMinTTL floors very short CDN TTLs.
	cacheMinTTL = 30 * time.Second
	// staleMax is how long an expired exit answer may still be served when
	// the exit cannot resolve the name.
	staleMax = 24 * time.Hour
)

// answer is an exit's resolution of one name (A records only).
type answer struct {
	Addrs []netip.Addr
	TTL   time.Duration
}

type cacheKey struct{ exit, name string }

type cacheEntry struct {
	answer
	expires time.Time
}

type cacheState int

const (
	cacheMiss cacheState = iota
	cacheFresh
	cacheStale // expired less than staleMax ago: serve, and refresh in the background
)

func (s cacheState) String() string {
	return [...]string{"miss", "cached", "stale"}[s]
}

// swrCache is a stale-while-revalidate cache of exit answers.
type swrCache struct {
	now        func() time.Time
	mu         sync.Mutex
	m          map[cacheKey]cacheEntry
	refreshing map[cacheKey]bool
}

func newCache() *swrCache {
	return &swrCache{now: time.Now, m: map[cacheKey]cacheEntry{}, refreshing: map[cacheKey]bool{}}
}

func (c *swrCache) get(k cacheKey) (answer, cacheState) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.m[k]
	if !ok {
		return answer{}, cacheMiss
	}
	now := c.now()
	switch {
	case now.Before(e.expires):
		return e.answer, cacheFresh
	case now.Sub(e.expires) < staleMax:
		return e.answer, cacheStale
	}
	delete(c.m, k)
	return answer{}, cacheMiss
}

// put stores a successful answer with at least cacheMinTTL.
func (c *swrCache) put(k cacheKey, a answer) {
	if len(a.Addrs) == 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.m[k] = cacheEntry{answer: a, expires: c.now().Add(max(a.TTL, cacheMinTTL))}
}

// startRefresh reports whether the caller should refresh k (only one
// refresh per key runs at a time); call endRefresh when done.
func (c *swrCache) startRefresh(k cacheKey) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.refreshing[k] {
		return false
	}
	c.refreshing[k] = true
	return true
}

func (c *swrCache) endRefresh(k cacheKey) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.refreshing, k)
}

// clear drops every entry (e.g. when a service changes exit).
func (c *swrCache) clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.m = map[cacheKey]cacheEntry{}
}

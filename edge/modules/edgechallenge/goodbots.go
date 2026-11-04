// SPDX-License-Identifier: Apache-2.0

package edgechallenge

import (
	"context"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"
)

// goodBots are crawlers verified by forward-confirmed reverse DNS: the
// IP's PTR name must end in one of the suffixes and resolve back to the IP.
type botRule struct {
	ua       string
	suffixes []string
}

var goodBots = []botRule{
	{"googlebot", []string{".googlebot.com", ".google.com", ".googleusercontent.com"}},
	{"google-inspectiontool", []string{".googlebot.com", ".google.com"}},
	{"bingbot", []string{".search.msn.com"}},
}

type botEntry struct {
	ok  bool
	exp time.Time
}

// botCache remembers verification results per IP (shared across reloads).
var botCache = struct {
	sync.Mutex
	m map[netip.Addr]botEntry
}{m: map[netip.Addr]botEntry{}}

func (c *Challenge) isGoodBot(ctx context.Context, ip netip.Addr, ua string) bool {
	lua := strings.ToLower(ua)
	i := slices.IndexFunc(goodBots, func(b botRule) bool { return strings.Contains(lua, b.ua) })
	if i < 0 || !ip.IsValid() {
		return false
	}
	now := c.now()
	botCache.Lock()
	e, found := botCache.m[ip]
	botCache.Unlock()
	if found && now.Before(e.exp) {
		return e.ok
	}
	ok := c.verifyBot(ctx, ip, goodBots[i].suffixes)
	ttl := time.Hour
	if ok {
		ttl = 24 * time.Hour
	}
	botCache.Lock()
	if len(botCache.m) > 100000 {
		clear(botCache.m)
	}
	botCache.m[ip] = botEntry{ok: ok, exp: now.Add(ttl)}
	botCache.Unlock()
	return ok
}

func (c *Challenge) verifyBot(ctx context.Context, ip netip.Addr, suffixes []string) bool {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	names, err := c.resolver.LookupAddr(ctx, ip.String())
	if err != nil {
		return false
	}
	for _, n := range names {
		n = strings.TrimSuffix(strings.ToLower(n), ".")
		if !slices.ContainsFunc(suffixes, func(s string) bool { return strings.HasSuffix(n, s) }) {
			continue
		}
		addrs, err := c.resolver.LookupHost(ctx, n)
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if pa, err := netip.ParseAddr(a); err == nil && pa.Unmap() == ip {
				return true
			}
		}
	}
	return false
}

// SPDX-License-Identifier: Apache-2.0

// Package edgelb implements the edge_tiered reverse_proxy selection policy
// (docs/DESIGN.md §6.4): priority tiers, weighted/other steering within a
// tier, signed sticky-session cookies, runtime drain/disable and manual
// overrides read from the edge_state app.
package edgelb

import (
	"cmp"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"hash/fnv"
	"math/rand/v2"
	"net"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/reverseproxy"

	"github.com/ingressd/ingressd/edge/modules/edgestate"
)

func init() {
	caddy.RegisterModule(Tiered{})
}

// Steering policies within a tier.
const (
	SteerRoundRobin = "round_robin"
	SteerWeighted   = "weighted"
	SteerLeastConn  = "least_conn"
	SteerFailover   = "failover"
	SteerRandom     = "random"
	SteerIPHash     = "ip_hash"
)

// Tiered selects an upstream by priority tier, health and policy.
type Tiered struct {
	// Pool names the pool in edge_state.
	Pool string `json:"pool,omitempty"`
	// Steering is the policy within a tier. Default round_robin.
	Steering string `json:"steering,omitempty"`
	// Upstreams carries per-upstream metadata, matched by dial address.
	Upstreams []Upstream `json:"upstreams,omitempty"`
	// Sticky enables signed affinity cookies.
	Sticky *Sticky `json:"sticky,omitempty"`

	meta  map[string]*Upstream
	store *edgestate.Store
	now   func() time.Time
	// avail reports Caddy-side availability (passive health, max requests).
	avail func(*reverseproxy.Upstream) bool

	rr *rrState
}

// rrState is the mutable round-robin state, behind a pointer so Tiered can
// be copied.
type rrState struct {
	next atomic.Uint64
	mu   sync.Mutex
	swrr map[string]int
}

// Upstream is the metadata of one upstream (origin).
type Upstream struct {
	Dial     string `json:"dial"`
	Origin   string `json:"origin"`
	Priority int    `json:"priority,omitempty"`
	Weight   int    `json:"weight,omitempty"`
	// State is the configured state: active (default) or draining.
	State string `json:"state,omitempty"`
}

type Sticky struct {
	Cookie string         `json:"cookie,omitempty"`
	TTL    caddy.Duration `json:"ttl,omitempty"`
}

func (Tiered) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.reverse_proxy.selection_policies.edge_tiered",
		New: func() caddy.Module { return new(Tiered) },
	}
}

func (t *Tiered) Provision(ctx caddy.Context) error {
	app, err := ctx.App("edge_state")
	if err != nil {
		return err
	}
	t.store = app.(*edgestate.App).Store()
	return t.setup()
}

// setup validates the config and fills defaults; split out for unit tests.
func (t *Tiered) setup() error {
	if t.Steering == "" {
		t.Steering = SteerRoundRobin
	}
	switch t.Steering {
	case SteerRoundRobin, SteerWeighted, SteerLeastConn, SteerFailover, SteerRandom, SteerIPHash:
	default:
		return fmt.Errorf("edge_tiered: unknown steering %q", t.Steering)
	}
	if t.Sticky != nil {
		if t.Sticky.Cookie == "" {
			t.Sticky.Cookie = "edge_aff"
		}
		if t.Sticky.TTL <= 0 {
			t.Sticky.TTL = caddy.Duration(time.Hour)
		}
	}
	t.meta = map[string]*Upstream{}
	for i := range t.Upstreams {
		u := &t.Upstreams[i]
		if u.Dial == "" {
			return fmt.Errorf("edge_tiered: upstreams[%d]: dial is required", i)
		}
		u.Origin = cmp.Or(u.Origin, u.Dial)
		u.Priority = max(u.Priority, 1)
		u.Weight = max(u.Weight, 1)
		u.State = cmp.Or(u.State, edgestate.StateActive)
		t.meta[u.Dial] = u
	}
	if t.store == nil {
		t.store = edgestate.Global()
	}
	if t.now == nil {
		t.now = time.Now
	}
	if t.avail == nil {
		t.avail = (*reverseproxy.Upstream).Available
	}
	t.rr = &rrState{swrr: map[string]int{}}
	return nil
}

// cand is an upstream with its metadata and effective runtime state.
type cand struct {
	up   *reverseproxy.Upstream
	meta *Upstream
	// usable: healthy (control plane and Caddy) and not disabled; may
	// serve existing sticky sessions.
	usable bool
	// fresh: usable and active; may take new sessions.
	fresh bool
}

func (t *Tiered) Select(pool reverseproxy.UpstreamPool, r *http.Request, w http.ResponseWriter) *reverseproxy.Upstream {
	now := t.now()
	ps := t.store.Snapshot().Pools[t.Pool]
	cands := make([]cand, 0, len(pool))
	for _, up := range pool {
		m := t.meta[up.Dial]
		if m == nil {
			m = &Upstream{Dial: up.Dial, Origin: up.Dial, Priority: 1, Weight: 1, State: edgestate.StateActive}
		}
		os := ps.Origins[m.Origin]
		state := cmp.Or(os.State, m.State)
		healthy := os.Healthy == nil || *os.Healthy
		usable := healthy && state != edgestate.StateDisabled && t.avail(up)
		cands = append(cands, cand{up: up, meta: m, usable: usable, fresh: usable && state == edgestate.StateActive})
	}

	set, stickyOK := t.candidates(cands, ps, now)

	var pinned *cand
	if t.Sticky != nil {
		if c, err := r.Cookie(t.Sticky.Cookie); err == nil {
			if origin, ok := t.verify(c.Value, now); ok {
				for i := range cands {
					if cands[i].meta.Origin == origin && stickyOK(&cands[i]) {
						pinned = &cands[i]
						break
					}
				}
			}
		}
	}
	if pinned != nil {
		return pinned.up
	}

	pick := t.choose(set, r)
	if pick == nil {
		return nil
	}
	if t.Sticky != nil {
		t.setCookie(w, r, pick.meta.Origin, now)
	}
	return pick.up
}

// candidates returns the set eligible for new sessions and a predicate for
// which pinned (sticky) origins may keep their sessions.
func (t *Tiered) candidates(cands []cand, ps edgestate.PoolState, now time.Time) ([]*cand, func(*cand) bool) {
	if ov := ps.Override; ov.Active(now) {
		var set []*cand
		for i := range cands {
			c := &cands[i]
			if !ov.Matches(c.meta.Origin, c.meta.Priority) {
				continue
			}
			// An origin forced by name may be draining; a forced tier only
			// takes origins that accept new sessions.
			if c.fresh || (len(ov.Origins) > 0 && c.usable) {
				set = append(set, c)
			}
		}
		if len(set) > 0 {
			return set, func(c *cand) bool { return c.usable && ov.Matches(c.meta.Origin, c.meta.Priority) }
		}
		// Nothing forced is usable: fall back to normal tiered selection
		// rather than failing every request.
	}

	tier := 0
	for _, floor := range []int{ps.Tier, 0} {
		for i := range cands {
			c := &cands[i]
			if c.fresh && c.meta.Priority >= floor && (tier == 0 || c.meta.Priority < tier) {
				tier = c.meta.Priority
			}
		}
		if tier != 0 {
			break
		}
	}
	var set []*cand
	for i := range cands {
		if c := &cands[i]; c.fresh && c.meta.Priority == tier {
			set = append(set, c)
		}
	}
	// Pinned sessions stay on their origin while it is usable and in the
	// chosen tier or a better one (draining origins included), so sessions
	// move back up after failback.
	return set, func(c *cand) bool { return c.usable && (tier == 0 || c.meta.Priority <= tier) }
}

func (t *Tiered) choose(set []*cand, r *http.Request) *cand {
	switch len(set) {
	case 0:
		return nil
	case 1:
		return set[0]
	}
	switch t.Steering {
	case SteerWeighted:
		return t.smoothWeighted(set)
	case SteerLeastConn:
		best := []*cand{}
		least := -1
		for _, c := range set {
			n := c.up.NumRequests()
			switch {
			case least == -1 || n < least:
				least, best = n, []*cand{c}
			case n == least:
				best = append(best, c)
			}
		}
		return best[rand.IntN(len(best))]
	case SteerFailover:
		return set[0] // config order
	case SteerRandom:
		return set[rand.IntN(len(set))]
	case SteerIPHash:
		return rendezvous(set, clientIP(r))
	default:
		return set[int(t.rr.next.Add(1)-1)%len(set)]
	}
}

// smoothWeighted is nginx's smooth weighted round robin: it spreads picks
// evenly (a,a,b,a for 3:1) instead of in bursts.
func (t *Tiered) smoothWeighted(set []*cand) *cand {
	t.rr.mu.Lock()
	defer t.rr.mu.Unlock()
	w := t.rr.swrr
	total := 0
	var best *cand
	for _, c := range set {
		k := c.meta.Origin
		w[k] += c.meta.Weight
		total += c.meta.Weight
		if best == nil || w[k] > w[best.meta.Origin] {
			best = c
		}
	}
	w[best.meta.Origin] -= total
	return best
}

// rendezvous picks by highest-random-weight hashing, so a client keeps its
// origin when other origins come and go.
func rendezvous(set []*cand, key string) *cand {
	var best *cand
	var bestScore uint64
	for _, c := range set {
		h := fnv.New64a()
		h.Write([]byte(key))
		h.Write([]byte{0})
		h.Write([]byte(c.meta.Origin))
		if s := h.Sum64(); best == nil || s > bestScore {
			best, bestScore = c, s
		}
	}
	return best
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// Cookie format: base64url(origin) "." expiry-unix "." base64url(hmac)[:22].
// The MAC covers the pool name, so a cookie cannot be replayed across pools.

func (t *Tiered) mac(origin string, exp int64) string {
	m := hmac.New(sha256.New, t.store.StickyKey())
	fmt.Fprintf(m, "%s\x00%s\x00%d", t.Pool, origin, exp)
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))[:22]
}

func (t *Tiered) sign(origin string, exp int64) string {
	return base64.RawURLEncoding.EncodeToString([]byte(origin)) + "." + strconv.FormatInt(exp, 10) + "." + t.mac(origin, exp)
}

func (t *Tiered) verify(v string, now time.Time) (string, bool) {
	parts := strings.Split(v, ".")
	if len(parts) != 3 {
		return "", false
	}
	ob, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", false
	}
	exp, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil || now.Unix() >= exp {
		return "", false
	}
	origin := string(ob)
	if !hmac.Equal([]byte(t.mac(origin, exp)), []byte(parts[2])) {
		return "", false
	}
	return origin, true
}

func (t *Tiered) setCookie(w http.ResponseWriter, r *http.Request, origin string, now time.Time) {
	ttl := time.Duration(t.Sticky.TTL)
	c := &http.Cookie{
		Name:     t.Sticky.Cookie,
		Value:    t.sign(origin, now.Add(ttl).Unix()),
		Path:     "/",
		MaxAge:   int(ttl.Seconds()),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   r.TLS != nil,
	}
	// A retry within the same request selects again; keep only the last cookie.
	h := w.Header()
	h["Set-Cookie"] = slices.DeleteFunc(h["Set-Cookie"], func(s string) bool {
		return strings.HasPrefix(s, t.Sticky.Cookie+"=")
	})
	http.SetCookie(w, c)
}

var (
	_ caddy.Provisioner     = (*Tiered)(nil)
	_ reverseproxy.Selector = (*Tiered)(nil)
)

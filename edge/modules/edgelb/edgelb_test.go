// SPDX-License-Identifier: Apache-2.0

package edgelb

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/reverseproxy"

	"github.com/ingressd/ingressd/edge/modules/edgestate"
)

type fixture struct {
	t     *Tiered
	pool  reverseproxy.UpstreamPool
	down  map[string]bool // Caddy-side unavailable dials
	store *edgestate.Store
	now   time.Time
}

func newFixture(t *testing.T, steering string, sticky bool, ups ...Upstream) *fixture {
	t.Helper()
	f := &fixture{down: map[string]bool{}, store: &edgestate.Store{}, now: time.Unix(1_700_000_000, 0)}
	f.t = &Tiered{Pool: "web", Steering: steering, Upstreams: ups, store: f.store}
	if sticky {
		f.t.Sticky = &Sticky{Cookie: "edge_aff", TTL: caddy.Duration(time.Hour)}
	}
	f.t.now = func() time.Time { return f.now }
	f.t.avail = func(u *reverseproxy.Upstream) bool { return !f.down[u.Dial] }
	if err := f.t.setup(); err != nil {
		t.Fatal(err)
	}
	for _, u := range ups {
		f.pool = append(f.pool, &reverseproxy.Upstream{Dial: u.Dial, Host: new(reverseproxy.Host)})
	}
	return f
}

// pick runs one selection and returns the chosen origin ("" for none) and
// the response recorder (for cookies).
func (f *fixture) pick(cookie *http.Cookie) (string, *httptest.ResponseRecorder) {
	r := httptest.NewRequest("GET", "http://web/", nil)
	if cookie != nil {
		r.AddCookie(cookie)
	}
	w := httptest.NewRecorder()
	u := f.t.Select(f.pool, r, w)
	if u == nil {
		return "", w
	}
	return f.t.meta[u.Dial].Origin, w
}

func (f *fixture) counts(n int) map[string]int {
	got := map[string]int{}
	for range n {
		o, _ := f.pick(nil)
		got[o]++
	}
	return got
}

func (f *fixture) set(ps edgestate.PoolState) {
	f.store.Set(edgestate.State{Pools: map[string]edgestate.PoolState{"web": ps}})
}

func ptr[T any](v T) *T { return &v }

var threeOrigins = []Upstream{
	{Dial: "10.0.0.1:80", Origin: "a", Priority: 1, Weight: 3},
	{Dial: "10.0.0.2:80", Origin: "b", Priority: 1, Weight: 1},
	{Dial: "10.0.0.3:80", Origin: "c", Priority: 2, Weight: 1},
}

func TestWeightedDistribution(t *testing.T) {
	f := newFixture(t, SteerWeighted, false, threeOrigins...)
	got := f.counts(400)
	if got["a"] != 300 || got["b"] != 100 || got["c"] != 0 {
		t.Fatalf("distribution = %v, want a:300 b:100 c:0", got)
	}
	// Smooth: never more than three a's in a row for 3:1.
	run, maxRun := 0, 0
	for range 40 {
		if o, _ := f.pick(nil); o == "a" {
			run++
			maxRun = max(maxRun, run)
		} else {
			run = 0
		}
	}
	if maxRun > 3 {
		t.Fatalf("weighted picks are bursty: %d a's in a row", maxRun)
	}
}

func TestSteeringPolicies(t *testing.T) {
	for _, s := range []string{SteerRoundRobin, SteerLeastConn, SteerRandom, SteerIPHash, SteerFailover} {
		t.Run(s, func(t *testing.T) {
			f := newFixture(t, s, false, threeOrigins...)
			got := f.counts(200)
			if got["c"] != 0 || got[""] != 0 {
				t.Fatalf("picked outside tier 1: %v", got)
			}
			switch s {
			case SteerRoundRobin:
				if got["a"] != 100 || got["b"] != 100 {
					t.Fatalf("round robin = %v", got)
				}
			case SteerIPHash, SteerFailover:
				if len(got) != 1 {
					t.Fatalf("%s should be stable for one client: %v", s, got)
				}
			case SteerRandom, SteerLeastConn:
				if got["a"] < 50 || got["b"] < 50 {
					t.Fatalf("%s badly skewed: %v", s, got)
				}
			}
		})
	}
}

func TestTierFailover(t *testing.T) {
	f := newFixture(t, SteerWeighted, false, threeOrigins...)

	// Caddy passive health ejects a: b takes all of tier 1.
	f.down["10.0.0.1:80"] = true
	if got := f.counts(20); got["b"] != 20 {
		t.Fatalf("a down: %v", got)
	}
	// Control plane marks b unhealthy: tier 2.
	f.set(edgestate.PoolState{Origins: map[string]edgestate.OriginState{"b": {Healthy: ptr(false)}}})
	if got := f.counts(20); got["c"] != 20 {
		t.Fatalf("tier 1 down: %v", got)
	}
	// Everything down: nil so the handler falls back.
	f.down["10.0.0.3:80"] = true
	if o, _ := f.pick(nil); o != "" {
		t.Fatalf("all down picked %q", o)
	}
	// Tier 1 recovers but the control plane holds the floor at tier 2.
	f.down = map[string]bool{}
	f.set(edgestate.PoolState{Tier: 2})
	if got := f.counts(10); got["c"] != 10 {
		t.Fatalf("failback hold: %v", got)
	}
	// Floor tier empty: lower tiers are used anyway.
	f.down["10.0.0.3:80"] = true
	if got := f.counts(8); got["c"] != 0 || got[""] != 0 {
		t.Fatalf("floor tier down should use tier 1: %v", got)
	}
}

func TestDrainAndDisable(t *testing.T) {
	f := newFixture(t, SteerRoundRobin, true, threeOrigins...)
	// Pin a session to a, then drain a.
	var aCookie *http.Cookie
	for range 4 {
		o, w := f.pick(nil)
		if o == "a" {
			aCookie = w.Result().Cookies()[0]
			break
		}
	}
	if aCookie == nil {
		t.Fatal("never picked a")
	}
	f.set(edgestate.PoolState{Origins: map[string]edgestate.OriginState{"a": {State: edgestate.StateDraining}}})
	if got := f.counts(10); got["b"] != 10 {
		t.Fatalf("draining a still gets new sessions: %v", got)
	}
	if o, _ := f.pick(aCookie); o != "a" {
		t.Fatalf("sticky session on draining origin moved to %q", o)
	}
	// Disabled: even sticky sessions move.
	f.set(edgestate.PoolState{Origins: map[string]edgestate.OriginState{"a": {State: edgestate.StateDisabled}}})
	if o, _ := f.pick(aCookie); o != "b" {
		t.Fatalf("sticky session on disabled origin went to %q", o)
	}
	// Configured draining state behaves the same.
	g := newFixture(t, SteerRoundRobin, false,
		Upstream{Dial: "10.0.0.1:80", Origin: "a", State: edgestate.StateDraining},
		Upstream{Dial: "10.0.0.2:80", Origin: "b"})
	if got := g.counts(6); got["b"] != 6 {
		t.Fatalf("configured draining: %v", got)
	}
}

func TestStickiness(t *testing.T) {
	f := newFixture(t, SteerWeighted, true, threeOrigins...)
	first, w := f.pick(nil)
	cookies := w.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != "edge_aff" || cookies[0].MaxAge != 3600 || !cookies[0].HttpOnly {
		t.Fatalf("cookie = %+v", cookies)
	}
	c := cookies[0]
	for range 20 {
		o, w := f.pick(c)
		if o != first {
			t.Fatalf("sticky request went to %q, pinned %q", o, first)
		}
		if len(w.Result().Cookies()) != 0 {
			t.Fatal("cookie rewritten for a healthy pinned origin")
		}
	}

	// Tampered or expired cookies are ignored.
	// Flip a character in the middle: the last base64 character can differ
	// only in padding bits (decoded identically), which made this flaky.
	bad := *c
	mid := len(c.Value) / 2
	repl := byte('A')
	if c.Value[mid] == 'A' {
		repl = 'B'
	}
	bad.Value = c.Value[:mid] + string(repl) + c.Value[mid+1:]
	if _, w := f.pick(&bad); len(w.Result().Cookies()) != 1 {
		t.Fatal("tampered cookie accepted")
	}
	f.now = f.now.Add(2 * time.Hour)
	if _, w := f.pick(c); len(w.Result().Cookies()) != 1 {
		t.Fatal("expired cookie accepted")
	}

	// Pinned origin unhealthy: rebalanced and cookie rewritten.
	f.now = time.Unix(1_700_000_000, 0)
	f.set(edgestate.PoolState{Origins: map[string]edgestate.OriginState{first: {Healthy: ptr(false)}}})
	o, w := f.pick(c)
	if o == first || o == "" {
		t.Fatalf("unhealthy pinned origin: got %q", o)
	}
	nc := w.Result().Cookies()
	if len(nc) != 1 {
		t.Fatal("cookie not rewritten after rebalance")
	}
	if o2, _ := f.pick(nc[0]); o2 != o {
		t.Fatalf("rewritten cookie pins %q, want %q", o2, o)
	}

	// A cookie for another pool does not verify.
	other := *f.t
	other.Pool = "other"
	if _, ok := other.verify(c.Value, f.now); ok {
		t.Fatal("cookie verified for another pool")
	}
}

func TestOverride(t *testing.T) {
	f := newFixture(t, SteerWeighted, true, threeOrigins...)
	until := f.now.Add(time.Minute)
	f.set(edgestate.PoolState{Override: &edgestate.Override{Tier: 2, Until: &until}})
	if got := f.counts(10); got["c"] != 10 {
		t.Fatalf("forced tier 2: %v", got)
	}
	// Sticky cookies for tier 1 do not escape the override.
	f.set(edgestate.PoolState{})
	_, w := f.pick(nil)
	c := w.Result().Cookies()[0]
	f.set(edgestate.PoolState{Override: &edgestate.Override{Tier: 2, Until: &until}})
	if o, _ := f.pick(c); o != "c" {
		t.Fatalf("pinned request escaped override: %q", o)
	}
	// Forced origin by name.
	f.set(edgestate.PoolState{Override: &edgestate.Override{Origins: []string{"b"}}})
	if got := f.counts(10); got["b"] != 10 {
		t.Fatalf("forced origin b: %v", got)
	}
	// Expired override is ignored.
	f.set(edgestate.PoolState{Override: &edgestate.Override{Tier: 2, Until: &until}})
	f.now = until.Add(time.Second)
	if got := f.counts(8); got["c"] != 0 {
		t.Fatalf("expired override still applied: %v", got)
	}
	// Forced set entirely down: normal selection instead of an outage.
	f.now = time.Unix(1_700_000_000, 0)
	f.down["10.0.0.3:80"] = true
	if got := f.counts(8); got["c"] != 0 || got[""] != 0 {
		t.Fatalf("override to dead tier: %v", got)
	}
}

func TestSetupValidation(t *testing.T) {
	if err := (&Tiered{Steering: "bogus"}).setup(); err == nil {
		t.Fatal("unknown steering accepted")
	}
	if err := (&Tiered{Upstreams: []Upstream{{Origin: "a"}}}).setup(); err == nil {
		t.Fatal("upstream without dial accepted")
	}
}

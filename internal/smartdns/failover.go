// SPDX-License-Identifier: Apache-2.0

package smartdns

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/ingressd/ingressd/pkg/nodeproto"
)

// Exit failover (docs/rev1/EXIT-FAILOVER.md): a service lists exits in order
// of preference, all in one country. New connections use the active exit,
// which only changes when it goes down (failover) or when an earlier exit
// has been healthy for failback_after (failback), so a flapping preferred
// exit does not make the service's egress IP bounce.

const (
	// healthInterval is how often the connector asks exit nodes for the health
	// of the node exits its services use.
	healthInterval = 5 * time.Second
	healthTimeout  = 4 * time.Second
)

// activeExit is one service's exit choice.
type activeExit struct {
	mu      sync.Mutex
	exits   []string
	current string               // exit in use now ("" while every exit is down)
	since   time.Time            // when current was chosen
	healthy map[string]time.Time // exit -> healthy since (absent = not healthy)
	message string               // why exits[0] is not in use
}

// activeFor returns the service's state, kept while its exit list is
// unchanged.
func (m *Manager) activeFor(r route) *activeExit {
	m.activeMu.Lock()
	defer m.activeMu.Unlock()
	a, ok := m.active[r.Service]
	if !ok || !slices.Equal(a.exits, r.Exits) {
		a = &activeExit{exits: slices.Clone(r.Exits), healthy: map[string]time.Time{}}
		m.active[r.Service] = a
	}
	return a
}

// pruneActive drops the state of services that are gone or whose exit list
// changed.
func (m *Manager) pruneActive(routes []route) {
	want := map[string][]string{}
	for _, r := range routes {
		want[r.Service] = r.Exits
	}
	m.activeMu.Lock()
	defer m.activeMu.Unlock()
	for svc, a := range m.active {
		if l, ok := want[svc]; !ok || !slices.Equal(l, a.exits) {
			delete(m.active, svc)
		}
	}
}

func failbackAfter(st *state, _ route) time.Duration { return st.plan.FailbackAfter }

// pick returns the exit new connections of r use, or errExitDown with every
// exit's reason when none is up (fail closed).
func (m *Manager) pick(st *state, r route) (string, error) {
	if len(r.Exits) == 0 {
		return "", fmt.Errorf("%w: service %s has no exit", errExitDown, r.Service)
	}
	up := make([]bool, len(r.Exits))
	why := make([]string, len(r.Exits))
	for i, e := range r.Exits {
		up[i], why[i] = m.exitUp(st, e)
	}
	now := m.now()
	a := m.activeFor(r)
	a.mu.Lock()
	defer a.mu.Unlock()
	for i, e := range r.Exits {
		if !up[i] {
			delete(a.healthy, e)
		} else if _, ok := a.healthy[e]; !ok {
			a.healthy[e] = now
		}
	}

	if cur := slices.Index(r.Exits, a.current); cur >= 0 && up[cur] {
		hold := failbackAfter(st, r)
		for i := range cur {
			if up[i] && now.Sub(a.healthy[r.Exits[i]]) >= hold {
				m.log.Info(fmt.Sprintf("service %s: exit %s healthy for %s, failing back from %s", r.Service, r.Exits[i], now.Sub(a.healthy[r.Exits[i]]).Round(time.Second), a.current))
				a.set(r.Exits[i], now)
				a.message = a.reasonLocked(r.Exits, up, why, i, hold, now)
				return a.current, nil
			}
		}
		a.message = a.reasonLocked(r.Exits, up, why, cur, hold, now)
		return a.current, nil
	}

	for i, e := range r.Exits {
		if !up[i] {
			continue
		}
		if a.current != "" || i > 0 {
			from, reason := a.current, ""
			if from == "" {
				from = r.Exits[0]
			}
			if j := slices.Index(r.Exits, from); j >= 0 {
				reason = why[j]
			}
			m.log.Warn(fmt.Sprintf("service %s: exit %s down (%s), using %s", r.Service, from, reason, e))
		}
		a.set(e, now)
		a.message = a.reasonLocked(r.Exits, up, why, i, failbackAfter(st, r), now)
		return e, nil
	}

	var msg string
	if len(r.Exits) == 1 {
		msg = why[0]
	} else {
		parts := make([]string, len(r.Exits))
		for i, e := range r.Exits {
			parts[i] = e + ": " + why[i]
		}
		msg = strings.Join(parts, "; ")
	}
	if a.current != "" || a.since.IsZero() {
		m.log.Warn(fmt.Sprintf("service %s: every exit is down (%s)", r.Service, msg))
		a.set("", now)
	}
	a.message = msg
	return "", fmt.Errorf("%w: %s", errExitDown, msg)
}

func (a *activeExit) set(exit string, now time.Time) {
	if a.current != exit || a.since.IsZero() {
		a.current, a.since = exit, now
	}
}

// reasonLocked explains, for the status, why the exit at index cur is used
// instead of exits[0].
func (a *activeExit) reasonLocked(exits []string, up []bool, why []string, cur int, hold time.Duration, now time.Time) string {
	if cur == 0 {
		return ""
	}
	if !up[0] {
		return exits[0] + ": " + why[0]
	}
	left := hold - now.Sub(a.healthy[exits[0]])
	return fmt.Sprintf("%s is healthy again; failing back in %s", exits[0], left.Round(time.Second))
}

// refreshActive runs pick for every service, so failover, failback and the
// status follow health even while a service has no traffic.
func (m *Manager) refreshActive(st *state) {
	for _, r := range st.allRoutes() {
		_, _ = m.pick(st, r)
	}
}

// routes returns one route per service, sorted by service.
func (mt matcher) routes() []route {
	seen := map[string]bool{}
	var out []route
	for _, r := range mt {
		if !seen[r.Service] {
			seen[r.Service] = true
			out = append(out, r)
		}
	}
	slices.SortFunc(out, func(a, b route) int { return strings.Compare(a.Service, b.Service) })
	return out
}

// Services reports each service's exits and the one in use.
func (m *Manager) Services() []nodeproto.ServiceStatus {
	out := []nodeproto.ServiceStatus{}
	for _, r := range m.state().allRoutes() {
		a := m.activeFor(r)
		a.mu.Lock()
		s := nodeproto.ServiceStatus{Name: r.Service, Exits: slices.Clone(r.Exits), Active: a.current, Since: a.since.UTC(), Message: a.message}
		a.mu.Unlock()
		s.Failover = s.Active != "" && s.Active != r.Exits[0]
		out = append(out, s)
	}
	return out
}

// usedRemoteExits maps each exit node to the remote exits some enabled
// service lists (usually one: a node has one exit).
func usedRemoteExits(st *state) map[string][]string {
	out := map[string][]string{}
	seen := map[string]bool{}
	for _, r := range st.allRoutes() {
		for _, name := range r.Exits {
			ex, ok := st.exit(name)
			if !ok || ex.Egress != nil || seen[name] {
				continue
			}
			seen[name] = true
			out[ex.Node] = append(out[ex.Node], name)
		}
	}
	for _, l := range out {
		slices.Sort(l)
	}
	return out
}

// pollExitHealth asks every exit node a service uses for its exit's health
// and feeds remoteDown, so the connector knows a node exit is down before a
// client is handed a cached answer for it.
func (m *Manager) pollExitHealth(ctx context.Context) {
	if m.remote == nil {
		return
	}
	st := m.state()
	ctx, cancel := context.WithTimeout(ctx, healthTimeout)
	defer cancel()
	var wg sync.WaitGroup
	for node, exits := range usedRemoteExits(st) {
		if !m.remote.Up(node) {
			continue // the tunnel being down already holds these exits down
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			h, err := m.remote.Health(ctx, node)
			for _, exit := range exits {
				switch {
				case err != nil:
					m.setRemoteDown(exit, true, err.Error())
				case h.Up:
					m.setRemoteDown(exit, false, "")
				default:
					m.setRemoteDown(exit, true, h.Error)
				}
			}
		}()
	}
	wg.Wait()
}

// runHealthPoll polls exit health every healthInterval until ctx ends.
func (m *Manager) runHealthPoll(ctx context.Context) {
	t := time.NewTicker(healthInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		m.pollExitHealth(ctx)
	}
}

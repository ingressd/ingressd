// SPDX-License-Identifier: Apache-2.0

package nodeagent

import (
	"context"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/ingressd/ingressd/internal/l4"
	"github.com/ingressd/ingressd/internal/observe"
	"github.com/ingressd/ingressd/pkg/config"
	"github.com/ingressd/ingressd/pkg/nodeproto"
)

// Live preview limits.
const (
	liveDefaultRate = 20
	liveMaxRate     = 200
	liveMaxDuration = time.Hour
	liveBatchEvery  = 500 * time.Millisecond
	liveBatchMax    = 100
	// livePeerEvery is how often game services are polled for connections;
	// their set keeps a connection for 30 s.
	livePeerEvery = 2 * time.Second
)

// readL4Peers is overridable in tests.
var readL4Peers = l4.ReadPeers

// liveSet holds one connection's live subscriptions.
type liveSet struct {
	a    *Agent
	s    *session
	mu   sync.Mutex
	subs map[string]context.CancelFunc
}

func newLiveSet(a *Agent, s *session) *liveSet {
	return &liveSet{a: a, s: s, subs: map[string]context.CancelFunc{}}
}

func (l *liveSet) start(sub nodeproto.LiveSubscribe) {
	if sub.SubscriptionID == "" || l.a.o.Logs == nil {
		return
	}
	until := sub.Until
	if until.IsZero() || time.Until(until) > liveMaxDuration {
		until = time.Now().Add(liveMaxDuration)
	}
	ctx, cancel := context.WithDeadline(l.s.ctx, until)
	l.mu.Lock()
	if old := l.subs[sub.SubscriptionID]; old != nil {
		old()
	}
	l.subs[sub.SubscriptionID] = cancel
	l.mu.Unlock()
	go func() {
		defer l.stop(sub.SubscriptionID)
		l.a.streamLive(ctx, l.s, sub)
	}()
}

func (l *liveSet) stop(id string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if c := l.subs[id]; c != nil {
		c()
		delete(l.subs, id)
	}
}

func (l *liveSet) stopAll() {
	l.mu.Lock()
	defer l.mu.Unlock()
	for id, c := range l.subs {
		c()
		delete(l.subs, id)
	}
}

// liveFilter decides which entries a subscription wants.
type liveFilter struct {
	hosts map[string]bool
	apps  map[string]bool
	idx   hostIndex
}

func (f liveFilter) match(host string) (app string, ok bool) {
	app = f.idx.app(host)
	if len(f.hosts) == 0 && len(f.apps) == 0 {
		return app, true
	}
	if f.hosts[strings.ToLower(host)] {
		return app, true
	}
	return app, app != "" && f.apps[app]
}

// l4Services lists the game services a subscription wants. They have no
// host, so a host filter leaves them out unless the app is asked for.
func (f liveFilter) l4Services(cfg *config.Config) []string {
	if cfg == nil {
		return nil
	}
	var out []string
	for name := range cfg.L4 {
		if f.apps[name] || (len(f.hosts) == 0 && len(f.apps) == 0) {
			out = append(out, name)
		}
	}
	slices.Sort(out)
	return out
}

// l4Connections returns the connections to services that are not in seen, as
// live entries, and updates seen. A service that cannot be read keeps what
// was seen of it, so its connections are not reported twice.
func l4Connections(ctx context.Context, services []string, seen map[string]map[l4.Peer]bool, now time.Time) []nodeproto.LogEntry {
	var out []nodeproto.LogEntry
	for _, name := range services {
		peers, err := readL4Peers(ctx, name)
		if err != nil {
			continue
		}
		current := make(map[l4.Peer]bool, len(peers))
		for _, p := range peers {
			current[p] = true
			if !seen[name][p] {
				out = append(out, nodeproto.LogEntry{Time: now.UTC(), App: name, Host: name, Method: strings.ToUpper(p.Proto),
					ClientIP: p.IP, Decision: nodeproto.DecisionAllow})
			}
		}
		seen[name] = current
	}
	return out
}

// streamLive forwards matching access-log entries and game connections as
// log batches until ctx ends, sending at most MaxPerSecond entries per
// second and counting the rest as dropped.
func (a *Agent) streamLive(ctx context.Context, s *session, sub nodeproto.LiveSubscribe) {
	f := liveFilter{hosts: map[string]bool{}, apps: map[string]bool{}}
	for _, h := range sub.Hosts {
		f.hosts[strings.ToLower(h)] = true
	}
	for _, ap := range sub.Apps {
		f.apps[ap] = true
	}
	var services []string
	if cfg, err := a.loadConfig(); err == nil {
		f.idx = newHostIndex(cfg)
		services = f.l4Services(cfg)
	} else {
		f.idx = hostIndex{}
	}
	rate := sub.MaxPerSecond
	if rate <= 0 {
		rate = liveDefaultRate
	}
	rate = min(rate, liveMaxRate)

	entries := a.o.Logs.Subscribe(ctx, observe.Filter{})
	tick := time.NewTicker(liveBatchEvery)
	defer tick.Stop()
	var batch []nodeproto.LogEntry
	dropped := 0
	window := time.Now()
	inWindow := 0
	flush := func() {
		if len(batch) == 0 && dropped == 0 {
			return
		}
		_ = a.sendOn(s, nodeproto.TypeLog, "", nodeproto.LogBatch{SubscriptionID: sub.SubscriptionID, Entries: batch, Dropped: dropped})
		batch, dropped = nil, 0
	}
	defer flush()
	add := func(le nodeproto.LogEntry) {
		if now := time.Now(); now.Sub(window) >= time.Second {
			window, inWindow = now, 0
		}
		if inWindow >= rate {
			dropped++
			return
		}
		inWindow++
		batch = append(batch, le)
		if len(batch) >= liveBatchMax {
			flush()
		}
	}
	var peers <-chan time.Time // nil without game services: never fires
	if len(services) > 0 {
		t := time.NewTicker(livePeerEvery)
		defer t.Stop()
		peers = t.C
	}
	seen := map[string]map[l4.Peer]bool{}
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			flush()
		case <-peers:
			for _, le := range l4Connections(ctx, services, seen, time.Now()) {
				add(le)
			}
		case e, ok := <-entries:
			if !ok {
				return
			}
			app, match := f.match(e.Host)
			if !match {
				continue
			}
			add(logEntry(e, app))
		}
	}
}

func logEntry(e observe.Entry, app string) nodeproto.LogEntry {
	le := nodeproto.LogEntry{
		Time: e.Time.UTC(), App: app, Host: e.Host, Method: e.Method,
		Path: RedactQuery(e.Path), Status: e.Status,
		DurationMS: float64(e.Duration.Microseconds()) / 1000, BytesOut: e.Bytes,
		ClientIP: e.ClientIP, UserAgent: e.UA,
	}
	switch e.Status {
	case 429:
		le.Decision = nodeproto.DecisionRateLimit
	default:
		le.Decision = nodeproto.DecisionAllow
		if e.Status == 401 || e.Status == 403 {
			le.Decision = "" // WAF or access policy: not distinguishable from the log line
		}
	}
	return le
}

// RedactQuery keeps a request URI's path and query keys but drops every
// query value: "/a?token=x&b" → "/a?token=&b".
func RedactQuery(uri string) string {
	path, q, ok := strings.Cut(uri, "?")
	if !ok {
		return uri
	}
	if q == "" {
		return path + "?"
	}
	parts := strings.Split(q, "&")
	for i, p := range parts {
		k, _, hasVal := strings.Cut(p, "=")
		if dk, err := url.QueryUnescape(k); err == nil {
			k = url.QueryEscape(dk)
		}
		if hasVal {
			parts[i] = k + "="
		} else {
			parts[i] = k
		}
	}
	return path + "?" + strings.Join(parts, "&")
}

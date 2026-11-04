// SPDX-License-Identifier: Apache-2.0

package nodeagent

import (
	"context"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/ingressd/ingressd/internal/observe"
	"github.com/ingressd/ingressd/pkg/nodeproto"
)

// Live preview limits.
const (
	liveDefaultRate = 20
	liveMaxRate     = 200
	liveMaxDuration = time.Hour
	liveBatchEvery  = 500 * time.Millisecond
	liveBatchMax    = 100
)

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

// streamLive forwards matching access-log entries as log batches until ctx
// ends, sending at most MaxPerSecond entries per second and counting the
// rest as dropped.
func (a *Agent) streamLive(ctx context.Context, s *session, sub nodeproto.LiveSubscribe) {
	f := liveFilter{hosts: map[string]bool{}, apps: map[string]bool{}}
	for _, h := range sub.Hosts {
		f.hosts[strings.ToLower(h)] = true
	}
	for _, ap := range sub.Apps {
		f.apps[ap] = true
	}
	if cfg, err := a.loadConfig(); err == nil {
		f.idx = newHostIndex(cfg)
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
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			flush()
		case e, ok := <-entries:
			if !ok {
				return
			}
			app, match := f.match(e.Host)
			if !match {
				continue
			}
			if now := time.Now(); now.Sub(window) >= time.Second {
				window, inWindow = now, 0
			}
			if inWindow >= rate {
				dropped++
				continue
			}
			inWindow++
			batch = append(batch, logEntry(e, app))
			if len(batch) >= liveBatchMax {
				flush()
			}
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

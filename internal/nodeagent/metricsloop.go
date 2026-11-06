// SPDX-License-Identifier: Apache-2.0

package nodeagent

import (
	"context"
	"slices"
	"sync"
	"time"

	"github.com/ingressd/ingressd/internal/observe"
	"github.com/ingressd/ingressd/pkg/nodeproto"
)

// maxBufferedMetrics is how many 1-minute messages the node keeps for
// resending (an hour, MANAGED.md §9.3).
const maxBufferedMetrics = 60

// MetricsSource is implemented by observers that meter edge metrics
// (*observe.Observer); Options.Logs may implement it.
type MetricsSource interface {
	TakeMetrics() observe.MetricsWindow
}

// metricsBuffer holds the last maxBufferedMetrics messages in memory.
type metricsBuffer struct {
	mu    sync.Mutex
	seq   int64
	acked int64
	// panelAcks is set once the panel acknowledged anything: from then on
	// every unacknowledged message is resent, not only unsent ones.
	panelAcks bool
	items     []bufferedMetrics
}

type bufferedMetrics struct {
	m    nodeproto.Metrics
	sent bool
}

// newMetricsBuffer seeds seq from the clock: the buffer is not persisted,
// and a restarted agent must not reuse seqs the panel already ingested
// (one per minute never catches up with one per second).
func newMetricsBuffer(now time.Time) *metricsBuffer {
	return &metricsBuffer{seq: now.Unix()}
}

func (b *metricsBuffer) add(m nodeproto.Metrics) nodeproto.Metrics {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.seq++
	m.Seq = b.seq
	b.items = append(b.items, bufferedMetrics{m: m})
	if n := len(b.items) - maxBufferedMetrics; n > 0 {
		b.items = b.items[n:]
	}
	return m
}

func (b *metricsBuffer) lastSeq() int64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.seq
}

func (b *metricsBuffer) markSent(seq int64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for i := range b.items {
		if b.items[i].m.Seq == seq {
			b.items[i].sent = true
		}
	}
}

func (b *metricsBuffer) ack(seq int64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.panelAcks = true
	if seq > b.acked {
		b.acked = seq
	}
	b.items = slices.DeleteFunc(b.items, func(it bufferedMetrics) bool { return it.m.Seq <= seq })
}

// resend lists what to send after reconnecting, oldest first.
func (b *metricsBuffer) resend() []nodeproto.Metrics {
	b.mu.Lock()
	defer b.mu.Unlock()
	var out []nodeproto.Metrics
	for _, it := range b.items {
		if it.m.Seq > b.acked && (b.panelAcks || !it.sent) {
			out = append(out, it.m)
		}
	}
	return out
}

// metricsCollector turns samples into points.
type metricsCollector struct {
	sys     *sysReader
	edge    func() *observe.MetricsWindow // nil: no edge metrics
	tunnels func(time.Time) *nodeproto.TunnelMetrics
	prev    *rawSample
}

func (c *metricsCollector) sample(now time.Time) point {
	cur := c.sys.read(now)
	var e *observe.MetricsWindow
	if c.edge != nil {
		e = c.edge()
	}
	var tun *nodeproto.TunnelMetrics
	if c.tunnels != nil {
		tun = c.tunnels(now)
	}
	p := diff(c.prev, cur, e, tun)
	c.prev = cur
	return p
}

// metricsLive is the active live subscription (one per node: the panel
// fans it out to every viewer).
type metricsLive struct {
	s     *session
	id    string
	until time.Time
}

func (a *Agent) startMetricsLive(s *session, sub nodeproto.MetricsSubscribe) {
	if sub.SubscriptionID == "" {
		return
	}
	until := sub.Until
	if limit := time.Now().Add(metricsLiveMax); until.IsZero() || until.After(limit) {
		until = limit
	}
	a.mlMu.Lock()
	a.ml = &metricsLive{s: s, id: sub.SubscriptionID, until: until}
	a.mlMu.Unlock()
	select {
	case a.metricsWake <- struct{}{}:
	default:
	}
}

// stopMetricsLive ends the subscription id ("" = whatever belongs to s).
func (a *Agent) stopMetricsLive(s *session, id string) {
	a.mlMu.Lock()
	defer a.mlMu.Unlock()
	if a.ml != nil && a.ml.s == s && (id == "" || a.ml.id == id) {
		a.ml = nil
	}
}

func (a *Agent) liveTarget(now time.Time) *metricsLive {
	a.mlMu.Lock()
	defer a.mlMu.Unlock()
	if a.ml != nil && !now.Before(a.ml.until) {
		a.ml = nil
	}
	if a.ml == nil {
		return nil
	}
	cp := *a.ml
	return &cp
}

func (a *Agent) newMetricsCollector() *metricsCollector {
	c := &metricsCollector{sys: &sysReader{root: procRoot, stateDir: a.o.StateDir}}
	if ms, ok := a.o.Logs.(MetricsSource); ok {
		c.edge = func() *observe.MetricsWindow { w := ms.TakeMetrics(); return &w }
	}
	c.tunnels = func(now time.Time) *nodeproto.TunnelMetrics {
		cfg, err := a.loadConfig()
		if err != nil || len(cfg.Tunnels) == 0 {
			return nil
		}
		return tunnelMetrics(a.tunnelStatus(cfg, now), len(cfg.Tunnels), now)
	}
	return c
}

// tunnelMetrics summarises tunnel status for metrics.
func tunnelMetrics(ts []nodeproto.TunnelStatus, total int, now time.Time) *nodeproto.TunnelMetrics {
	t := &nodeproto.TunnelMetrics{Total: total}
	var oldest time.Time
	for _, s := range ts {
		if !s.Up {
			continue
		}
		t.Up++
		if s.Transport == "websocket" {
			t.WebSocket++
		}
		if !s.LastHandshake.IsZero() && (oldest.IsZero() || s.LastHandshake.Before(oldest)) {
			oldest = s.LastHandshake
		}
	}
	if !oldest.IsZero() {
		t.OldestHandshakeSeconds = int64(now.Sub(oldest).Seconds())
	}
	return t
}

// metricsLoop samples whether or not the panel is connected, so the buffer
// covers outages.
func (a *Agent) metricsLoop(ctx context.Context) {
	c := a.newMetricsCollector()
	c.sample(time.Now()) // baseline for the first rates
	w := newWindow(time.Now())
	for {
		every := a.o.MetricsSample
		live := a.liveTarget(time.Now())
		if live != nil {
			every = min(every, a.o.MetricsLive)
		}
		select {
		case <-ctx.Done():
			return
		case <-a.metricsWake: // a live subscription started: sample now
		case <-time.After(every):
		}
		now := time.Now()
		p := c.sample(now)
		w.add(p)
		if live = a.liveTarget(now); live != nil {
			lw := newWindow(now)
			lw.add(p)
			m := lw.metrics(a.appOf())
			if a.sendOn(live.s, nodeproto.TypeMetricsLive, "", nodeproto.MetricsLive{SubscriptionID: live.id, Metrics: m}) != nil {
				a.stopMetricsLive(live.s, live.id)
			}
		}
		if now.Sub(w.from) >= a.o.MetricsInterval {
			m := a.metrics.add(w.metrics(a.appOf()))
			if a.send(nodeproto.TypeMetrics, "", m) == nil {
				a.metrics.markSent(m.Seq)
			}
			w = newWindow(now)
		}
	}
}

// appOf maps request hosts to app keys with the current config.
func (a *Agent) appOf() func(string) string {
	cfg, err := a.loadConfig()
	if err != nil {
		return nil
	}
	return newHostIndex(cfg).app
}

// resendMetrics sends buffered metrics on a new connection.
func (a *Agent) resendMetrics(s *session) {
	for _, m := range a.metrics.resend() {
		if a.sendOn(s, nodeproto.TypeMetrics, "", m) == nil {
			a.metrics.markSent(m.Seq)
		}
	}
}

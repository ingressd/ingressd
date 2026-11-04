// SPDX-License-Identifier: Apache-2.0

package alerts

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/ingressd/ingressd/pkg/config"
)

// DefaultRepeatAfter re-sends still-firing alerts once a day.
const DefaultRepeatAfter = 24 * time.Hour

// EngineOptions configure an Engine.
type EngineOptions struct {
	// StatePath persists alert state (JSON) so restarts neither re-send
	// firing alerts nor lose pending recoveries. Empty keeps it in memory.
	StatePath string
	// Email sends email-channel notifications (Phase 3's SES/SMTP sender).
	Email  Sender
	Log    *slog.Logger
	Client *http.Client
	// Now is the clock (tests).
	Now func() time.Time
}

// Engine deduplicates events and routes them to channels by rule.
type Engine struct {
	opts  EngineOptions
	log   *slog.Logger
	queue chan Event

	mu       sync.Mutex
	edge     string
	rules    []config.AlertRule
	quiet    *quietHours
	repeat   time.Duration
	channels map[string]Channel
	state    map[string]*State
	sent     map[string][2]int64 // channel → [ok, failed]
}

// State is one alert's status.
type State struct {
	Event    Event     `json:"event"` // latest firing event
	Since    time.Time `json:"since"`
	Firing   bool      `json:"firing"`
	Notified bool      `json:"notified"` // the firing notice was sent
	LastSent time.Time `json:"last_sent"`
	// RecoveryPending: resolved during quiet hours; recovery not yet sent.
	RecoveryPending bool `json:"recovery_pending,omitempty"`
}

func stateKey(k Kind, key string) string { return string(k) + "\x00" + key }

// NewEngine creates an engine. Call Configure, then Run.
func NewEngine(opts EngineOptions) *Engine {
	if opts.Log == nil {
		opts.Log = slog.New(slog.DiscardHandler)
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	e := &Engine{
		opts: opts, log: opts.Log,
		queue:    make(chan Event, 1000),
		repeat:   DefaultRepeatAfter,
		channels: map[string]Channel{},
		state:    map[string]*State{},
		sent:     map[string][2]int64{},
	}
	e.loadState()
	return e
}

// Configure (re)builds channels and rules from the config. Channels whose
// secrets cannot be resolved are skipped and reported in the error.
func (e *Engine) Configure(cfg *config.Config, res Resolver) error {
	var errs []error
	chans := map[string]Channel{}
	for name, c := range cfg.Alerts.Channels {
		ch, err := NewChannel(c, res, e.opts.Email, e.opts.Client)
		if err != nil {
			errs = append(errs, fmt.Errorf("alerts.channels.%s: %w", name, err))
			continue
		}
		chans[name] = ch
	}
	var q *quietHours
	if qh := cfg.Alerts.QuietHours; qh != nil {
		var err error
		if q, err = newQuietHours(*qh); err != nil {
			errs = append(errs, err)
		}
	}
	e.mu.Lock()
	e.edge = cfg.Edge.Name
	e.rules = cfg.Alerts.Rules
	e.channels = chans
	e.quiet = q
	e.repeat = DefaultRepeatAfter
	if r := cfg.Alerts.RepeatAfter; r != nil {
		e.repeat = time.Duration(*r)
	}
	e.mu.Unlock()
	return errors.Join(errs...)
}

// Publish queues an event. It never blocks; events are dropped (and
// logged) if the queue is full.
func (e *Engine) Publish(ev Event) {
	select {
	case e.queue <- ev:
	default:
		e.log.Warn("alert queue full; dropping event", "event", ev.Kind, "key", ev.Key)
	}
}

// Run processes events until ctx is done. Once a minute it sends alerts
// held by quiet hours and reminders for long-firing alerts.
func (e *Engine) Run(ctx context.Context) {
	tick := time.NewTicker(time.Minute)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case ev := <-e.queue:
			e.Process(ctx, ev)
		case <-tick.C:
			e.Tick(ctx)
		}
	}
}

// Process handles one event synchronously (Run calls it; tests use it).
func (e *Engine) Process(ctx context.Context, ev Event) {
	now := e.opts.Now()
	ev.normalize(now)
	e.mu.Lock()
	k := stateKey(ev.Kind, ev.Key)
	st := e.state[k]
	quiet := e.quietNow(now, ev.Kind)
	var send *Notification
	if !ev.Resolved {
		switch {
		case st == nil || (!st.Firing && !st.RecoveryPending):
			st = &State{Event: ev, Since: now, Firing: true}
			e.state[k] = st
			if !quiet {
				send = &Notification{Event: ev}
			}
		case st.RecoveryPending:
			// Flapped back during quiet hours before its recovery was sent:
			// from the user's point of view it never recovered.
			st.Firing, st.RecoveryPending, st.Event = true, false, ev
		default:
			st.Event = ev
			if st.Notified && e.repeat > 0 && now.Sub(st.LastSent) >= e.repeat && !quiet {
				send = &Notification{Event: ev, Reminder: true}
			}
		}
	} else if st != nil && st.Firing {
		switch {
		case !st.Notified:
			delete(e.state, k) // never told anyone; nothing to recover
		case quiet:
			st.Firing, st.RecoveryPending = false, true
		default:
			delete(e.state, k)
			send = &Notification{Event: ev}
		}
	}
	if send != nil {
		send.Edge = e.edge
		if !send.Resolved {
			st.Notified, st.LastSent = true, now
		}
	}
	e.mu.Unlock()
	if send != nil {
		e.deliver(ctx, *send)
	}
	e.saveState()
}

// Tick sends held alerts once quiet hours end, and reminders.
func (e *Engine) Tick(ctx context.Context) {
	now := e.opts.Now()
	var out []Notification
	e.mu.Lock()
	for k, st := range e.state {
		if e.quietNow(now, st.Event.Kind) {
			continue
		}
		switch {
		case st.RecoveryPending:
			ev := st.Event
			ev.Resolved, ev.Title, ev.Severity, ev.Time = true, "", "", now
			ev.normalize(now)
			out = append(out, Notification{Event: ev, Edge: e.edge})
			delete(e.state, k)
		case st.Firing && !st.Notified:
			out = append(out, Notification{Event: st.Event, Edge: e.edge})
			st.Notified, st.LastSent = true, now
		case st.Firing && e.repeat > 0 && now.Sub(st.LastSent) >= e.repeat:
			out = append(out, Notification{Event: st.Event, Edge: e.edge, Reminder: true})
			st.LastSent = now
		}
	}
	e.mu.Unlock()
	for _, n := range out {
		e.deliver(ctx, n)
	}
	if len(out) > 0 {
		e.saveState()
	}
}

// quietNow reports whether kind is held right now. Caller holds e.mu.
func (e *Engine) quietNow(now time.Time, k Kind) bool {
	return e.quiet != nil && e.quiet.active(now) && !slices.Contains(e.quiet.except, string(k))
}

// routes returns the channel names subscribed to kind.
func (e *Engine) routes(k Kind) []string {
	var names []string
	for _, r := range e.rules {
		if slices.Contains(r.On, string(k)) {
			for _, n := range r.Notify {
				if !slices.Contains(names, n) {
					names = append(names, n)
				}
			}
		}
	}
	return names
}

func (e *Engine) deliver(ctx context.Context, n Notification) {
	e.mu.Lock()
	names := e.routes(n.Kind)
	chans := map[string]Channel{}
	for _, name := range names {
		if ch := e.channels[name]; ch != nil {
			chans[name] = ch
		}
	}
	e.mu.Unlock()
	if len(names) == 0 {
		e.log.Info("alert (no channel subscribed)", "event", n.Kind, "key", n.Key, "resolved", n.Resolved)
		return
	}
	for _, name := range names {
		ch := chans[name]
		var err error
		if ch == nil {
			err = errors.New("channel not configured")
		} else {
			// Two attempts: transient network errors are common.
			for attempt := 0; attempt < 2; attempt++ {
				cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
				err = ch.Send(cctx, n)
				cancel()
				if err == nil || errors.Is(err, ErrEmailNotConfigured) || ctx.Err() != nil {
					break
				}
				time.Sleep(time.Second)
			}
		}
		e.mu.Lock()
		c := e.sent[name]
		if err != nil {
			c[1]++
		} else {
			c[0]++
		}
		e.sent[name] = c
		e.mu.Unlock()
		if err != nil {
			e.log.Warn("sending alert failed", "channel", name, "event", n.Kind, "key", n.Key, "err", err)
		} else {
			e.log.Info("alert sent", "channel", name, "event", n.Kind, "key", n.Key, "resolved", n.Resolved)
		}
	}
}

// Test sends a test notification to one channel, bypassing rules, dedup
// and quiet hours.
func (e *Engine) Test(ctx context.Context, channel string) error {
	e.mu.Lock()
	ch := e.channels[channel]
	edge := e.edge
	e.mu.Unlock()
	if ch == nil {
		return fmt.Errorf("unknown or unconfigured channel %q", channel)
	}
	ev := Event{Kind: "test", Key: channel, Severity: Info,
		Title: "ingressd test notification", Message: "If you can read this, channel " + channel + " works."}
	ev.normalize(e.opts.Now())
	return ch.Send(ctx, Notification{Event: ev, Edge: edge})
}

// Firing returns the currently firing alerts, oldest first.
func (e *Engine) Firing() []State {
	e.mu.Lock()
	defer e.mu.Unlock()
	var out []State
	for _, st := range e.state {
		if st.Firing {
			out = append(out, *st)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Since.Before(out[j].Since) })
	return out
}

// SentCounts returns notifications sent per channel as [ok, failed].
func (e *Engine) SentCounts() map[string][2]int64 {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make(map[string][2]int64, len(e.sent))
	for k, v := range e.sent {
		out[k] = v
	}
	return out
}

func (e *Engine) loadState() {
	if e.opts.StatePath == "" {
		return
	}
	b, err := os.ReadFile(e.opts.StatePath)
	if err != nil {
		return
	}
	var sts []*State
	if err := json.Unmarshal(b, &sts); err != nil {
		e.log.Warn("ignoring corrupt alert state", "path", e.opts.StatePath, "err", err)
		return
	}
	for _, st := range sts {
		e.state[stateKey(st.Event.Kind, st.Event.Key)] = st
	}
}

func (e *Engine) saveState() {
	if e.opts.StatePath == "" {
		return
	}
	e.mu.Lock()
	sts := make([]*State, 0, len(e.state))
	for _, st := range e.state {
		sts = append(sts, st)
	}
	b, err := json.MarshalIndent(sts, "", "  ")
	e.mu.Unlock()
	if err != nil {
		return
	}
	tmp := e.opts.StatePath + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err == nil {
		err = os.Rename(tmp, e.opts.StatePath)
	}
	if err != nil {
		e.log.Warn("saving alert state", "err", err)
	}
}

type quietHours struct {
	start, end int // minutes after midnight
	loc        *time.Location
	except     []string
}

func newQuietHours(q config.QuietHours) (*quietHours, error) {
	s, err := config.ParseClock(q.Start)
	if err != nil {
		return nil, fmt.Errorf("alerts.quiet_hours.start: %w", err)
	}
	en, err := config.ParseClock(q.End)
	if err != nil {
		return nil, fmt.Errorf("alerts.quiet_hours.end: %w", err)
	}
	loc := time.Local
	if q.Timezone != "" {
		if loc, err = time.LoadLocation(q.Timezone); err != nil {
			return nil, fmt.Errorf("alerts.quiet_hours.timezone: %w", err)
		}
	}
	return &quietHours{start: s, end: en, loc: loc, except: q.Except}, nil
}

func (q *quietHours) active(now time.Time) bool {
	t := now.In(q.loc)
	m := t.Hour()*60 + t.Minute()
	if q.start <= q.end {
		return m >= q.start && m < q.end
	}
	return m >= q.start || m < q.end // spans midnight
}

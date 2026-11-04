// SPDX-License-Identifier: Apache-2.0

package health

import "time"

// EventType names a health event. Alerts (Phase 10) subscribe to these.
type EventType string

const (
	// EventOriginDown / EventOriginUp: an origin's effective health changed
	// (after flap protection, or instantly when its tunnel went down/up).
	EventOriginDown EventType = "origin_down"
	EventOriginUp   EventType = "origin_up"
	// EventPoolFailover: the pool moved to a lower-priority tier because its
	// active tier has no healthy origin. FromTier/ToTier are set.
	EventPoolFailover EventType = "pool_failover"
	// EventPoolFailback: the pool returned to a higher-priority tier (after
	// failback_hold, or a manual failback).
	EventPoolFailback EventType = "pool_failback"
	// EventPoolAllDown: no origin in any tier is healthy. EventPoolRecovered
	// follows when one is again.
	EventPoolAllDown   EventType = "pool_all_down"
	EventPoolRecovered EventType = "pool_recovered"
	// EventTunnelDown / EventTunnelUp: a tunnel's WireGuard handshake went
	// stale (or its interface vanished) / recovered. Origin events for the
	// tunnel's origins follow.
	EventTunnelDown EventType = "tunnel_down"
	EventTunnelUp   EventType = "tunnel_up"
)

// Event is one health state change.
type Event struct {
	Type   EventType `json:"type"`
	Time   time.Time `json:"time"`
	Pool   string    `json:"pool,omitempty"`
	Origin string    `json:"origin,omitempty"`
	Tunnel string    `json:"tunnel,omitempty"`
	// FromTier and ToTier are set for failover and failback.
	FromTier int `json:"from_tier,omitempty"`
	ToTier   int `json:"to_tier,omitempty"`
	// Reason is a human-readable cause, e.g. "3 failed checks: HTTP 503".
	Reason string `json:"reason,omitempty"`
}

// Sink receives health events. HealthEvent is called from a single
// dispatcher goroutine, in order; it should not block for long (slow sinks
// delay later events, and events are dropped if the queue fills).
type Sink interface {
	HealthEvent(Event)
}

// SinkFunc adapts a function to Sink.
type SinkFunc func(Event)

func (f SinkFunc) HealthEvent(e Event) { f(e) }

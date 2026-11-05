// SPDX-License-Identifier: Apache-2.0

// Package edgestate holds runtime state that the ingressd control plane
// pushes into Caddy without a config reload: pool health, runtime origin
// states (drain/disable) and manual overrides, plus the key that signs
// sticky-session cookies.
//
// The control plane replaces the whole state with
//
//	POST /ingressd/state   (Caddy admin API, unix socket)
//
// and can read it back with GET. Modules such as edge_tiered read it
// lock-free from an atomic snapshot. The state lives in a process-wide store
// rather than in the app instance, so it survives config reloads.
package edgestate

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/caddyserver/caddy/v2"
)

func init() {
	caddy.RegisterModule(App{})
	caddy.RegisterModule(adminAPI{})
}

// Origin states, matching config.OriginActive etc.
const (
	StateActive   = "active"
	StateDraining = "draining"
	StateDisabled = "disabled"
)

// State is the full runtime state for all pools.
type State struct {
	// Version increases with every update; assigned by the store.
	Version uint64 `json:"version"`
	// Updated is when the control plane last pushed.
	Updated time.Time            `json:"updated"`
	Pools   map[string]PoolState `json:"pools,omitempty"`
	// Tunnels holds the tunnels the control plane found down (stale
	// handshake or missing interface); absent tunnels are up.
	Tunnels map[string]TunnelState `json:"tunnels,omitempty"`
}

// TunnelState is the control plane's view of one tunnel.
type TunnelState struct {
	Down bool `json:"down,omitempty"`
}

// PoolState is the runtime state of one pool.
type PoolState struct {
	// Tier is the lowest priority tier the pool may use for new sessions
	// (failback hold / manual failback). Zero means no restriction. When no
	// tier at or above it has a usable origin, lower tiers are used anyway.
	Tier     int                    `json:"tier,omitempty"`
	Origins  map[string]OriginState `json:"origins,omitempty"`
	Override *Override              `json:"override,omitempty"`
}

// OriginState is the control plane's view of one origin. Origins that are
// absent from the state are treated as healthy, in their configured state.
type OriginState struct {
	// Healthy is the active health check result; nil means unknown (healthy).
	Healthy *bool `json:"healthy,omitempty"`
	// State, when set, replaces the configured state (runtime drain/disable).
	State  string `json:"state,omitempty"`
	Reason string `json:"reason,omitempty"`
}

// Override forces traffic to a tier and/or a set of origins.
type Override struct {
	Tier    int        `json:"tier,omitempty"`
	Origins []string   `json:"origins,omitempty"`
	Until   *time.Time `json:"until,omitempty"`
	Reason  string     `json:"reason,omitempty"`
}

// Active reports whether the override applies at now.
func (o *Override) Active(now time.Time) bool {
	if o == nil || (o.Tier == 0 && len(o.Origins) == 0) {
		return false
	}
	return o.Until == nil || now.Before(*o.Until)
}

// Matches reports whether an origin with the given name and priority is in
// the forced set.
func (o *Override) Matches(origin string, priority int) bool {
	if o.Tier != 0 && priority != o.Tier {
		return false
	}
	return len(o.Origins) == 0 || slices.Contains(o.Origins, origin)
}

// Update is the body of POST /ingressd/state.
type Update struct {
	State
	// StickyKey (base64 in JSON) signs sticky-session cookies. The control
	// plane keeps it stable across restarts. Empty keeps the current key.
	StickyKey []byte `json:"sticky_key,omitempty"`
}

// Store is the process-wide state holder.
type Store struct {
	state   atomic.Pointer[State]
	key     atomic.Pointer[[]byte]
	keyOnce sync.Once
	mu      sync.Mutex // serialises writers
}

var global = &Store{}

// Global returns the process-wide store.
func Global() *Store { return global }

var empty = &State{}

// Snapshot returns the current state. It is never nil and must not be modified.
func (s *Store) Snapshot() *State {
	if st := s.state.Load(); st != nil {
		return st
	}
	return empty
}

// Set replaces the state and returns its new version.
func (s *Store) Set(st State) uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	st.Version = s.Snapshot().Version + 1
	if st.Updated.IsZero() {
		st.Updated = time.Now()
	}
	s.state.Store(&st)
	return st.Version
}

// StickyKey returns the cookie signing key. Until the control plane pushes
// one, a random per-process key is used.
func (s *Store) StickyKey() []byte {
	s.keyOnce.Do(func() {
		if s.key.Load() != nil {
			return
		}
		k := make([]byte, 32)
		_, _ = rand.Read(k)
		s.key.CompareAndSwap(nil, &k)
	})
	return *s.key.Load()
}

// SetStickyKey replaces the cookie signing key.
func (s *Store) SetStickyKey(k []byte) {
	k = slices.Clone(k)
	s.key.Store(&k)
}

// App is the edge_state Caddy app. It has no configuration of its own; it
// is the documented home of the runtime state, and modules that need the
// state load it with ctx.App("edge_state").
type App struct{}

func (App) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "edge_state",
		New: func() caddy.Module { return new(App) },
	}
}

// Store returns the runtime state store.
func (*App) Store() *Store { return global }

func (*App) Start() error { return nil }
func (*App) Stop() error  { return nil }

// adminAPI serves /ingressd/state on Caddy's admin endpoint.
type adminAPI struct{}

func (adminAPI) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "admin.api.edge_state",
		New: func() caddy.Module { return new(adminAPI) },
	}
}

func (adminAPI) Routes() []caddy.AdminRoute {
	return []caddy.AdminRoute{{Pattern: "/ingressd/state", Handler: caddy.AdminHandlerFunc(handleState)}}
}

// maxBody bounds a state push; real states are a few KB.
const maxBody = 4 << 20

func handleState(w http.ResponseWriter, r *http.Request) error {
	switch r.Method {
	case http.MethodGet:
		w.Header().Set("Content-Type", "application/json")
		return json.NewEncoder(w).Encode(global.Snapshot())
	case http.MethodPost, http.MethodPut:
		b, err := io.ReadAll(io.LimitReader(r.Body, maxBody))
		if err != nil {
			return caddy.APIError{HTTPStatus: http.StatusBadRequest, Err: err}
		}
		var u Update
		if err := json.Unmarshal(b, &u); err != nil {
			return caddy.APIError{HTTPStatus: http.StatusBadRequest, Err: fmt.Errorf("decoding state: %w", err)}
		}
		if len(u.StickyKey) > 0 {
			if len(u.StickyKey) < 16 {
				return caddy.APIError{HTTPStatus: http.StatusBadRequest, Err: fmt.Errorf("sticky_key must be at least 16 bytes")}
			}
			global.SetStickyKey(u.StickyKey)
		}
		v := global.Set(u.State)
		w.Header().Set("Content-Type", "application/json")
		return json.NewEncoder(w).Encode(map[string]uint64{"version": v})
	default:
		return caddy.APIError{HTTPStatus: http.StatusMethodNotAllowed, Err: fmt.Errorf("method %s not allowed", r.Method)}
	}
}

var (
	_ caddy.App         = (*App)(nil)
	_ caddy.AdminRouter = (*adminAPI)(nil)
)

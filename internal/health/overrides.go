// SPDX-License-Identifier: Apache-2.0

package health

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/ingressd/ingressd/pkg/config"
)

// File names in the state directory.
const (
	OverridesFile = "pool-overrides.json"
	StatusFile    = "pool-health.json"
	StickyKeyFile = "lb-sticky.key"
)

// Overrides are runtime (not config) changes to pools: drained or disabled
// origins, forced tiers/origins and manual failback requests. They live in
// <state-dir>/pool-overrides.json; the monitor re-reads the file when it
// changes and pushes the result to the edge.
type Overrides struct {
	Pools map[string]*PoolOverrides `json:"pools,omitempty"`
}

type PoolOverrides struct {
	Origins map[string]OriginOverride `json:"origins,omitempty"`
	Force   *Force                    `json:"force,omitempty"`
	// FailbackAt requests a manual failback (failback: manual pools, or to
	// skip failback_hold). Requests older than the pending recovery are
	// ignored.
	FailbackAt *time.Time `json:"failback_at,omitempty"`
}

// OriginOverride replaces an origin's configured state.
type OriginOverride struct {
	State  string     `json:"state"` // active, draining or disabled
	Until  *time.Time `json:"until,omitempty"`
	Reason string     `json:"reason,omitempty"`
	By     string     `json:"by,omitempty"`
	At     time.Time  `json:"at"`
}

// Force pins a pool's traffic to a tier and/or named origins.
type Force struct {
	Tier    int        `json:"tier,omitempty"`
	Origins []string   `json:"origins,omitempty"`
	Until   *time.Time `json:"until,omitempty"`
	Reason  string     `json:"reason,omitempty"`
	By      string     `json:"by,omitempty"`
	At      time.Time  `json:"at"`
}

func expired(until *time.Time, now time.Time) bool { return until != nil && !now.Before(*until) }

// Active reports whether the force applies at now.
func (f *Force) Active(now time.Time) bool {
	return f != nil && (f.Tier != 0 || len(f.Origins) > 0) && !expired(f.Until, now)
}

// OriginState returns the runtime state override for an origin, if any.
func (o *Overrides) OriginState(pool, origin string, now time.Time) (OriginOverride, bool) {
	p := o.Pools[pool]
	if p == nil {
		return OriginOverride{}, false
	}
	ov, ok := p.Origins[origin]
	if !ok || expired(ov.Until, now) {
		return OriginOverride{}, false
	}
	return ov, true
}

// Pool returns the pool's overrides, creating them.
func (o *Overrides) Pool(name string) *PoolOverrides {
	if o.Pools == nil {
		o.Pools = map[string]*PoolOverrides{}
	}
	p := o.Pools[name]
	if p == nil {
		p = &PoolOverrides{}
		o.Pools[name] = p
	}
	return p
}

// Prune drops expired entries and pools/origins that no longer exist in cfg.
func (o *Overrides) Prune(cfg *config.Config, now time.Time) {
	for name, p := range o.Pools {
		pool, ok := cfg.Pools[name]
		if !ok {
			delete(o.Pools, name)
			continue
		}
		for origin, ov := range p.Origins {
			if expired(ov.Until, now) || !hasOrigin(pool, origin) {
				delete(p.Origins, origin)
			}
		}
		if p.Force != nil && !p.Force.Active(now) {
			p.Force = nil
		}
		if len(p.Origins) == 0 && p.Force == nil && p.FailbackAt == nil {
			delete(o.Pools, name)
		}
	}
}

func hasOrigin(p config.Pool, name string) bool {
	for _, o := range p.Origins {
		if o.Name == name {
			return true
		}
	}
	return false
}

// LoadOverrides reads the overrides file; a missing file is empty.
func LoadOverrides(stateDir string) (*Overrides, error) {
	var o Overrides
	if err := readJSON(filepath.Join(stateDir, OverridesFile), &o); err != nil {
		return nil, err
	}
	return &o, nil
}

// SaveOverrides writes the overrides file atomically.
func SaveOverrides(stateDir string, o *Overrides) error {
	return writeJSON(filepath.Join(stateDir, OverridesFile), o)
}

func readJSON(path string, v any) error {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := json.Unmarshal(b, v); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}

func writeJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o640); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

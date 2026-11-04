// SPDX-License-Identifier: Apache-2.0

// Package apply pushes a rendered plan to the kernel, nftables and Caddy,
// rolling back to the last successfully applied plan if any step fails.
package apply

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/ingressd/ingressd/internal/render"
)

// Backends are the side-effecting steps, in apply order. A nil backend is
// skipped (useful in tests).
type Backends struct {
	Net   func(ctx context.Context, n render.Network) error
	NFT   func(ctx context.Context, script string) error
	Caddy func(ctx context.Context, cfg json.RawMessage) error
}

type Engine struct {
	Backends
	// StatePath stores the last successfully applied plan (mode 0600; it
	// contains keys and tokens).
	StatePath string
}

// Last returns the last applied plan, or nil if nothing was applied yet.
func (e *Engine) Last() (*render.Plan, error) {
	b, err := os.ReadFile(e.StatePath)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var p render.Plan
	if err := json.Unmarshal(b, &p); err != nil {
		return nil, fmt.Errorf("decode %s: %w", e.StatePath, err)
	}
	return &p, nil
}

// Apply brings the system to plan. On failure it re-applies the previous
// plan (best effort) and returns the original error.
func (e *Engine) Apply(ctx context.Context, plan *render.Plan) error {
	prev, err := e.Last()
	if err != nil {
		return err
	}
	if err := e.applyAll(ctx, plan); err != nil {
		if prev == nil {
			return err
		}
		if rerr := e.applyAll(ctx, prev); rerr != nil {
			return fmt.Errorf("%w; rolling back also failed: %v", err, rerr)
		}
		return fmt.Errorf("%w (rolled back to the previous configuration)", err)
	}
	return e.save(plan)
}

func (e *Engine) applyAll(ctx context.Context, p *render.Plan) error {
	if e.Net != nil {
		if err := e.Net(ctx, p.Network); err != nil {
			return fmt.Errorf("network: %w", err)
		}
	}
	if e.NFT != nil {
		if err := e.NFT(ctx, p.NFT); err != nil {
			return fmt.Errorf("nftables: %w", err)
		}
	}
	if e.Caddy != nil {
		if err := e.Caddy(ctx, p.Caddy); err != nil {
			return fmt.Errorf("caddy: %w", err)
		}
	}
	return nil
}

func (e *Engine) save(p *render.Plan) error {
	b, err := json.Marshal(p)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(e.StatePath), 0o700); err != nil {
		return err
	}
	tmp := e.StatePath + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, e.StatePath)
}

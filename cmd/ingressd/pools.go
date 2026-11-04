// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"log/slog"

	"github.com/ingressd/ingressd/internal/health"
)

// startPoolMonitor runs pool health checks for `ingressd serve` and pushes
// pool state to the edge. Call SetConfig on the result after every apply.
// Later phases (alerts, UI) subscribe to its events with Subscribe.
func startPoolMonitor(ctx context.Context, e *env, log *slog.Logger) *health.Monitor {
	m := health.New(health.Options{
		StateDir: e.stateDir,
		Push:     health.NewPusher(e.adminSocket()).Push,
		Log:      log,
	})
	go m.Run(ctx)
	return m
}

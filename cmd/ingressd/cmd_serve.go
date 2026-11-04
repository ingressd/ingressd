// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/ingressd/ingressd/internal/controlsrv"
	"github.com/ingressd/ingressd/internal/crawler"
	"github.com/ingressd/ingressd/pkg/config"
)

func newServeCmd(e *env) *cobra.Command {
	var interval time.Duration
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Run the control plane: apply at startup and whenever config.yaml changes",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			return serve(ctx, e, interval)
		},
	}
	cmd.Flags().DurationVar(&interval, "watch-interval", 5*time.Second, "how often to check config.yaml for changes")
	cmd.Flags().StringVar(&metricsListen, "metrics-listen", "", "also serve Prometheus /metrics on this TCP address (e.g. 127.0.0.1:9464)")
	return cmd
}

func serve(ctx context.Context, e *env, interval time.Duration) error {
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))

	mux := &controlsrv.Mux{}
	if err := os.MkdirAll(e.runDir, 0o750); err != nil {
		return err
	}
	ops := startOps(ctx, e, log)
	srvErr := make(chan error, 1)
	go func() { srvErr <- controlsrv.Serve(ctx, e.controlSocket(), mux) }()
	go serveTunnelControl(ctx, e, log)
	pools := startPoolMonitor(ctx, e, log)
	go crawler.RunScheduler(ctx, e.loadConfig, e.stateDir, log)

	geoipChanged := startGeoIPUpdater(ctx, e, log)
	sd := startSmartDNS(ctx, e, log)
	refresh := func(cfg *config.Config) {
		mux.SetHosts(controlHandlers(cfg, e))
		sd.applied(cfg)
		pools.SetConfig(cfg)
	}
	// Managed mode (rev1): while node.json exists the panel is the source of
	// truth and the agent applies its snapshots; local edits are ignored.
	managed := newManagedMode(e, log, ops, refresh)
	managed.storage = startStorageRelay(ctx, e, log)
	managed.startup()
	var lastMod time.Time
	first, geoip := true, false
	tick := time.NewTicker(interval)
	defer tick.Stop()
	for {
		if fi, err := os.Stat(e.configPath()); err != nil {
			log.Error("stat config", "err", err)
		} else if !first && !geoip && fi.ModTime() != lastMod && managed.active() {
			if managed.checkLocalEdit() {
				lastMod = fi.ModTime()
			}
		} else if first || fi.ModTime() != lastMod {
			// Kernel state (interfaces, routes, nftables) does not survive a
			// reboot, so the first apply is always forced.
			o := applyOpts{force: first, author: "ingressd", message: "Apply config.yaml change"}
			if first {
				o.message = "Apply at startup"
			}
			err := runApply(ctx, e, logWriter{log}, o)
			ops.applied(err)
			if err != nil {
				log.Error("apply failed; keeping previous configuration", "err", err)
			} else {
				lastMod = fi.ModTime()
				first, geoip = false, false
				if cfg, err := e.loadConfig(); err == nil {
					refresh(cfg)
				}
			}
		}
		if managed.poll(ctx) {
			lastMod = time.Time{} // detached: config.yaml is the source of truth again
		}
		select {
		case <-ctx.Done():
			return nil
		case err := <-srvErr:
			return err
		case <-tick.C:
		case <-geoipChanged:
			lastMod, geoip = time.Time{}, true // re-render with the new GeoIP database
			managed.startup()                  // never re-apply a local edit while managed
		case done := <-reapplyCh: // a connector enrolled: its key must take effect now
			err := runApply(ctx, e, logWriter{log}, applyOpts{author: "ingressd", message: "Apply after connector enrollment"})
			if cfg, lerr := e.loadConfig(); err == nil && lerr == nil {
				refresh(cfg)
			}
			done <- err
		}
	}
}

// logWriter adapts runApply's progress output to structured logs.
type logWriter struct{ log *slog.Logger }

func (w logWriter) Write(p []byte) (int, error) {
	w.log.Info(string(trimNL(p)))
	return len(p), nil
}

func trimNL(b []byte) []byte {
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == '\r') {
		b = b[:len(b)-1]
	}
	return b
}

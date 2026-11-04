// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"

	"github.com/ingressd/ingressd/internal/alerts"
	"github.com/ingressd/ingressd/internal/backup"
	"github.com/ingressd/ingressd/internal/controlsrv"
	"github.com/ingressd/ingressd/internal/nodeagent"
	"github.com/ingressd/ingressd/internal/observe"
	"github.com/ingressd/ingressd/internal/render"
	"github.com/ingressd/ingressd/internal/version"
	"github.com/ingressd/ingressd/pkg/config"
)

// Observability, alerting and scheduled backups inside `ingressd serve`.

func (e *env) accessLogSocket() string { return filepath.Join(e.runDir, "access-log.sock") }
func (e *env) opsSocket() string       { return filepath.Join(e.runDir, "ops.sock") }
func (e *env) observeDB() string       { return filepath.Join(e.stateDir, "observe.db") }

// alertEmailSender delivers email alert channels. Phase 3 sets it to its
// SES/SMTP sender; until then email channels report "not configured".
var alertEmailSender alerts.Sender

// metricsListen is serve's --metrics-listen address (empty: ops.sock only).
var metricsListen string

// opsRuntime is the running observability stack.
type opsRuntime struct {
	e   *env
	log *slog.Logger
	cfg atomic.Pointer[config.Config]

	store    *observe.Store
	observer *observe.Observer
	registry *observe.Registry
	alerts   *alerts.Engine

	appliesOK, appliesFailed atomic.Int64
	lastApply                atomic.Int64 // unix seconds of last successful apply
}

var currentOps atomic.Pointer[opsRuntime]

// metricsHandler serves Prometheus metrics for the running control plane.
// Mount it on the admin host (e.g. /metrics in adminHostMux, behind admin
// auth from Phase 2). It is also served on <run-dir>/ops.sock and on
// --metrics-listen.
func metricsHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		o := currentOps.Load()
		if o == nil {
			http.Error(w, "metrics not available", http.StatusServiceUnavailable)
			return
		}
		o.registry.ServeHTTP(w, r)
	})
}

// observeAPI is the log/stats query API of the running control plane
// (observe.Observer.Handler), for the dashboard (Phase 2).
func observeAPI() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		o := currentOps.Load()
		if o == nil {
			http.Error(w, "observability not available", http.StatusServiceUnavailable)
			return
		}
		o.observer.Handler(o.registry).ServeHTTP(w, r)
	})
}

// startOps starts log ingestion, alerting and the backup scheduler. It is
// called before the first apply so Caddy's log writer can connect at once.
// Failures are logged; serve keeps running without the failed part.
func startOps(ctx context.Context, e *env, log *slog.Logger) *opsRuntime {
	o := &opsRuntime{e: e, log: log, registry: observe.NewRegistry()}
	if err := os.MkdirAll(e.stateDir, 0o750); err != nil {
		log.Error("state dir", "err", err)
	}
	store, err := observe.OpenStore(e.observeDB())
	if err != nil {
		log.Error("access log database unavailable; keeping logs in memory only", "err", err)
		store = nil
	}
	o.store = store

	o.alerts = alerts.NewEngine(alerts.EngineOptions{
		StatePath: filepath.Join(e.stateDir, "alerts-state.json"),
		Email:     alertEmailSender,
		Log:       log.With("component", "alerts"),
	})
	alerts.SetDefault(o.alerts)
	go o.alerts.Run(ctx)

	o.observer = observe.New(observe.Options{
		Store: store,
		Log:   log.With("component", "observe"),
		OnEvent: func(ev observe.LogEvent) {
			nodeagent.ObserveCaddyEvent(ev) // managed-mode cert status
			if a, ok := alerts.CertLogEvent(ev); ok {
				alerts.Publish(a)
			}
		},
	})
	go o.observer.Run(ctx)
	if err := o.observer.Listen(ctx, e.accessLogSocket()); err != nil {
		log.Error("access log socket", "err", err)
	}

	o.registry.Register(o.observer.Collector())
	o.registry.Register(observe.TunnelCollector(o.cfg.Load))
	o.registry.Register(o.alerts.Collector())
	o.registry.Register(o.collect)

	api := o.observer.Handler(o.registry)
	go func() {
		if err := controlsrv.Serve(ctx, e.opsSocket(), api); err != nil {
			log.Error("ops socket", "err", err)
		}
	}()
	if metricsListen != "" {
		go o.serveMetrics(ctx, metricsListen)
	}

	mon := &alerts.Monitor{
		Publish:   alerts.Publish,
		Config:    o.cfg.Load,
		CertDir:   filepath.Join(e.stateDir, "caddy", "certificates"),
		DiskPaths: []string{e.stateDir, e.configDir},
	}
	go mon.Run(ctx)

	sch := &backup.Scheduler{
		Config: o.cfg.Load, OpenSecrets: e.openSecrets,
		ConfigDir: e.configDir, KeyPath: e.keyPath, StateDir: e.stateDir,
		Version: version.String(), Publish: alerts.Publish, Log: log.With("component", "backup"),
	}
	go sch.Run(ctx)

	currentOps.Store(o)
	go func() {
		<-ctx.Done()
		if o.store != nil {
			o.observer.Flush()
		}
	}()
	return o
}

func (o *opsRuntime) serveMetrics(ctx context.Context, addr string) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		o.log.Error("metrics listener", "err", err)
		return
	}
	mux := http.NewServeMux()
	mux.Handle("GET /metrics", o.registry)
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		srv.Close()
	}()
	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		o.log.Error("metrics listener", "err", err)
	}
}

// applied is called after every apply attempt in serve.
func (o *opsRuntime) applied(err error) {
	if err != nil {
		o.appliesFailed.Add(1)
		alerts.Publish(alerts.Event{Kind: alerts.ApplyFailed, Key: "config", Message: err.Error()})
		return
	}
	o.appliesOK.Add(1)
	o.lastApply.Store(time.Now().Unix())
	alerts.Publish(alerts.Event{Kind: alerts.ApplyFailed, Key: "config", Resolved: true})
	cfg, lerr := o.e.loadConfig()
	if lerr != nil {
		return
	}
	o.cfg.Store(cfg)
	hosts := render.ControlHosts(cfg)
	for _, a := range cfg.Apps {
		hosts = append(hosts, a.Hosts...)
	}
	o.observer.Configure(hosts, cfg.Logging.Sampling(), time.Duration(cfg.Logging.Retention))
	st, serr := o.e.openSecrets()
	var res alerts.Resolver
	if serr == nil {
		res = st
	}
	if err := o.alerts.Configure(cfg, res); err != nil {
		o.log.Warn("alert channels", "err", err)
	}
}

// collect exports control-plane metrics.
func (o *opsRuntime) collect(x *observe.Exposition) {
	x.Counter("ingressd_applies_total", "Config applies by serve, by result.", float64(o.appliesOK.Load()), "result", "ok")
	x.Counter("ingressd_applies_total", "Config applies by serve, by result.", float64(o.appliesFailed.Load()), "result", "error")
	if t := o.lastApply.Load(); t > 0 {
		x.Gauge("ingressd_last_apply_timestamp_seconds", "Unix time of the last successful apply.", float64(t))
	}
	if cfg := o.cfg.Load(); cfg != nil {
		x.Gauge("ingressd_config_apps", "Configured HTTP apps.", float64(len(cfg.Apps)))
		x.Gauge("ingressd_config_tunnels", "Configured tunnels.", float64(len(cfg.Tunnels)))
	}
	if st, err := backup.ReadStatus(o.e.stateDir); err == nil && !st.LastSuccess.IsZero() {
		x.Gauge("ingressd_backup_last_success_timestamp_seconds", "Unix time of the last successful scheduled backup.", float64(st.LastSuccess.Unix()))
	}
	if u, err := alerts.DiskUsage(o.e.stateDir); err == nil {
		x.Gauge("ingressd_state_disk_free_bytes", "Free bytes on the state directory's filesystem.", float64(u.Free))
	}
}

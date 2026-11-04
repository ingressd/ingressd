// SPDX-License-Identifier: Apache-2.0

package crawler

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/robfig/cron/v3"

	"github.com/ingressd/ingressd/internal/render"
	"github.com/ingressd/ingressd/pkg/config"
)

// RunScheduler takes snapshots on each app's always_online.crawl.schedule
// until ctx is done. It re-reads the config every minute (load returns the
// current valid config), and also snapshots an app right away when it has
// no snapshot yet, so a new app does not wait for its first scheduled run.
func RunScheduler(ctx context.Context, load func() (*config.Config, error), stateDir string, log *slog.Logger) {
	s := &scheduler{load: load, stateDir: stateDir, log: log, running: map[string]bool{}, tried: map[string]bool{}}
	s.tick(ctx, time.Now().Truncate(time.Minute), true)
	for {
		next := time.Now().Truncate(time.Minute).Add(time.Minute)
		select {
		case <-ctx.Done():
			s.wg.Wait()
			return
		case <-time.After(time.Until(next)):
			s.tick(ctx, next, false)
		}
	}
}

type scheduler struct {
	load     func() (*config.Config, error)
	stateDir string
	log      *slog.Logger
	wg       sync.WaitGroup
	mu       sync.Mutex
	running  map[string]bool
	tried    map[string]bool // initial snapshot attempted
}

func (s *scheduler) tick(ctx context.Context, t time.Time, startup bool) {
	cfg, err := s.load()
	if err != nil {
		return // serve logs config errors already
	}
	for name, app := range cfg.Apps {
		if !app.AlwaysOnlineEnabled() || !cfg.IsPublicApp(app) {
			continue
		}
		run := !startup && Due(app.AlwaysOnline.Crawl.Schedule, t)
		if !run && !s.tried[name] {
			if _, err := Latest(render.SnapshotDir(s.stateDir, name)); err != nil {
				run = true
			}
		}
		s.tried[name] = true
		if run {
			s.start(ctx, cfg, name)
		}
	}
}

func (s *scheduler) start(ctx context.Context, cfg *config.Config, name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.running[name] {
		return
	}
	s.running[name] = true
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		defer func() { s.mu.Lock(); delete(s.running, name); s.mu.Unlock() }()
		res, err := Snapshot(ctx, cfg, name, s.stateDir, Options{})
		if err != nil {
			s.log.Error("snapshot failed", "app", name, "err", err)
			return
		}
		s.log.Info("snapshot taken", "app", name, "id", res.ID, "entries", res.Pages, "bytes", res.Bytes, "truncated", res.Truncated)
	}()
}

// Due reports whether a cron schedule fires at minute t.
func Due(schedule string, t time.Time) bool {
	sched, err := cron.ParseStandard(schedule)
	if err != nil {
		return false
	}
	t = t.Truncate(time.Minute)
	return sched.Next(t.Add(-time.Second)).Equal(t)
}

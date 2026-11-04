// SPDX-License-Identifier: Apache-2.0

package upgrade

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// helper carries out one plan (see managed.go).
type helper struct {
	p   *Plan
	log *log.Logger
	// child is the process started in RestartExec mode (nil otherwise).
	child     *exec.Cmd
	childDone chan error
	// restartFn is overridable in tests.
	restartFn func(ctx context.Context, h *helper) error
}

// RunHelper executes the plan at planPath: swap, restart, wait for the new
// version's beacon, roll back if it does not come. It always writes a
// result and removes the plan.
func RunHelper(ctx context.Context, planPath string) error {
	p, err := LoadTrustedPlan(planPath)
	if err != nil {
		return err
	}
	lf, err := os.OpenFile(filepath.Join(p.WorkDir, HelperLogFile), os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	var w io.Writer = os.Stderr
	if err == nil {
		defer lf.Close()
		w = io.MultiWriter(os.Stderr, lf)
	}
	h := &helper{p: p, log: log.New(w, "upgrade-helper: ", log.LstdFlags|log.LUTC)}
	return h.run(ctx)
}

func (h *helper) run(ctx context.Context) error {
	p := h.p
	defer os.Remove(filepath.Join(p.WorkDir, PlanFile))
	h.log.Printf("updating %s → %s (restart: %s)", p.From, p.To, p.Restart.Mode)
	res := Outcome{ID: p.ID, From: p.From, To: p.To}
	finish := func(err error) error {
		if err != nil {
			res.Reason = err.Error()
			h.log.Printf("update failed: %v (rolled back: %v)", err, res.RolledBack)
		} else {
			res.OK = true
			h.log.Printf("update to %s succeeded", p.To)
		}
		if werr := WriteResult(p.WorkDir, res); werr != nil {
			h.log.Printf("write result: %v", werr)
		}
		return err
	}

	swapped, err := h.swap()
	if err != nil {
		res.RolledBack = true
		if rerr := h.restore(swapped); rerr != nil {
			return finish(fmt.Errorf("install: %w; ROLLBACK FAILED: %w", err, rerr))
		}
		return finish(fmt.Errorf("install: %w", err))
	}
	h.log.Printf("installed %d binaries; restarting", len(swapped))
	restarted := time.Now().Add(-time.Second)
	_ = os.Remove(filepath.Join(p.WorkDir, BeaconFile))
	err = h.restart(ctx)
	if err == nil {
		err = h.waitHealthy(ctx, restarted)
	}
	if err == nil {
		return finish(nil)
	}
	// Roll back: previous binaries, restart again.
	res.RolledBack = true
	h.log.Printf("new version unhealthy (%v); rolling back", err)
	h.stopChild()
	if rerr := h.restore(swapped); rerr != nil {
		return finish(fmt.Errorf("%w; ROLLBACK FAILED: %w (previous binaries are *.old)", err, rerr))
	}
	if rerr := h.restart(ctx); rerr != nil {
		return finish(fmt.Errorf("%w; rolled back, but restarting the previous version failed: %w", err, rerr))
	}
	return finish(err)
}

// swap installs every staged binary, keeping the current one as .old.
func (h *helper) swap() ([]Swap, error) {
	var done []Swap
	for _, s := range h.p.Swaps {
		_ = os.Remove(s.Old)
		if err := os.Link(s.Path, s.Old); err != nil {
			if err := copyFile(s.Path, s.Old); err != nil {
				return done, fmt.Errorf("keep %s: %w", s.Path, err)
			}
		}
		if err := replaceFile(s.New, s.Path); err != nil {
			return done, fmt.Errorf("install %s: %w", s.Path, err)
		}
		done = append(done, s)
	}
	return done, nil
}

// restore puts the .old binaries back.
func (h *helper) restore(swapped []Swap) error {
	var errs []error
	for _, s := range swapped {
		if err := replaceFile(s.Old, s.Path); err != nil {
			errs = append(errs, err)
		}
	}
	for _, s := range h.p.Swaps {
		_ = os.Remove(s.New)
	}
	return errors.Join(errs...)
}

func (h *helper) restart(ctx context.Context) error {
	if h.restartFn != nil {
		return h.restartFn(ctx, h)
	}
	r := h.p.Restart
	switch r.Mode {
	case RestartSystemd:
		return run(ctx, "systemctl", append([]string{"restart"}, r.Units...)...)
	case RestartLaunchd:
		var errs []error
		for _, u := range r.Units {
			if err := run(ctx, "launchctl", "kickstart", "-k", "system/"+u); err != nil {
				errs = append(errs, err)
			}
		}
		return errors.Join(errs...)
	case RestartWindows:
		var errs []error
		for _, u := range r.Units {
			if err := restartWindowsService(ctx, u); err != nil {
				errs = append(errs, err)
			}
		}
		return errors.Join(errs...)
	case RestartExec:
		return h.restartExec(ctx)
	}
	return fmt.Errorf("unknown restart mode %q", r.Mode)
}

// restartExec stops the process (the original, or the one this helper
// started) and starts the command again with the binaries now on disk.
func (h *helper) restartExec(ctx context.Context) error {
	r := h.p.Restart
	if h.child != nil {
		h.stopChild()
	} else if r.PID > 0 {
		if err := stopPID(r.PID, 20*time.Second); err != nil {
			return fmt.Errorf("stop pid %d: %w", r.PID, err)
		}
	}
	if len(r.Argv) == 0 {
		return errors.New("no command to restart")
	}
	cmd := exec.Command(r.Argv[0], r.Argv[1:]...) //nolint:gosec // G204: re-executes the command line the node itself was started with
	cmd.Env, cmd.Dir = r.Env, r.Dir
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	detach(cmd)
	if err := cmd.Start(); err != nil {
		return err
	}
	h.log.Printf("started %s (pid %d)", r.Argv[0], cmd.Process.Pid)
	h.child, h.childDone = cmd, make(chan error, 1)
	go func(c *exec.Cmd, done chan error) { done <- c.Wait() }(cmd, h.childDone)
	return nil
}

func (h *helper) stopChild() {
	if h.child == nil {
		return
	}
	select {
	case <-h.childDone: //nolint:errcheck // exit status irrelevant: stopping it
	default:
		_ = terminate(h.child.Process)
		select {
		case <-h.childDone: //nolint:errcheck // exit status irrelevant: stopping it
		case <-time.After(20 * time.Second):
			_ = h.child.Process.Kill()
			<-h.childDone //nolint:errcheck // exit status irrelevant: killed
		}
	}
	h.child = nil
}

// waitHealthy waits for a beacon of the new version written after the
// restart (or for the started process to exit, which is a failure).
func (h *helper) waitHealthy(ctx context.Context, since time.Time) error {
	timeout := h.p.HealthTimeout
	if timeout <= 0 {
		timeout = DefaultHealthTimeout
	}
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	tick := time.NewTicker(500 * time.Millisecond)
	defer tick.Stop()
	path := filepath.Join(h.p.WorkDir, BeaconFile)
	for {
		if b, err := readBeacon(path); err == nil && strings.EqualFold(b.Version, h.p.To) && b.Time.After(since) {
			return nil
		}
		var exited chan error
		if h.child != nil {
			exited = h.childDone
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-exited:
			h.child = nil
			if err == nil {
				err = errors.New("exit status 0")
			}
			return fmt.Errorf("the new version exited during the health check: %w", err)
		case <-deadline.C:
			return fmt.Errorf("the new version did not report healthy within %s", timeout)
		case <-tick.C:
		}
	}
}

func run(ctx context.Context, name string, args ...string) error {
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// replaceFile moves src over dst (atomic rename; on Windows a running
// dst is renamed away first, which Windows allows).
func replaceFile(src, dst string) error {
	if err := os.Rename(src, dst); err == nil {
		return nil
	}
	aside := dst + ".replaced"
	_ = os.Remove(aside)
	if err := os.Rename(dst, aside); err != nil && !os.IsNotExist(err) {
		return err
	}
	if err := os.Rename(src, dst); err != nil {
		_ = os.Rename(aside, dst)
		return err
	}
	_ = os.Remove(aside)
	return nil
}

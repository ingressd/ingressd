// SPDX-License-Identifier: Apache-2.0

package backup

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/ingressd/ingressd/internal/alerts"
	"github.com/ingressd/ingressd/internal/secrets"
	"github.com/ingressd/ingressd/pkg/config"
)

// StatusFile (in the state dir) records the outcome of the last backup.
const StatusFile = "backup-status.json"

// Status is the outcome of scheduled (and manual "backup now") runs.
type Status struct {
	LastAttempt time.Time `json:"last_attempt"`
	LastSuccess time.Time `json:"last_success,omitzero"`
	LastError   string    `json:"last_error,omitempty"`
	LastFile    string    `json:"last_file,omitempty"`
	S3Object    string    `json:"s3_object,omitempty"`
	GitPushed   bool      `json:"git_pushed,omitempty"`
}

// ReadStatus reads the backup status; a zero Status if none was recorded.
func ReadStatus(stateDir string) (Status, error) {
	var st Status
	b, err := os.ReadFile(filepath.Join(stateDir, StatusFile))
	if errors.Is(err, fs.ErrNotExist) {
		return st, nil
	}
	if err != nil {
		return st, err
	}
	return st, json.Unmarshal(b, &st)
}

func writeStatus(stateDir string, st Status) error {
	b, _ := json.MarshalIndent(st, "", "  ")
	tmp := filepath.Join(stateDir, StatusFile+".tmp")
	if err := os.WriteFile(tmp, b, 0o640); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(stateDir, StatusFile))
}

// Scheduler runs backups on the configured schedule.
type Scheduler struct {
	// Config returns the current config (nil before the first apply).
	Config      func() *config.Config
	OpenSecrets func() (*secrets.Store, error)
	ConfigDir   string
	KeyPath     string
	StateDir    string
	Version     string
	Publish     func(alerts.Event)
	Log         *slog.Logger
	Now         func() time.Time
}

func (s *Scheduler) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// Run waits for each scheduled time and backs up, re-reading the schedule
// whenever the config changes.
func (s *Scheduler) Run(ctx context.Context) {
	for {
		var wait <-chan time.Time
		cfg := s.Config()
		if cfg != nil && cfg.Backups.Schedule != "" {
			if sch, err := ParseSchedule(cfg.Backups.Schedule); err == nil {
				if next := sch.Next(s.now()); !next.IsZero() {
					wait = time.After(time.Until(next))
				}
			}
		}
		// Re-check the config every minute so schedule edits take effect.
		recheck := time.After(time.Minute)
		select {
		case <-ctx.Done():
			return
		case <-recheck:
		case <-wait:
			if _, err := s.RunOnce(ctx); err != nil && s.Log != nil {
				s.Log.Error("scheduled backup failed", "err", err)
			}
		}
	}
}

// LocalDir is where archives go: backups.local_dir or <state-dir>/backups.
func LocalDir(cfg *config.Config, stateDir string) string {
	if cfg.Backups.LocalDir != "" {
		return cfg.Backups.LocalDir
	}
	return filepath.Join(stateDir, "backups")
}

// RunOnce makes one backup now: local archive, rotation, S3 upload and git
// push as configured. It records the status and publishes backup_failed
// (or its recovery).
func (s *Scheduler) RunOnce(ctx context.Context) (Status, error) {
	st, _ := ReadStatus(s.StateDir)
	st.LastAttempt = s.now().UTC()
	err := s.run(ctx, &st)
	if err != nil {
		st.LastError = err.Error()
	} else {
		st.LastError = ""
		st.LastSuccess = st.LastAttempt
	}
	if werr := writeStatus(s.StateDir, st); werr != nil && s.Log != nil {
		s.Log.Warn("writing backup status", "err", werr)
	}
	if s.Publish != nil {
		if err != nil {
			s.Publish(alerts.Event{Kind: alerts.BackupFailed, Key: "scheduled", Message: "Backup failed: " + err.Error()})
		} else {
			s.Publish(alerts.Event{Kind: alerts.BackupFailed, Key: "scheduled", Resolved: true})
		}
	}
	return st, err
}

func (s *Scheduler) run(ctx context.Context, st *Status) error {
	cfg := s.Config()
	if cfg == nil {
		return errors.New("no valid config loaded")
	}
	b := cfg.Backups
	var store *secrets.Store
	resolve := func(v string) (string, error) {
		if !strings.HasPrefix(v, secrets.RefPrefix) {
			return v, nil
		}
		if store == nil {
			var err error
			if store, err = s.OpenSecrets(); err != nil {
				return "", err
			}
		}
		return store.Resolve(v)
	}
	pass, err := resolve(b.Passphrase)
	if err != nil {
		return fmt.Errorf("backups.passphrase: %w", err)
	}

	dir := LocalDir(cfg, s.StateDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	edge := cfg.Edge.Name
	if edge == "" {
		edge = "edge"
	}
	name := fmt.Sprintf("ingressd-%s-%s.tar.gz", fileLabel(edge), st.LastAttempt.Format("20060102T150405Z"))
	path := filepath.Join(dir, name)
	if err := writeArchive(path, ExportOptions{ConfigDir: s.ConfigDir, KeyPath: s.KeyPath, Passphrase: pass,
		Version: s.Version, Edge: cfg.Edge.Name, Now: st.LastAttempt}); err != nil {
		return err
	}
	st.LastFile = path
	if err := rotateLocal(dir, b.Keep); err != nil {
		return fmt.Errorf("rotating %s: %w", dir, err)
	}

	var errs []error
	if b.S3 != nil {
		obj, err := uploadS3(ctx, *b.S3, resolve, path, b.Keep)
		if err != nil {
			errs = append(errs, fmt.Errorf("s3: %w", err))
		}
		st.S3Object = obj
	}
	st.GitPushed = false
	if b.GitRemote != "" {
		remote, err := resolve(b.GitRemote)
		if err == nil {
			// A secret:// reference is only checked once resolved.
			err = config.ValidateGitRemote(remote)
		}
		if err == nil {
			_, err = git(s.ConfigDir, "push", "-q", "--", remote, "HEAD:refs/heads/main")
			if err != nil {
				// The remote URL may hold a token: never include it.
				err = errors.New(strings.ReplaceAll(err.Error(), remote, "<git_remote>"))
			}
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("git push: %w", err))
		} else {
			st.GitPushed = true
		}
	}
	return errors.Join(errs...)
}

// fileLabel makes an edge name safe as part of a file name.
func fileLabel(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '-' || r == '_' || r == '.' || r >= '0' && r <= '9' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' {
			return r
		}
		return '-'
	}, s)
}

func writeArchive(path string, o ExportOptions) error {
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := Export(f, o); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, path)
}

// isArchive matches names written by the scheduler.
func isArchive(name string) bool {
	return strings.HasPrefix(name, "ingressd-") && strings.HasSuffix(name, ".tar.gz")
}

// rotateLocal keeps the newest keep archives (names sort by time).
func rotateLocal(dir string, keep int) error {
	if keep <= 0 {
		return nil
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	var names []string
	for _, e := range ents {
		if !e.IsDir() && isArchive(e.Name()) {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	for len(names) > keep {
		if err := os.Remove(filepath.Join(dir, names[0])); err != nil {
			return err
		}
		names = names[1:]
	}
	return nil
}

// LatestLocal returns the newest archive in dir and its modification time.
func LatestLocal(dir string) (string, time.Time, error) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return "", time.Time{}, err
	}
	var best string
	var bt time.Time
	for _, e := range ents {
		if e.IsDir() || !isArchive(e.Name()) {
			continue
		}
		if fi, err := e.Info(); err == nil && fi.ModTime().After(bt) {
			best, bt = filepath.Join(dir, e.Name()), fi.ModTime()
		}
	}
	return best, bt, nil
}

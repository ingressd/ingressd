// SPDX-License-Identifier: Apache-2.0

// Package pipeline is the config apply pipeline shared by the CLI and the
// admin API: load → validate → ensure keys → render → diff → apply → git
// commit. All config and secrets writes in a process go through one
// Pipeline so they are serialized.
package pipeline

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sync"

	"github.com/pmezard/go-difflib/difflib"

	"github.com/ingressd/ingressd/internal/apply"
	"github.com/ingressd/ingressd/internal/gitstore"
	"github.com/ingressd/ingressd/internal/render"
	"github.com/ingressd/ingressd/internal/secrets"
	"github.com/ingressd/ingressd/internal/tunnel"
	"github.com/ingressd/ingressd/pkg/config"
)

// Pipeline applies config changes for one config directory.
type Pipeline struct {
	ConfigPath  string
	SecretsPath string
	KeyPath     string
	Repo        gitstore.Repo
	Render      render.Options
	// Engine returns the apply engine (tests use one with nil backends).
	Engine func() *apply.Engine
	// OnApplied runs after every successful, non-dry-run apply or change,
	// with the config now in effect (e.g. to refresh control handlers).
	OnApplied func(cfg *config.Config)
	// Prepare creates keys and runtime material the render needs (tunnel,
	// access, challenge, Origin CA) and reports whether st changed. Default:
	// tunnel keys only.
	Prepare func(cfg *config.Config, st *secrets.Store, dryRun bool) (bool, error)
	// Keys supplies WireGuard keys for rendering (including connector-
	// enrolled site keys). Default: tunnel.Keys from the store.
	Keys func(cfg *config.Config, st *secrets.Store) render.Keys
	// ExtraPaths are config-dir files committed with config.yaml when they
	// exist (e.g. the PKI inventory).
	ExtraPaths []string

	mu sync.Mutex
}

func (p *Pipeline) prepare(cfg *config.Config, st *secrets.Store, dryRun bool) (bool, error) {
	if p.Prepare != nil {
		return p.Prepare(cfg, st, dryRun)
	}
	return tunnel.EnsureKeys(cfg, st)
}

func (p *Pipeline) keys(cfg *config.Config, st *secrets.Store) render.Keys {
	if p.Keys != nil {
		return p.Keys(cfg, st)
	}
	return tunnel.Keys{Cfg: cfg, Store: st}
}

// Options are the CLI apply flags.
type Options struct {
	DryRun  bool
	Force   bool
	Author  string
	Message string
}

// Revision identifies a config file's content (for optimistic locking).
func Revision(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func (p *Pipeline) openSecrets() (*secrets.Store, error) {
	id, err := secrets.LoadIdentity(p.KeyPath)
	if err != nil {
		return nil, err
	}
	return secrets.Open(p.SecretsPath, id)
}

func (p *Pipeline) commit(author, msg string) (string, error) {
	paths := []string{"config.yaml"}
	if _, err := os.Stat(p.SecretsPath); err == nil {
		paths = append(paths, "secrets.age")
	}
	for _, f := range p.ExtraPaths {
		if _, err := os.Stat(filepath.Join(p.Repo.Dir, f)); err == nil {
			paths = append(paths, f)
		}
	}
	return p.Repo.Commit(author, msg, paths...)
}

func (p *Pipeline) applied(cfg *config.Config) {
	if p.OnApplied != nil && cfg != nil {
		p.OnApplied(cfg)
	}
}

// Run is `ingressd apply` / `ingressd diff`: it applies config.yaml as it is
// on disk, printing progress to out.
func (p *Pipeline) Run(ctx context.Context, out io.Writer, o Options) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	cfg, err := config.Load(p.ConfigPath)
	if err != nil {
		return err
	}
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("%s is invalid:\n%w", p.ConfigPath, err)
	}
	st, err := p.openSecrets()
	if err != nil {
		return err
	}
	keysChanged, err := p.prepare(cfg, st, o.DryRun)
	if err != nil {
		return err
	}
	if keysChanged && !o.DryRun {
		if err := st.Save(); err != nil {
			return err
		}
	}
	plan, err := render.Render(cfg, st, p.keys(cfg, st), p.Render)
	if err != nil {
		return err
	}

	eng := p.Engine()
	last, err := eng.Last()
	if err != nil {
		return err
	}
	d := apply.Diff(last, plan, st.Redact)
	if o.DryRun {
		if d == "" {
			fmt.Fprintln(out, "No changes.")
		} else {
			fmt.Fprint(out, d)
		}
		return nil
	}
	if d == "" && !o.Force {
		fmt.Fprintln(out, "No changes to apply.")
	} else {
		if err := eng.Apply(ctx, plan); err != nil {
			return err
		}
		fmt.Fprintln(out, "Applied.")
	}
	rev, err := p.commit(o.Author, o.Message)
	if err != nil {
		return fmt.Errorf("applied, but recording history failed: %w", err)
	}
	if rev != "" {
		fmt.Fprintf(out, "Recorded as %.8s.\n", rev)
	}
	p.applied(cfg)
	return nil
}

// Change is an edit made through the API (or an API-like CLI command).
type Change struct {
	// Edit returns the new config.yaml given the current content. Nil
	// applies the file as it is.
	Edit func(cur []byte) ([]byte, error)
	// Secrets optionally modifies secrets as part of the same change.
	Secrets func(st *secrets.Store) error
	// Check can veto the change (e.g. RBAC scope), given old and new YAML.
	Check func(old, new []byte) error
	// BaseRevision, if set, must match the current file (else ConflictError).
	BaseRevision string
	Author       string
	Message      string
	DryRun       bool
	// Force re-applies even if the rendered plan did not change.
	Force bool
	// NoApply validates and records the change without touching the running
	// system (for changes that do not affect rendering, made offline).
	NoApply bool
}

// FieldError is one validation problem.
type FieldError struct {
	Path    string `json:"path"`
	Message string `json:"message"`
}

// Result describes a (possibly dry-run) change.
type Result struct {
	DryRun     bool         `json:"dry_run"`
	Valid      bool         `json:"valid"`
	Errors     []FieldError `json:"errors"`
	ConfigDiff string       `json:"config_diff"`
	PlanDiff   string       `json:"plan_diff"`
	Revision   string       `json:"revision"`
	Commit     string       `json:"commit"`
	Applied    bool         `json:"applied"`

	Config *config.Config `json:"-"`
}

// ConflictError means the config changed since the editor loaded it.
type ConflictError struct {
	Revision string
	YAML     []byte
}

func (e *ConflictError) Error() string {
	return "config.yaml was changed by someone else; reload and re-apply your edit"
}

// InvalidError means the new config does not parse or validate.
type InvalidError struct{ Errors []FieldError }

func (e *InvalidError) Error() string {
	msg := "invalid config"
	for _, fe := range e.Errors {
		msg += "\n" + fe.Path + ": " + fe.Message
	}
	return msg
}

// FieldErrors splits a Validate/Parse error into its parts.
func FieldErrors(err error) []FieldError {
	var out []FieldError
	var walk func(error)
	walk = func(err error) {
		if j, ok := err.(interface{ Unwrap() []error }); ok {
			for _, e := range j.Unwrap() {
				walk(e)
			}
			return
		}
		var ce *config.Error
		if errors.As(err, &ce) {
			out = append(out, FieldError{Path: ce.Path, Message: ce.Msg})
			return
		}
		out = append(out, FieldError{Message: err.Error()})
	}
	walk(err)
	return out
}

// Validate parses and validates YAML without touching anything.
func Validate(b []byte) (*config.Config, error) {
	cfg, err := config.Parse(b)
	if err != nil {
		return nil, &InvalidError{FieldErrors(err)}
	}
	if err := cfg.Validate(); err != nil {
		return cfg, &InvalidError{FieldErrors(err)}
	}
	return cfg, nil
}

// Read returns the current config.yaml and its revision.
func (p *Pipeline) Read() ([]byte, string, error) {
	b, err := os.ReadFile(p.ConfigPath)
	if err != nil {
		return nil, "", err
	}
	return b, Revision(b), nil
}

// UnifiedDiff is a unified diff of two config texts.
func UnifiedDiff(a, b []byte) string {
	if string(a) == string(b) {
		return ""
	}
	d, _ := difflib.GetUnifiedDiffString(difflib.UnifiedDiff{
		A: difflib.SplitLines(string(a)), B: difflib.SplitLines(string(b)),
		FromFile: "a/config.yaml", ToFile: "b/config.yaml", Context: 3,
	})
	return d
}

// Apply runs a Change through validate → check → render → diff and, unless
// it is a dry run, writes, applies and commits it. On an invalid config it
// returns the partial result (with Errors and ConfigDiff) and an
// *InvalidError.
func (p *Pipeline) Apply(ctx context.Context, c Change) (*Result, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	cur, err := os.ReadFile(p.ConfigPath)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	if c.BaseRevision != "" && c.BaseRevision != Revision(cur) {
		return nil, &ConflictError{Revision: Revision(cur), YAML: cur}
	}
	next := cur
	if c.Edit != nil {
		if next, err = c.Edit(cur); err != nil {
			return nil, err
		}
	}
	st, err := p.openSecrets()
	if err != nil {
		return nil, err
	}
	res := &Result{DryRun: c.DryRun, Valid: true, Errors: []FieldError{}, Revision: Revision(next)}
	res.ConfigDiff = st.Redact(UnifiedDiff(cur, next))
	cfg, err := Validate(next)
	if err != nil {
		var ie *InvalidError
		if errors.As(err, &ie) {
			res.Valid, res.Errors = false, ie.Errors
		}
		return res, err
	}
	res.Config = cfg
	if c.Check != nil {
		if err := c.Check(cur, next); err != nil {
			return nil, err
		}
	}

	secretsBefore, secretsErr := os.ReadFile(p.SecretsPath)
	secretsChanged := false
	if c.Secrets != nil {
		if err := c.Secrets(st); err != nil {
			return nil, err
		}
		secretsChanged = true
	}
	var plan *render.Plan
	eng := p.Engine()
	if !c.NoApply {
		keysChanged, err := p.prepare(cfg, st, c.DryRun)
		if err != nil {
			return nil, err
		}
		// Prepare may also save the store itself (Origin CA); restoring the
		// original file on failure is harmless if nothing changed.
		secretsChanged = secretsChanged || keysChanged || p.Prepare != nil
		if plan, err = render.Render(cfg, st, p.keys(cfg, st), p.Render); err != nil {
			return nil, err
		}
		last, err := eng.Last()
		if err != nil {
			return nil, err
		}
		res.PlanDiff = apply.Diff(last, plan, st.Redact)
	}
	if c.DryRun {
		return res, nil
	}

	restore := func() {
		_ = writeFile(p.ConfigPath, cur, 0o640)
		if secretsChanged {
			if secretsErr == nil {
				_ = writeFile(p.SecretsPath, secretsBefore, 0o600)
			} else {
				_ = os.Remove(p.SecretsPath)
			}
		}
	}
	if secretsChanged {
		if err := st.Save(); err != nil {
			return nil, err
		}
	}
	if string(next) != string(cur) {
		if err := writeFile(p.ConfigPath, next, 0o640); err != nil {
			restore()
			return nil, err
		}
	}
	if plan != nil && (res.PlanDiff != "" || c.Force) {
		if err := eng.Apply(ctx, plan); err != nil {
			restore()
			return nil, err
		}
		res.Applied = true
	}
	msg := c.Message
	if msg == "" {
		msg = "Update config"
	}
	if res.Commit, err = p.commit(c.Author, msg); err != nil {
		return res, fmt.Errorf("applied, but recording history failed: %w", err)
	}
	p.applied(cfg)
	return res, nil
}

// WithSecrets runs fn with the secrets store under the pipeline lock (for
// reads that must not race with writes).
func (p *Pipeline) WithSecrets(fn func(st *secrets.Store) error) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	st, err := p.openSecrets()
	if err != nil {
		return err
	}
	return fn(st)
}

// UpdateSecrets changes secrets only (no config change, no apply unless the
// rendered plan depends on them — callers that need that use Apply with
// Secrets) and commits secrets.age.
func (p *Pipeline) UpdateSecrets(author, msg string, fn func(st *secrets.Store) error) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	st, err := p.openSecrets()
	if err != nil {
		return "", err
	}
	if err := fn(st); err != nil {
		return "", err
	}
	if err := st.Save(); err != nil {
		return "", err
	}
	return p.Repo.Commit(author, msg, "secrets.age")
}

func writeFile(path string, b []byte, mode os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, mode); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

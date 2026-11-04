// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"

	"github.com/spf13/cobra"

	"github.com/ingressd/ingressd/internal/challenge"
	"github.com/ingressd/ingressd/internal/pipeline"
	"github.com/ingressd/ingressd/internal/pki"
	"github.com/ingressd/ingressd/internal/secrets"
	"github.com/ingressd/ingressd/internal/tunnel"
	"github.com/ingressd/ingressd/pkg/config"
)

//go:embed initial-config.yaml
var initialConfig []byte

func newInitCmd(e *env) *cobra.Command {
	return &cobra.Command{
		Use:   "init",
		Short: "Create the config directory, secrets key and a starter config",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			out := cmd.OutOrStdout()
			if err := os.MkdirAll(e.configDir, 0o750); err != nil {
				return err
			}
			if _, err := os.Stat(e.keyPath); errors.Is(err, fs.ErrNotExist) {
				if err := secrets.GenerateIdentity(e.keyPath); err != nil {
					return err
				}
				fmt.Fprintf(out, "Created secrets key %s — back it up somewhere other than this server.\n", e.keyPath)
			}
			if _, err := os.Stat(e.configPath()); errors.Is(err, fs.ErrNotExist) {
				if err := os.WriteFile(e.configPath(), initialConfig, 0o640); err != nil {
					return err
				}
				fmt.Fprintf(out, "Created %s — edit it, then run ingressd apply.\n", e.configPath())
			}
			if err := e.repo().Init(); err != nil {
				return err
			}
			if _, err := e.commit("ingressd", "Initial config"); err != nil {
				return err
			}
			return nil
		},
	}
}

func newValidateCmd(e *env) *cobra.Command {
	var path string
	cmd := &cobra.Command{
		Use:   "validate",
		Short: "Validate a config file without applying it",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if path == "" {
				path = e.configPath()
			}
			cfg, err := config.Load(path)
			if err != nil {
				return err
			}
			if err := cfg.Validate(); err != nil {
				return fmt.Errorf("%s is invalid:\n%w", path, err)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "%s is valid (%d tunnels, %d pools, %d apps)\n",
				path, len(cfg.Tunnels), len(cfg.Pools), len(cfg.Apps))
			for _, w := range cfg.AccessWarnings() {
				fmt.Fprintln(cmd.OutOrStdout(), "warning: "+w)
			}
			return nil
		},
	}
	cmd.Flags().StringVarP(&path, "file", "f", "", "config file to validate (default <config-dir>/config.yaml)")
	return cmd
}

func newDiffCmd(e *env) *cobra.Command {
	return &cobra.Command{
		Use:   "diff",
		Short: "Show what apply would change",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runApply(cmd.Context(), e, cmd.OutOrStdout(), applyOpts{dryRun: true})
		},
	}
}

func newApplyCmd(e *env) *cobra.Command {
	var o applyOpts
	cmd := &cobra.Command{
		Use:   "apply",
		Short: "Apply config.yaml to the edge and record it in history",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runApply(cmd.Context(), e, cmd.OutOrStdout(), o)
		},
	}
	cmd.Flags().BoolVar(&o.dryRun, "dry-run", false, "show the diff without applying")
	cmd.Flags().BoolVar(&o.force, "force", false, "re-apply even if nothing changed (e.g. after a reboot)")
	cmd.Flags().StringVar(&o.author, "author", os.Getenv("USER"), "author recorded in history")
	cmd.Flags().StringVarP(&o.message, "message", "m", "Apply config", "history message")
	return cmd
}

type applyOpts struct {
	dryRun  bool
	force   bool
	author  string
	message string
}

// runApply is the full pipeline: validate → keys → render → diff → apply → commit.
// It lives in internal/pipeline, shared with the admin API.
func runApply(ctx context.Context, e *env, out io.Writer, o applyOpts) error {
	return e.pipeline().Run(ctx, out, pipeline.Options{DryRun: o.dryRun, Force: o.force, Author: o.author, Message: o.message})
}

// prepareApply creates whatever the render needs that config alone does not
// hold: WireGuard, bot-challenge and access keys, and the Origin CA material.
// It reports whether st changed. pki.Ensure saves its own changes unless
// dryRun.
func (e *env) prepareApply(cfg *config.Config, st *secrets.Store, dryRun bool) (bool, error) {
	changed, err := tunnel.EnsureKeys(cfg, st)
	if err != nil {
		return false, err
	}
	if ch, err := challenge.EnsureKey(cfg, st); err != nil {
		return false, err
	} else if ch {
		changed = true
	}
	if changed, err = ensureAccessKeys(cfg, st, changed); err != nil {
		return false, err
	}
	if changed, err = ensureSmartDNSKeys(cfg, st, changed); err != nil {
		return false, err
	}
	if err := pki.Ensure(cfg, st, pki.EnsureOptions{ConfigDir: e.configDir, StateDir: e.stateDir, DryRun: dryRun}); err != nil {
		return false, err
	}
	return changed, nil
}

func newHistoryCmd(e *env) *cobra.Command {
	var n int
	cmd := &cobra.Command{
		Use:   "history",
		Short: "List applied config changes",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			entries, err := e.repo().Log(n)
			if err != nil {
				return err
			}
			for _, en := range entries {
				fmt.Fprintf(cmd.OutOrStdout(), "%.8s  %s  %-12s  %s\n", en.Rev, en.Time.Format("2006-01-02 15:04"), en.Author, en.Subject)
			}
			return nil
		},
	}
	cmd.Flags().IntVarP(&n, "limit", "n", 20, "number of entries")
	return cmd
}

func newRollbackCmd(e *env) *cobra.Command {
	var author string
	cmd := &cobra.Command{
		Use:   "rollback <revision>",
		Short: "Restore config.yaml from a previous revision and apply it",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			rev := args[0]
			old, err := e.repo().Show(rev, "config.yaml")
			if err != nil {
				return err
			}
			cfg, err := config.Parse(old)
			if err != nil {
				return err
			}
			if err := cfg.Validate(); err != nil {
				return fmt.Errorf("config at %s is no longer valid:\n%w", rev, err)
			}
			current, err := os.ReadFile(e.configPath())
			if err != nil {
				return err
			}
			if err := os.WriteFile(e.configPath(), old, 0o640); err != nil {
				return err
			}
			err = runApply(cmd.Context(), e, cmd.OutOrStdout(), applyOpts{author: author, message: "Rollback to " + rev})
			if err != nil {
				// Leave the file as it was so it matches what is running.
				_ = os.WriteFile(e.configPath(), current, 0o640)
			}
			return err
		},
	}
	cmd.Flags().StringVar(&author, "author", os.Getenv("USER"), "author recorded in history")
	return cmd
}

// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/ingressd/ingressd/internal/alerts"
	"github.com/ingressd/ingressd/internal/upgrade"
	"github.com/ingressd/ingressd/internal/version"
)

func newAlertsCmd(e *env) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "alerts",
		Short: "Test alert channels and list firing alerts",
	}
	cmd.AddCommand(&cobra.Command{
		Use:   "test <channel>",
		Short: "Send a test notification to a channel from config.yaml",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := e.loadConfig()
			if err != nil {
				return err
			}
			if _, ok := cfg.Alerts.Channels[args[0]]; !ok {
				var names []string
				for n := range cfg.Alerts.Channels {
					names = append(names, n)
				}
				sort.Strings(names)
				return fmt.Errorf("no channel %q in alerts.channels (have: %s)", args[0], strings.Join(names, ", "))
			}
			st, err := e.openSecrets()
			if err != nil {
				return err
			}
			eng := alerts.NewEngine(alerts.EngineOptions{Email: alertEmailSender})
			if err := eng.Configure(cfg, st); err != nil {
				return err
			}
			ctx, cancel := context.WithTimeout(cmd.Context(), 30*time.Second)
			defer cancel()
			if err := eng.Test(ctx, args[0]); err != nil {
				return fmt.Errorf("channel %s: %s", args[0], st.Redact(err.Error()))
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Sent a test notification to %s.\n", args[0])
			return nil
		},
	})
	cmd.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "List firing alerts (as recorded by ingressd serve)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			b, err := os.ReadFile(filepath.Join(e.stateDir, "alerts-state.json"))
			if errors.Is(err, os.ErrNotExist) {
				fmt.Fprintln(cmd.OutOrStdout(), "No alerts firing.")
				return nil
			}
			if err != nil {
				return err
			}
			var sts []alerts.State
			if err := json.Unmarshal(b, &sts); err != nil {
				return err
			}
			n := 0
			for _, s := range sts {
				if s.Firing {
					n++
					fmt.Fprintf(cmd.OutOrStdout(), "%s  %-22s %-20s %s\n", s.Since.Local().Format("2006-01-02 15:04"), s.Event.Kind, s.Event.Key, s.Event.Title)
				}
			}
			if n == 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "No alerts firing.")
			}
			return nil
		},
	})
	return cmd
}

func newUpgradeCmd(e *env) *cobra.Command {
	var (
		o         upgrade.Options
		noRestart bool
	)
	cmd := &cobra.Command{
		Use:   "upgrade",
		Short: "Install a signed release from GitHub and roll back if doctor fails",
		Long: `Upgrade downloads a release of ingressd and ingressd-edge, verifies the
SHA-256 checksums and their minisign signature against the key built into
this binary, swaps the binaries atomically (keeping *.old), restarts the
systemd units and runs "ingressd doctor" with the new binary. If doctor keeps
failing for a minute, the old binaries are restored and restarted.

The signed release must be the one asked for (--version), and a release older
than the running one is refused unless --allow-downgrade is given.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if o.BinDir == "" {
				exe, err := os.Executable()
				if err != nil {
					return err
				}
				if exe, err = filepath.EvalSymlinks(exe); err != nil {
					return err
				}
				o.BinDir = filepath.Dir(exe)
			}
			if noRestart {
				o.Units = nil
			}
			o.Log = cmd.OutOrStdout()
			newBin := filepath.Join(o.BinDir, "ingressd")
			o.Doctor = func(ctx context.Context) error {
				out, err := exec.CommandContext(ctx, newBin, "--config-dir", e.configDir, "--key", e.keyPath,
					"--state-dir", e.stateDir, "--run-dir", e.runDir, "doctor").CombinedOutput()
				if err != nil {
					return fmt.Errorf("%w\n%s", err, out)
				}
				return nil
			}
			o.Current = version.Version
			fmt.Fprintf(cmd.OutOrStdout(), "Current version: %s\n", version.String())
			res, err := upgrade.Run(cmd.Context(), o)
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Upgraded to %s.\n", res.Version)
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVar(&o.Version, "version", "", "release tag to install (default: latest)")
	f.StringVar(&o.BinDir, "bin-dir", "", "directory holding the binaries (default: this binary's directory)")
	f.StringSliceVar(&o.Units, "units", upgrade.DefaultUnits, "systemd units to restart")
	f.BoolVar(&noRestart, "no-restart", false, "do not restart units")
	f.BoolVar(&o.AllowDowngrade, "allow-downgrade", false, "install a release older than the running one (not below the latest release's minimum supported version)")
	f.DurationVar(&o.HealthTimeout, "health-timeout", time.Minute, "how long doctor may take to pass before rolling back")
	f.StringVar(&o.BaseURL, "release-url", upgrade.DefaultBaseURL, "releases base URL (mirrors, testing)")
	_ = f.MarkHidden("release-url")
	return cmd
}

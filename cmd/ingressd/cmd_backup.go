// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/ingressd/ingressd/internal/alerts"
	"github.com/ingressd/ingressd/internal/backup"
	"github.com/ingressd/ingressd/internal/version"
	"github.com/ingressd/ingressd/pkg/config"
	"github.com/ingressd/ingressd/pkg/envcompat"
)

// PassphraseEnv supplies the backup passphrase non-interactively.
const PassphraseEnv = "INGRESSD_BACKUP_PASSPHRASE" //nolint:gosec // G101: the name of an environment variable, not a credential

// readPassphrase returns the passphrase from $INGRESSD_BACKUP_PASSPHRASE,
// a terminal prompt, or the first line of stdin.
func readPassphrase(cmd *cobra.Command, confirm bool) (string, error) {
	if p := envcompat.Get(PassphraseEnv); p != "" {
		return p, nil
	}
	in := cmd.InOrStdin()
	if f, ok := in.(*os.File); ok && term.IsTerminal(int(f.Fd())) {
		fmt.Fprint(cmd.ErrOrStderr(), "Passphrase: ")
		p, err := term.ReadPassword(int(f.Fd()))
		fmt.Fprintln(cmd.ErrOrStderr())
		if err != nil {
			return "", err
		}
		if confirm {
			fmt.Fprint(cmd.ErrOrStderr(), "Repeat passphrase: ")
			p2, err := term.ReadPassword(int(f.Fd()))
			fmt.Fprintln(cmd.ErrOrStderr())
			if err != nil {
				return "", err
			}
			if string(p) != string(p2) {
				return "", errors.New("passphrases do not match")
			}
		}
		if len(p) == 0 {
			return "", errors.New("empty passphrase")
		}
		return string(p), nil
	}
	line, err := bufio.NewReader(in).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	line = strings.TrimRight(line, "\r\n")
	if line == "" {
		return "", fmt.Errorf("no passphrase: set %s or pipe it on stdin", PassphraseEnv)
	}
	return line, nil
}

func newExportCmd(e *env) *cobra.Command {
	var (
		out       string
		usePass   bool
		noSecrets bool
	)
	cmd := &cobra.Command{
		Use:   "export -o backup.tar.gz",
		Short: "Export config, secrets and history to a .tar.gz archive",
		Long: `Export writes config.yaml, secrets.age and the git history of the config
directory to an archive. By default the secrets stay encrypted to this edge's
key file, so restoring needs a copy of that key. With --passphrase they are
re-encrypted to a passphrase instead (read from $` + PassphraseEnv + `, a
prompt, or stdin) and the archive restores anywhere. --no-secrets makes a
config-only export for sharing.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if out == "" {
				return errors.New("-o/--output is required (use - for stdout)")
			}
			if usePass && noSecrets {
				return errors.New("--passphrase and --no-secrets are mutually exclusive")
			}
			o := backup.ExportOptions{ConfigDir: e.configDir, KeyPath: e.keyPath, NoSecrets: noSecrets, Version: version.String()}
			if cfg, err := config.Load(e.configPath()); err == nil {
				o.Edge = cfg.Edge.Name
			}
			if usePass {
				p, err := readPassphrase(cmd, true)
				if err != nil {
					return err
				}
				o.Passphrase = p
			}
			w := cmd.OutOrStdout()
			var f *os.File
			if out != "-" {
				var err error
				if f, err = os.OpenFile(out+".tmp", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600); err != nil {
					return err
				}
				w = f
			}
			m, err := backup.Export(w, o)
			if f != nil {
				if cerr := f.Close(); err == nil {
					err = cerr
				}
				if err != nil {
					os.Remove(out + ".tmp")
					return err
				}
				if err := os.Rename(out+".tmp", out); err != nil {
					return err
				}
				fmt.Fprintf(cmd.ErrOrStderr(), "Exported to %s (secrets: %s, history: %v)\n", out, m.Secrets, m.Head != "")
				if m.Secrets == backup.SecretsKey {
					fmt.Fprintf(cmd.ErrOrStderr(), "Restoring needs the key file %s (or export with --passphrase).\n", e.keyPath)
				}
			}
			return err
		},
	}
	cmd.Flags().StringVarP(&out, "output", "o", "", "archive to write (- for stdout)")
	cmd.Flags().BoolVar(&usePass, "passphrase", false, "re-encrypt secrets to a passphrase so the archive restores without the key file")
	cmd.Flags().BoolVar(&noSecrets, "no-secrets", false, "leave secrets out (config-only export)")
	return cmd
}

func newRestoreCmd(e *env) *cobra.Command {
	var usePass, force, noApply bool
	cmd := &cobra.Command{
		Use:   "restore <backup.tar.gz>",
		Short: "Restore an exported archive onto this machine, then apply it",
		Long: `Restore unpacks an archive made by ingressd export (or a scheduled backup)
into the config directory, which must not contain a config yet unless --force
is given. Secrets protected by a passphrase are re-encrypted to the key file
(--key), which is created if missing. Then the config is applied; WireGuard
keys are preserved, so sites reconnect once DNS points at this machine.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			f, err := os.Open(args[0])
			if err != nil {
				return err
			}
			defer f.Close()
			o := backup.RestoreOptions{ConfigDir: e.configDir, KeyPath: e.keyPath, Force: force}
			if usePass {
				if o.Passphrase, err = readPassphrase(cmd, false); err != nil {
					return err
				}
			}
			res, err := backup.Restore(f, o)
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			m := res.Manifest
			fmt.Fprintf(out, "Restored backup of %s (edge %q, ingressd %s): config, %d secrets, history %v.\n",
				m.Created.Local().Format("2006-01-02 15:04"), m.Edge, m.Version, res.Secrets, m.Head != "")
			if res.KeyGenerated {
				fmt.Fprintf(out, "Created a new secrets key %s — back it up.\n", e.keyPath)
			}
			if m.Secrets == backup.SecretsNone {
				fmt.Fprintln(out, "The backup had no secrets: set them with ingressd secret set; new WireGuard keys will be generated (sites must re-import).")
			}
			if noApply {
				return nil
			}
			return runApply(cmd.Context(), e, out, applyOpts{force: true, author: "ingressd", message: "Apply restored config"})
		},
	}
	cmd.Flags().BoolVar(&usePass, "passphrase", false, "the archive's secrets are protected by a passphrase")
	cmd.Flags().BoolVar(&force, "force", false, "overwrite an existing config, secrets and history")
	cmd.Flags().BoolVar(&noApply, "no-apply", false, "only restore the files")
	return cmd
}

func newBackupCmd(e *env) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "backup",
		Short: "Run or inspect scheduled backups (config: backups)",
	}
	cmd.AddCommand(&cobra.Command{
		Use:   "run",
		Short: "Make a backup now, as the schedule would (local, S3, git remote)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := e.loadConfig()
			if err != nil {
				return err
			}
			s := &backup.Scheduler{
				Config: func() *config.Config { return cfg }, OpenSecrets: e.openSecrets,
				ConfigDir: e.configDir, KeyPath: e.keyPath, StateDir: e.stateDir, Version: version.String(),
			}
			st, err := s.RunOnce(cmd.Context())
			if st.LastFile != "" {
				fmt.Fprintf(cmd.OutOrStdout(), "Wrote %s\n", st.LastFile)
			}
			if st.S3Object != "" {
				fmt.Fprintf(cmd.OutOrStdout(), "Uploaded s3://%s/%s\n", cfg.Backups.S3.Bucket, st.S3Object)
			}
			if st.GitPushed {
				fmt.Fprintln(cmd.OutOrStdout(), "Pushed history to the git remote")
			}
			return err
		},
	})
	cmd.AddCommand(&cobra.Command{
		Use:   "status",
		Short: "Show the last scheduled backup",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			st, err := backup.ReadStatus(e.stateDir)
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			if st.LastAttempt.IsZero() {
				fmt.Fprintln(out, "No backup has run yet.")
				return nil
			}
			fmt.Fprintf(out, "Last attempt: %s\n", st.LastAttempt.Local().Format(time.RFC1123))
			if !st.LastSuccess.IsZero() {
				fmt.Fprintf(out, "Last success: %s (%s ago)\n", st.LastSuccess.Local().Format(time.RFC1123), time.Since(st.LastSuccess).Round(time.Minute))
			}
			if st.LastError != "" {
				fmt.Fprintf(out, "Last error:   %s\n", st.LastError)
			}
			if st.LastFile != "" {
				fmt.Fprintf(out, "Last file:    %s\n", st.LastFile)
			}
			return nil
		},
	})
	return cmd
}

// doctorOps adds disk space and backup age checks to ingressd doctor.
func doctorOps(e *env, cfg *config.Config, check, warn func(string, error)) {
	for _, p := range []string{e.stateDir, e.configDir} {
		u, err := alerts.DiskUsage(p)
		if err != nil {
			continue
		}
		name := "disk space for " + p
		switch {
		case u.Free < 100<<20:
			check(name, fmt.Errorf("only %s free", alerts.HumanBytes(u.Free)))
		case u.Low():
			warn(name, fmt.Errorf("only %s free of %s", alerts.HumanBytes(u.Free), alerts.HumanBytes(u.Total)))
		default:
			check(fmt.Sprintf("%s (%s free)", name, alerts.HumanBytes(u.Free)), nil)
		}
	}
	if cfg.Backups.Schedule == "" {
		warn("backups", errors.New("no backups.schedule configured (ingressd export makes a manual backup)"))
		return
	}
	st, err := backup.ReadStatus(e.stateDir)
	if err != nil {
		warn("backup status", err)
		return
	}
	maxAge := 48 * time.Hour
	if sch, err := backup.ParseSchedule(cfg.Backups.Schedule); err == nil {
		now := time.Now()
		if n := sch.Next(now); !n.IsZero() {
			if p := sch.Next(n).Sub(n); 2*p+time.Hour > maxAge {
				maxAge = 2*p + time.Hour
			}
		}
	}
	switch {
	case st.LastSuccess.IsZero():
		warn("last backup", errors.New("no successful backup yet"))
	case time.Since(st.LastSuccess) > maxAge:
		warn("last backup", fmt.Errorf("last success %s ago (%s)", time.Since(st.LastSuccess).Round(time.Minute), st.LastError))
	default:
		check(fmt.Sprintf("last backup %s ago", time.Since(st.LastSuccess).Round(time.Minute)), nil)
	}
	if st.LastError != "" && st.LastAttempt.After(st.LastSuccess) {
		warn("last backup attempt", errors.New(st.LastError))
	}
}

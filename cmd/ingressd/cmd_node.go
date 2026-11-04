// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/ingressd/ingressd/internal/connector"
	"github.com/ingressd/ingressd/internal/nodeagent"
	"github.com/ingressd/ingressd/internal/pipeline"
	"github.com/ingressd/ingressd/internal/storagerelay"
	"github.com/ingressd/ingressd/pkg/config"
	"github.com/ingressd/ingressd/pkg/envcompat"
)

// Managed mode (rev1): enrolment with the hosted panel, the agent inside
// `ingressd serve`, detach, and importing a config exported from the panel.

// machineHost is the node's own hostname or public IP recorded at
// enrolment (kept after detach); "" on nodes that never enrolled.
func (e *env) machineHost() string { return nodeagent.LoadEndpoint(e.stateDir).Host() }

func cliAuthor() string {
	if u := os.Getenv("SUDO_USER"); u != "" {
		return u
	}
	if u := os.Getenv("USER"); u != "" {
		return u
	}
	return "ingressd"
}

// minimalConfig is written at enrolment when no config exists yet; the
// panel's first snapshot replaces it.
const minimalConfig = "# Managed by the ingressd panel. Local edits are ignored while this node\n# is enrolled; run `ingressd node detach` to manage it with this file.\nversion: 1\n"

// ensureConfigDir creates the config dir, its git repository and the age
// identity, and a minimal config.yaml if there is none.
func ensureConfigDir(e *env) error {
	if err := os.MkdirAll(e.configDir, 0o750); err != nil {
		return err
	}
	if _, err := nodeagent.EnsureIdentity(e.keyPath); err != nil {
		return err
	}
	if err := e.repo().Init(); err != nil {
		return err
	}
	if _, err := os.Stat(e.configPath()); errors.Is(err, fs.ErrNotExist) {
		if err := os.WriteFile(e.configPath(), []byte(minimalConfig), 0o640); err != nil {
			return err
		}
		if _, err := e.commit("ingressd", "Initial config (managed node)"); err != nil {
			return err
		}
	}
	return nil
}

func newNodeCmd(e *env) *cobra.Command {
	cmd := &cobra.Command{Use: "node", Short: "Managed mode: enrol this node with an ingressd panel, show status, detach"}
	cmd.AddCommand(newNodeEnrollCmd(e), newNodeStatusCmd(e), newNodeDetachCmd(e))
	return cmd
}

func newNodeEnrollCmd(e *env) *cobra.Command {
	var o nodeagent.EnrollOptions
	var tokenFile string
	cmd := &cobra.Command{
		Use:   "enroll --panel URL --token-file FILE|-",
		Short: "Enrol this node with a panel using a one-time token",
		Long: "Enrol this node with a panel using a one-time token. Pass the token with --token-file (a file, or - for stdin)\n" +
			"or the " + nodeagent.EnrollTokenEnv + " environment variable; --token puts it on the command line, where\n" +
			"other local users can read it.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			tok, err := enrollToken(cmd, o.Token, tokenFile)
			if err != nil {
				return err
			}
			o.Token = tok
			if err := ensureConfigDir(e); err != nil {
				return err
			}
			o.KeyPath, o.StateDir = e.keyPath, e.stateDir
			ctx, cancel := context.WithTimeout(cmd.Context(), time.Minute)
			defer cancel()
			st, err := nodeagent.Enroll(ctx, o)
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "Enrolled as %s (%s) with %s.\n", st.NodeID, st.Name, st.PanelURL)
			if st.PublicIPv4 == "" && st.Hostname == "" {
				fmt.Fprintln(out, "Warning: no public IP detected and no --hostname given; sites will not know how to reach this node.")
			}
			fmt.Fprintln(out, "ingressd serve connects to the panel automatically (systemctl restart ingressd if it is running).")
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVar(&o.PanelURL, "panel", "", "panel URL, e.g. https://panel.example.com")
	f.StringVar(&o.Token, "token", "", "one-time enrolment token from the panel (visible to local users in the process list; prefer --token-file or "+nodeagent.EnrollTokenEnv+")")
	f.StringVar(&tokenFile, "token-file", "", "read the enrolment token from this file (- for stdin)")
	f.StringVar(&o.Name, "name", "", "node name (optional; the token may carry one)")
	f.StringVar(&o.Hostname, "hostname", "", "this node's public DNS name, if it has one")
	f.StringVar(&o.PublicIPv4, "public-ip", "", "this node's public IPv4 address (default: detected)")
	f.StringVar(&o.PublicIPv6, "public-ipv6", "", "this node's public IPv6 address")
	f.IntVar(&o.SSHPort, "ssh-port", 0, "port sshd listens on, if not 22 (the panel keeps it open in the managed firewall)")
	_ = cmd.MarkFlagRequired("panel")
	cmd.MarkFlagsMutuallyExclusive("token", "token-file")
	return cmd
}

// enrollToken picks the enrolment token from --token, --token-file (- is
// stdin) or INGRESSD_ENROLL_TOKEN, in that order.
func enrollToken(cmd *cobra.Command, flagToken, file string) (string, error) {
	var tok string
	switch {
	case flagToken != "":
		tok = flagToken
	case file == "-":
		b, err := io.ReadAll(io.LimitReader(cmd.InOrStdin(), 4096))
		if err != nil {
			return "", fmt.Errorf("read the token from stdin: %w", err)
		}
		tok = string(b)
	case file != "":
		b, err := os.ReadFile(file)
		if err != nil {
			return "", fmt.Errorf("--token-file: %w", err)
		}
		tok = string(b)
	default:
		tok = os.Getenv(nodeagent.EnrollTokenEnv)
	}
	tok = strings.TrimSpace(tok)
	if tok == "" {
		return "", errors.New("an enrolment token is required: --token-file FILE (- for stdin), " + nodeagent.EnrollTokenEnv + ", or --token")
	}
	return tok, nil
}

func newNodeStatusCmd(e *env) *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show whether this node is managed and connected to its panel",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			out := cmd.OutOrStdout()
			st, err := nodeagent.LoadState(e.stateDir)
			if errors.Is(err, fs.ErrNotExist) {
				fmt.Fprintln(out, "Standalone (not enrolled with a panel).")
				return nil
			}
			if err != nil {
				return err
			}
			tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
			fmt.Fprintf(tw, "Mode:\tmanaged\n")
			fmt.Fprintf(tw, "Panel:\t%s\n", st.PanelURL)
			fmt.Fprintf(tw, "Node:\t%s %s\n", st.NodeID, st.Name)
			if st.OrgID != "" {
				fmt.Fprintf(tw, "Org:\t%s\n", st.OrgID)
			}
			ep := nodeagent.Endpoint{Hostname: st.Hostname, PublicIPv4: st.PublicIPv4}
			fmt.Fprintf(tw, "Endpoint:\t%s\n", ep.Host())
			fmt.Fprintf(tw, "Applied revision:\t%d\n", st.AppliedRevision)
			if rt, err := nodeagent.LoadRuntime(e.stateDir); err == nil {
				conn := "disconnected"
				if rt.Connected {
					conn = "connected since " + rt.Since.Local().Format(time.RFC3339)
				}
				fmt.Fprintf(tw, "Connection:\t%s\n", conn)
				if rt.LastError != "" && !rt.Connected {
					fmt.Fprintf(tw, "Last error:\t%s\n", rt.LastError)
				}
				fmt.Fprintf(tw, "Usage:\tseq %d, %d unacknowledged\n", rt.UsageSeq, rt.UsagePending)
			} else {
				fmt.Fprintf(tw, "Connection:\tunknown (is ingressd serve running?)\n")
			}
			return tw.Flush()
		},
	}
}

func newNodeDetachCmd(e *env) *cobra.Command {
	return &cobra.Command{
		Use:   "detach",
		Short: "Leave managed mode: keep the config and secrets and continue standalone",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if !nodeagent.Managed(e.stateDir) {
				fmt.Fprintln(cmd.OutOrStdout(), "Already standalone.")
				return nil
			}
			if err := nodeagent.RemoveState(e.stateDir); err != nil {
				return err
			}
			_ = os.Remove(filepath.Join(e.stateDir, nodeagent.RuntimeFile))
			_ = os.Remove(filepath.Join(e.stateDir, nodeagent.SnapshotFile))
			fmt.Fprintf(cmd.OutOrStdout(), "Detached. The node keeps serving its current config; manage it with %s and ingressd apply.\n", e.configPath())
			return nil
		},
	}
}

func newImportCmd(e *env) *cobra.Command {
	var dryRun bool
	cmd := &cobra.Command{
		Use:   "import <config.yaml>",
		Short: "Import a config exported from the panel (validate, write, apply) on a standalone node",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if nodeagent.Managed(e.stateDir) {
				return errors.New("this node is managed by a panel; run ingressd node detach first")
			}
			b, err := os.ReadFile(args[0])
			if err != nil {
				return err
			}
			if _, err := pipeline.Validate(b); err != nil {
				return fmt.Errorf("%s is invalid:\n%w", args[0], err)
			}
			if err := ensureConfigDir(e); err != nil {
				return err
			}
			res, err := e.pipeline().Apply(cmd.Context(), pipeline.Change{
				Edit:    func([]byte) ([]byte, error) { return b, nil },
				Author:  cliAuthor(),
				Message: "Import " + filepath.Base(args[0]),
				DryRun:  dryRun,
			})
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			switch {
			case dryRun && res.PlanDiff == "":
				fmt.Fprintln(out, "Valid. No changes.")
			case dryRun:
				fmt.Fprint(out, res.PlanDiff)
			case res.Applied:
				fmt.Fprintln(out, "Imported and applied.")
			default:
				fmt.Fprintln(out, "Imported. No changes to apply.")
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "validate and show the plan diff without writing anything")
	return cmd
}

// managedMode runs the node agent inside `ingressd serve` while node.json
// exists, and notices enrolment and detach while serve runs.
type managedMode struct {
	e         *env
	log       *slog.Logger
	ops       *opsRuntime
	onApplied func(cfg *config.Config)
	// storage is the shared-storage relay (nil in tests); the agent is its
	// backend while managed.
	storage *storagerelay.Server

	agent     *nodeagent.Agent
	done      chan struct{}
	warnedSHA string
	seenSHA   string
}

func newManagedMode(e *env, log *slog.Logger, ops *opsRuntime, onApplied func(cfg *config.Config)) *managedMode {
	return &managedMode{e: e, log: log.With("component", "managed"), ops: ops, onApplied: onApplied}
}

// active reports whether the agent is running.
func (m *managedMode) active() bool { return m.agent != nil }

// startup restores the last applied snapshot's config if config.yaml was
// edited locally while managed (the panel is the source of truth).
func (m *managedMode) startup() {
	if !nodeagent.Managed(m.e.stateDir) {
		return
	}
	if restored, err := nodeagent.RestoreSnapshotConfig(m.e.stateDir, m.e.configPath()); err != nil {
		m.log.Warn("could not check config.yaml against the last panel snapshot", "err", err)
	} else if restored {
		m.log.Warn("config.yaml was edited locally; restored the panel's last applied config (detach to manage this node locally)")
	}
}

// poll starts the agent when node.json appears and notices when it stops;
// it reports true when managed mode just ended (serve then applies
// config.yaml as it is on disk).
func (m *managedMode) poll(ctx context.Context) (stopped bool) {
	if m.agent != nil {
		select {
		case <-m.done:
			m.agent = nil
			m.e.pipeline().Render.StorageSocket = "" // back to file_system storage
			if m.storage != nil {
				m.storage.SetBackend(ctx, nil, "")
			}
			m.log.Info("managed mode stopped; this node is standalone and follows config.yaml again")
			return true
		default:
		}
		return
	}
	if !nodeagent.Managed(m.e.stateDir) {
		return
	}
	// Enrolled while serve runs: render the machine host from now on.
	m.e.pipeline().Render.MachineHost = m.e.machineHost()
	m.e.pipeline().Render.StorageSocket = m.e.storageSocket() // shared certificate storage
	opts := nodeagent.Options{
		StateDir: m.e.stateDir, KeyPath: m.e.keyPath, ConfigPath: m.e.configPath(),
		AdminSocket: m.e.adminSocket(), CaddyStorage: filepath.Join(m.e.stateDir, "caddy"),
		Pipeline: m.e.pipeline(), Keys: m.e.tunnelKeys,
		Connectors: connectorServer(m.e), ConnectorStore: connector.NewStore(m.e.stateDir),
		OnApplied: func(cfg *config.Config) {
			if m.ops != nil {
				m.ops.applied(nil)
			}
			m.onApplied(cfg)
		},
		Log: m.log,
	}
	// Test-only overrides (the netns e2e test cannot wait minutes).
	if d, err := time.ParseDuration(envcompat.Get("INGRESSD_AGENT_USAGE_INTERVAL")); err == nil {
		opts.UsageInterval = d
	}
	if d, err := time.ParseDuration(envcompat.Get("INGRESSD_AGENT_STATUS_INTERVAL")); err == nil {
		opts.StatusInterval, opts.StatusPoll = d, d
	}
	if d, err := time.ParseDuration(envcompat.Get("INGRESSD_UPGRADE_HEALTH_TIMEOUT")); err == nil {
		opts.Upgrade.HealthTimeout = d
	}
	if m.ops != nil && m.ops.observer != nil {
		opts.Logs = m.ops.observer
	}
	a, err := nodeagent.New(opts)
	if err != nil {
		m.log.Error("cannot start managed mode", "err", err)
		return
	}
	m.agent, m.done = a, make(chan struct{})
	if m.storage != nil {
		m.storage.SetBackend(ctx, a, a.State().NodeID)
	}
	done := m.done
	setManagedAgent(m.e, a) // hosted Access: OTP via the panel, relays
	go func() {
		defer close(done)
		defer setManagedAgent(m.e, nil)
		if err := a.Run(ctx); errors.Is(err, nodeagent.ErrDetached) {
			m.log.Info("detached from the panel")
		}
	}()
	st := a.State()
	m.log.Info("managed mode: connecting to the panel", "panel", st.PanelURL, "node", st.NodeID)
	return false
}

// checkLocalEdit is called when config.yaml's mtime changed while managed.
// Such edits are never applied (the panel is the source of truth); a
// warning is logged once per distinct content that differs from the last
// applied snapshot. It reports whether serve may consider the change
// handled (false: look again on the next tick, e.g. while the agent is
// still recording an apply it just made).
func (m *managedMode) checkLocalEdit() bool {
	b, err := os.ReadFile(m.e.configPath())
	if err != nil {
		return true
	}
	sum := sha256.Sum256(b)
	sha := hex.EncodeToString(sum[:])
	if sha == m.agent.AppliedConfigSHA() {
		m.seenSHA = ""
		return true
	}
	if sha != m.seenSHA { // give an in-flight snapshot apply one tick
		m.seenSHA = sha
		return false
	}
	if sha != m.warnedSHA {
		m.warnedSHA = sha
		m.log.Warn("config.yaml was edited locally; ignored in managed mode (the panel is the source of truth; run ingressd node detach to manage this node locally)")
	}
	return true
}

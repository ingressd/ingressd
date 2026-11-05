// SPDX-License-Identifier: Apache-2.0

// Command ingressd-connector links a site to the edge when the site's router
// cannot run WireGuard natively. See internal/connector/client.
package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/ingressd/ingressd/internal/connector/client"
	"github.com/ingressd/ingressd/internal/version"
	"github.com/ingressd/ingressd/pkg/release"
)

func main() {
	renamedHint(os.Args[0])
	if err := newRootCmd().Execute(); err != nil {
		os.Exit(1)
	}
}

func defaultMode() string {
	if runtime.GOOS == "linux" && os.Geteuid() == 0 {
		return client.ModeTUN
	}
	return client.ModeNetstack
}

func newRootCmd() *cobra.Command {
	var statePath string
	var debug bool
	root := &cobra.Command{
		Use:          "ingressd-connector",
		Short:        "Connect this site to an ingressd edge over WireGuard",
		SilenceUsage: true,
		// A pre-rename install kept its state under ingressd-connector/.
		PersistentPreRun: func(*cobra.Command, []string) { statePath = client.MigrateState(statePath) },
	}
	root.PersistentFlags().StringVar(&statePath, "state", client.DefaultStatePath(), "state file (holds the site's private key; mode 0600)")
	root.PersistentFlags().BoolVar(&debug, "debug", false, "verbose logging")
	logger := func() *slog.Logger {
		lvl := slog.LevelInfo
		if debug {
			lvl = slog.LevelDebug
		}
		return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lvl}))
	}

	var eo client.EnrollOptions
	enroll := &cobra.Command{
		Use:   "enroll <join-string> | enroll <edge-url> <token>",
		Short: "Enroll this site with the join string (or edge URL and one-time token) from the control panel",
		Long: "Generates the site's WireGuard keypair locally, exchanges the token for\n" +
			"this site's tunnel config and stores both in the state file.\n\n" +
			"The join string is the single argument shown by the panel: it carries the\n" +
			"edge URL, the token and, for edges without a public certificate, the CA to\n" +
			"pin. The two-argument form takes the edge URL and token separately.\n\n" +
			"A join string of \"-\" is read from standard input, which keeps the\n" +
			"token out of the process list (the installer does this).",
		Args: cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 1 {
				join := args[0]
				if join == "-" {
					var err error
					if join, err = readJoin(cmd.InOrStdin()); err != nil {
						return err
					}
				}
				if err := eo.ApplyJoin(join); err != nil {
					return err
				}
			} else {
				eo.EdgeURL, eo.Token = args[0], args[1]
			}
			ctx, cancel := context.WithTimeout(cmd.Context(), 2*time.Minute)
			defer cancel()
			st, err := client.Enroll(ctx, statePath, eo)
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Enrolled tunnel %q (site address %s, %s mode). State saved to %s.\nStart it with: ingressd-connector run (or install-service)\n",
				st.Tunnel(), st.Primary().Config.Address, st.Mode, statePath)
			return nil
		},
	}
	ef := enroll.Flags()
	ef.StringVar(&eo.Mode, "mode", defaultMode(), "tun (routed, needs root on Linux) or netstack (userspace, no root)")
	ef.StringVar(&eo.EdgeAddr, "edge-addr", "", "IP address to dial instead of resolving the edge hostname")
	ef.StringVar(&eo.CAFile, "ca", "", "PEM file with the CA that signed the edge's certificate")
	ef.BoolVar(&eo.Insecure, "insecure", false, "do not verify the edge's certificate (testing only)")
	ef.StringVar(&eo.Interface, "interface", "", "TUN-mode interface name (default "+client.DefaultInterface+")")
	ef.BoolVar(&eo.Masquerade, "masquerade", true, "TUN mode: masquerade tunnel traffic to the LAN so hosts reply through this machine (set --masquerade=false only when this host is the LAN's router)")
	ef.BoolVar(&eo.NoDiscovery, "no-discovery", false, "never scan the LAN for services when the edge asks (stored in the state file)")

	r := &client.Runner{}
	run := &cobra.Command{
		Use:   "run",
		Short: "Run the connector (foreground, or as a service)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			r.StatePath, r.Log = statePath, logger()
			if ok, err := client.RunService(r.Run); ok {
				return err
			}
			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			return r.Run(ctx)
		},
	}
	rf := run.Flags()
	rf.StringVar(&r.Mode, "mode", "", "override the enrolled mode (tun or netstack)")
	rf.DurationVar(&r.UDPTimeout, "udp-timeout", client.DefaultUDPTimeout, "wait this long for a UDP handshake before falling back to WebSocket")
	rf.DurationVar(&r.UDPRetry, "udp-retry", client.DefaultUDPRetry, "while on WebSocket, retry UDP this often")
	rf.BoolVar(&r.NoDiscovery, "no-discovery", false, "refuse LAN service discovery requests from the edge")

	status := &cobra.Command{
		Use:   "status",
		Short: "Show the tunnel state of the running connector",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			st, err := client.LoadState(statePath)
			if err != nil {
				return err
			}
			s, _ := client.LoadStatus(statePath)
			return printStatus(cmd.OutOrStdout(), st, s, time.Now())
		},
	}

	var so client.ServiceOptions
	install := &cobra.Command{
		Use:   "install-service",
		Short: "Install the connector as a system service (systemd, launchd or Windows service)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			abs, err := filepath.Abs(statePath)
			if err != nil {
				return err
			}
			if _, err := client.LoadState(abs); err != nil {
				return err
			}
			so.StatePath = abs
			where, err := client.InstallService(so)
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Installed service %s (%s).\n", client.ServiceName, where)
			return nil
		},
	}
	install.Flags().BoolVar(&so.NoStart, "no-start", false, "install without starting")

	root.AddCommand(
		&cobra.Command{
			Use:   "version",
			Short: "Print the version",
			Args:  cobra.NoArgs,
			Run: func(cmd *cobra.Command, _ []string) {
				fmt.Fprintln(cmd.OutOrStdout(), "ingressd-connector", version.String())
			},
		},
		enroll, run, status, install, newDiscoverCmd(&statePath), newUpgradeHelperCmd(), newVerifySumsCmd(),
	)
	return root
}

// readJoin reads a join string (its first non-empty line) from r.
func readJoin(r io.Reader) (string, error) {
	sc := bufio.NewScanner(io.LimitReader(r, 64<<10))
	sc.Buffer(make([]byte, 0, 4096), 64<<10)
	for sc.Scan() {
		if s := strings.TrimSpace(sc.Text()); s != "" {
			return s, nil
		}
	}
	if err := sc.Err(); err != nil {
		return "", err
	}
	return "", errors.New("no join string on standard input")
}

// newVerifySumsCmd checks a release's SHA256SUMS signature with the built-in
// release key; deploy/install-connector.sh uses it when the minisign CLI is
// not installed (see the installer for what that does and does not prove).
func newVerifySumsCmd() *cobra.Command {
	return &cobra.Command{
		Use:    "verify-sums <SHA256SUMS> <SHA256SUMS.minisig>",
		Short:  "Verify a release's SHA256SUMS signature (used by the installer)",
		Hidden: true,
		Args:   cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			sums, err := os.ReadFile(args[0])
			if err != nil {
				return err
			}
			sig, err := os.ReadFile(args[1])
			if err != nil {
				return err
			}
			trusted, err := release.VerifySums(sums, sig)
			if err != nil {
				return fmt.Errorf("%s: %w", args[0], err)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "signature OK (%s)\n", trusted)
			return nil
		},
	}
}

// newUpgradeHelperCmd carries out a staged self-update (started detached
// by the running connector, see internal/connector/client/update.go).
func newUpgradeHelperCmd() *cobra.Command {
	var plan string
	cmd := &cobra.Command{
		Use:    "upgrade-helper",
		Short:  "Carry out a staged update (started by the connector)",
		Hidden: true,
		Args:   cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			// Stopping the service must not stop the helper half-way.
			signal.Ignore(syscall.SIGHUP, syscall.SIGTERM, os.Interrupt)
			return client.RunUpgradeHelper(plan)
		},
	}
	cmd.Flags().StringVar(&plan, "plan", "", "plan file")
	return cmd
}

// renamedHint tells someone who started the binary under its pre-rename
// name (an old script or a copied file) what it is called now.
func renamedHint(arg0 string) {
	base := strings.TrimSuffix(filepath.Base(arg0), ".exe")
	if strings.HasPrefix(base, "homeedge") { // legacy homeedge name, remove after 2027-01
		fmt.Fprintf(os.Stderr, "note: homeedge was renamed to ingressd; run %s instead of %s\n", "ingressd-connector", base) // legacy homeedge name, remove after 2027-01
	}
}

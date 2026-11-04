// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"github.com/skip2/go-qrcode"
	"github.com/spf13/cobra"

	"github.com/ingressd/ingressd/internal/tunnel"
)

func newTunnelCmd(e *env) *cobra.Command {
	cmd := &cobra.Command{Use: "tunnel", Short: "Site tunnel configuration and status"}

	var opts tunnel.SiteOptions
	var qr bool
	cfgCmd := &cobra.Command{
		Use:   "config <tunnel>",
		Short: "Print the WireGuard config to import on the site",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := e.loadConfig()
			if err != nil {
				return err
			}
			st, err := e.openSecrets()
			if err != nil {
				return err
			}
			changed, err := tunnel.EnsureKeys(cfg, st)
			if err != nil {
				return err
			}
			if changed {
				if err := st.Save(); err != nil {
					return err
				}
				if _, err := e.repo().Commit(os.Getenv("USER"), "Generate WireGuard keys", "secrets.age"); err != nil {
					return err
				}
			}
			text, err := tunnel.SiteConfig(cfg, tunnel.Keys{Cfg: cfg, Store: st}, args[0], opts)
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			if !qr {
				fmt.Fprint(out, text)
				return nil
			}
			q, err := qrcode.New(text, qrcode.Medium)
			if err != nil {
				return err
			}
			fmt.Fprint(out, q.ToSmallString(false))
			return nil
		},
	}
	cfgCmd.Flags().StringVar(&opts.Endpoint, "endpoint", "", "host the site dials (default edge.admin.hostname, then edge.public_ipv4)")
	cfgCmd.Flags().StringVar(&opts.Format, "format", tunnel.FormatWGQuick, "wg-quick (for routers and wg-quick) or wg (for wg setconf)")
	cfgCmd.Flags().BoolVar(&qr, "qr", false, "print as a QR code")

	status := &cobra.Command{
		Use:   "status",
		Short: "Show handshake and traffic for each tunnel",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := e.loadConfig()
			if err != nil {
				return err
			}
			sts, err := tunnel.ReadStatus(cfg)
			if err != nil {
				return err
			}
			now := time.Now()
			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
			fmt.Fprintln(w, "TUNNEL\tSTATE\tENDPOINT\tLAST HANDSHAKE\tRX\tTX\tCONNECTOR")
			for _, s := range sts {
				state, hs := "down", "never"
				if s.Healthy(now) {
					state = "up"
				} else if !s.Up {
					state = "missing"
				}
				if !s.LastHandshake.IsZero() {
					hs = now.Sub(s.LastHandshake).Round(time.Second).String() + " ago"
				}
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%d\t%d\t%s\n", s.Tunnel, state, s.Endpoint, hs, s.RxBytes, s.TxBytes, connectorSummary(e, s.Tunnel, now))
			}
			return w.Flush()
		},
	}

	cmd.AddCommand(cfgCmd, status, newEnrollTokenCmd(e), newTunnelDiscoverCmd(e))
	return cmd
}

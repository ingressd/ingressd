// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"
	"maps"
	"net/http"
	"path/filepath"
	"slices"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/ingressd/ingressd/internal/apply"
	"github.com/ingressd/ingressd/internal/controlsrv"
	"github.com/ingressd/ingressd/internal/l4"
	"github.com/ingressd/ingressd/pkg/config"
)

// l4Authenticator signs players in for login-to-play with the Access
// email-code flow (through the panel on managed nodes); see
// l4.Authenticator for the contract. The Access service picks up each
// applied config, so the authenticator always sees the current one.
func (e *env) l4Authenticator() l4.Authenticator {
	svc, err := accessService(e)
	if err != nil {
		return l4.RefuseAuthenticate
	}
	return svc.PlayAuthenticate
}

func (e *env) l4Store() *l4.Store {
	return &l4.Store{Path: filepath.Join(e.stateDir, l4.FileName)}
}

func (e *env) l4Manager(cfg *config.Config) *l4.Manager {
	return &l4.Manager{Cfg: cfg, Store: e.l4Store(), NFT: apply.NFT}
}

// nftApply loads the nft script, then restores the runtime L4 allowlist
// entries into the freshly recreated sets. Used as the engine's NFT backend,
// so rollbacks restore them too.
func (e *env) nftApply(ctx context.Context, script string) error {
	if err := apply.NFT(ctx, script); err != nil {
		return err
	}
	return l4.Sync(ctx, e.l4Store(), script, apply.NFT)
}

// l4PortalHandlers serves each login-to-play portal host.
func l4PortalHandlers(cfg *config.Config, e *env, hosts map[string]http.Handler) {
	for _, h := range cfg.LoginToPlayHosts() {
		hosts[h] = &l4.Portal{
			Cfg: cfg, Host: h, Manager: e.l4Manager(cfg),
			Authenticate: e.l4Authenticator(), ClientIP: controlsrv.ClientIP,
			OnAllowed: reportL4Allow,
		}
	}
}

func newL4Cmd(e *env) *cobra.Command {
	cmd := &cobra.Command{Use: "l4", Short: "TCP/UDP services: allowlists and server setup snippets"}

	list := &cobra.Command{
		Use:   "list",
		Short: "List L4 services and their runtime allowlist entries",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := e.loadConfig()
			if err != nil {
				return err
			}
			entries, err := e.l4Store().List()
			if err != nil {
				return err
			}
			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
			fmt.Fprintln(w, "SERVICE\tLISTEN\tTARGET\tMODE\tENGINE\tACCESS")
			for _, name := range slices.Sorted(maps.Keys(cfg.L4)) {
				s := cfg.L4[name]
				fmt.Fprintf(w, "%s\t%v\t%s:%s\t%s\t%s\t%s\n", name, s.Listen, s.Target.Tunnel, s.Target.Address, s.Mode, s.Engine(), s.Access)
			}
			w.Flush()
			if len(entries) == 0 {
				return nil
			}
			fmt.Fprintln(cmd.OutOrStdout())
			w = tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
			fmt.Fprintln(w, "SERVICE\tIP\tEMAIL\tEXPIRES")
			for _, en := range entries {
				exp := "never"
				if !en.Expires.IsZero() {
					exp = en.Expires.Local().Format("2006-01-02 15:04:05") + " (in " + time.Until(en.Expires).Round(time.Second).String() + ")"
				}
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", en.Service, en.IP, en.Email, exp)
			}
			return w.Flush()
		},
	}

	var ttl time.Duration
	var email string
	allow := &cobra.Command{
		Use:   "allow <service> <ip>",
		Short: "Allow an IP to connect to a service (access allowlist or login_to_play)",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := e.loadConfig()
			if err != nil {
				return err
			}
			d := ttl
			if !cmd.Flags().Changed("ttl") {
				if lp := cfg.L4[args[0]].LoginToPlay; lp != nil {
					d = time.Duration(lp.TTL)
				}
			}
			en, err := e.l4Manager(cfg).Allow(cmd.Context(), args[0], args[1], email, d)
			if en.IP != "" {
				exp := "no expiry"
				if !en.Expires.IsZero() {
					exp = "until " + en.Expires.Local().Format(time.RFC1123)
				}
				fmt.Fprintf(cmd.OutOrStdout(), "Allowed %s on %s (%s).\n", en.IP, en.Service, exp)
			}
			return err
		},
	}
	allow.Flags().DurationVar(&ttl, "ttl", 0, "how long the entry lasts; 0 = no expiry (default: the service's login_to_play.ttl, else no expiry)")
	allow.Flags().StringVar(&email, "email", "", "who the entry is for (shown in list)")

	revoke := &cobra.Command{
		Use:   "revoke <service> <ip>",
		Short: "Remove an IP from a service's runtime allowlist",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := e.loadConfig()
			if err != nil {
				return err
			}
			if err := e.l4Manager(cfg).Revoke(cmd.Context(), args[0], args[1]); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Revoked %s on %s.\n", args[1], args[0])
			return nil
		},
	}

	snippet := &cobra.Command{
		Use:   "snippet <service>",
		Short: "Print game-server and site settings for a service",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := e.loadConfig()
			if err != nil {
				return err
			}
			text, err := l4.Snippet(cfg, args[0])
			if err != nil {
				return err
			}
			fmt.Fprint(cmd.OutOrStdout(), text)
			return nil
		},
	}

	cmd.AddCommand(list, allow, revoke, snippet)
	return cmd
}

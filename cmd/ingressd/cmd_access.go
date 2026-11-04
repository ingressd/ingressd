// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"sync"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/ingressd/ingressd/internal/auth"
	"github.com/ingressd/ingressd/internal/secrets"
	"github.com/ingressd/ingressd/pkg/config"
)

// ensureAccessKeys generates the Access session/JWT keys during apply.
func ensureAccessKeys(cfg *config.Config, st *secrets.Store, changed bool) (bool, error) {
	c, err := auth.EnsureKeys(cfg, st)
	return changed || c, err
}

// The Access service lives for the whole serve process (its database and
// background email delivery outlast config applies).
var (
	accessOnce sync.Once
	accessSvc  *auth.Service
	accessErr  error
)

func accessService(e *env) (*auth.Service, error) {
	accessOnce.Do(func() {
		accessSvc, accessErr = auth.Open(e.stateDir, slog.New(slog.NewTextHandler(os.Stderr, nil)))
	})
	return accessSvc, accessErr
}

// addAccessHandlers registers the login portal on access.portal_host and
// the edge_auth API on auth.ControlHost (reachable only via the socket).
func addAccessHandlers(hosts map[string]http.Handler, cfg *config.Config, e *env) {
	if !auth.Needed(cfg) { // neither the portal nor login-to-play
		return
	}
	unavailable := func(err error) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "access portal unavailable: "+err.Error(), http.StatusServiceUnavailable)
		})
	}
	svc, err := accessService(e)
	if err == nil {
		var st *secrets.Store
		if st, err = e.openSecrets(); err == nil {
			err = svc.Update(cfg, st)
		}
	}
	if err != nil {
		slog.Error("access service", "err", err)
		if auth.Enabled(cfg) {
			hosts[cfg.Access.PortalHost] = unavailable(err)
		}
		hosts[auth.ControlHost] = unavailable(err)
		return
	}
	if auth.Enabled(cfg) {
		hosts[cfg.Access.PortalHost] = svc.PortalHandler()
	}
	hosts[auth.ControlHost] = svc.EdgeAPIHandler()
}

func newAccessCmd(e *env) *cobra.Command {
	cmd := &cobra.Command{Use: "access", Short: "Access policies"}
	var app, email, ip, country, path string
	test := &cobra.Command{
		Use:   "test",
		Short: "Simulate which policy applies to a request",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := e.loadConfig()
			if err != nil {
				return err
			}
			a, ok := cfg.Apps[app]
			if !ok {
				return fmt.Errorf("unknown app %q", app)
			}
			id := auth.Identity{Email: strings.ToLower(email), Country: strings.ToUpper(country)}
			if ip != "" {
				if id.IP, err = netip.ParseAddr(ip); err != nil {
					return fmt.Errorf("--ip: %w", err)
				}
				if id.Country == "" {
					id.Country = (&auth.GeoIP{Path: auth.GeoIPPath(e.stateDir)}).Country(id.IP)
				}
			}
			out := cmd.OutOrStdout()
			if !a.Protected() {
				fmt.Fprintf(out, "app %s has no access policies: public\n", app)
				return nil
			}
			eng := auth.NewEngine(cfg)
			list := auth.ListFor(a, path)
			d := eng.Evaluate(list, id)
			fmt.Fprintf(out, "app:      %s\npath:     %s\npolicies: %s\n", app, path, strings.Join(list, ", "))
			fmt.Fprintf(out, "identity: email=%s ip=%s country=%s\n", dash(id.Email), dash(ip), dash(id.Country))
			if d.Policy == "" {
				fmt.Fprintln(out, "result:   deny (no policy matched)")
			} else {
				fmt.Fprintf(out, "result:   %s (policy %s", d.Action, d.Policy)
				if d.Action == config.ActionAllow {
					fmt.Fprintf(out, ", session %s", d.Session)
				}
				fmt.Fprintln(out, ")")
			}
			return nil
		},
	}
	f := test.Flags()
	f.StringVar(&app, "app", "", "app name (required)")
	f.StringVar(&email, "email", "", "email address of the user")
	f.StringVar(&ip, "ip", "", "client IP address")
	f.StringVar(&country, "country", "", "client country code (default: GeoIP lookup of --ip)")
	f.StringVar(&path, "path", "/", "request path (for path overrides)")
	_ = test.MarkFlagRequired("app")
	cmd.AddCommand(test)
	return cmd
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func newSessionsCmd(e *env) *cobra.Command {
	cmd := &cobra.Command{Use: "sessions", Short: "List and revoke Access sessions"}
	var email string
	list := &cobra.Command{
		Use:   "list",
		Short: "List active sessions",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			st, err := auth.OpenStore(auth.DBPath(e.stateDir))
			if err != nil {
				return err
			}
			defer st.Close()
			ss, err := st.ListSessions(cmd.Context(), strings.ToLower(email))
			if err != nil {
				return err
			}
			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
			fmt.Fprintln(w, "SID\tEMAIL\tIP\tCREATED\tEXPIRES\tSTATE")
			for _, s := range ss {
				state := "active"
				if s.Revoked {
					state = "revoked"
				}
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n", s.SID, s.Email, s.IP,
					s.Created.Format(time.DateTime), s.Expires.Format(time.DateTime), state)
			}
			return w.Flush()
		},
	}
	list.Flags().StringVar(&email, "email", "", "only sessions of this email")

	var revokeEmail string
	revoke := &cobra.Command{
		Use:   "revoke [sid]",
		Short: "Revoke a session (or all sessions of --email) everywhere within seconds",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			sid := ""
			if len(args) == 1 {
				sid = args[0]
			}
			if sid == "" && revokeEmail == "" {
				return fmt.Errorf("give a session id or --email")
			}
			st, err := auth.OpenStore(auth.DBPath(e.stateDir))
			if err != nil {
				return err
			}
			defer st.Close()
			n, err := st.Revoke(cmd.Context(), sid, strings.ToLower(revokeEmail))
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Revoked %d session(s).\n", n)
			return nil
		},
	}
	revoke.Flags().StringVar(&revokeEmail, "email", "", "revoke every session of this email")
	cmd.AddCommand(list, revoke)
	return cmd
}

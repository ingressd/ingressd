// SPDX-License-Identifier: Apache-2.0

package main

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/spf13/cobra"

	"github.com/ingressd/ingressd/internal/connector"
	"github.com/ingressd/ingressd/internal/connector/proto"
	"github.com/ingressd/ingressd/internal/secrets"
	"github.com/ingressd/ingressd/internal/tunnel"
	"github.com/ingressd/ingressd/pkg/config"
)

// tunnelKeys returns the render keys, including site keys recorded by
// connector enrollment.
func (e *env) tunnelKeys(cfg *config.Config, st *secrets.Store) tunnel.Keys {
	return tunnel.Keys{Cfg: cfg, Store: st, SiteKey: connector.NewStore(e.stateDir).SitePublicKey}
}

var (
	connOnce sync.Once
	connSrv  *connector.Server
	// reapplyCh asks the serve loop to apply now (after an enrollment); the
	// loop answers on the given channel.
	reapplyCh = make(chan chan error)
)

func connectorServer(e *env) *connector.Server {
	connOnce.Do(func() {
		connector.DefaultHost = e.machineHost
		connSrv = &connector.Server{
			Store: connector.NewStore(e.stateDir),
			Log:   slog.New(slog.NewTextHandler(os.Stderr, nil)),
			Reapply: func(ctx context.Context) error {
				done := make(chan error, 1)
				select {
				case reapplyCh <- done:
				case <-ctx.Done():
					return ctx.Err()
				}
				select {
				case err := <-done:
					return err
				case <-ctx.Done():
					return ctx.Err()
				}
			},
		}
	})
	return connSrv
}

// mountConnector registers the connector control channel and the
// WireGuard-over-WebSocket bridge on the admin host mux.
func mountConnector(mux *http.ServeMux, cfg *config.Config, e *env) {
	srv := connectorServer(e)
	if st, err := e.openSecrets(); err == nil {
		srv.Update(cfg, e.tunnelKeys(cfg, st))
	}
	mux.Handle(proto.MachinePrefix+"connector/", srv.ConnectorHandler())
	mux.Handle(proto.TunnelPathPrefix, srv.TunnelHandler())
	mux.Handle(proto.LegacyMachinePrefix, proto.ServeLegacyPrefix(mux))
}

func newEnrollTokenCmd(e *env) *cobra.Command {
	var join bool
	var caFile, edgeURL string
	cmd := &cobra.Command{
		Use:   "enroll-token <tunnel>",
		Short: "Create a one-time token (valid 15 minutes) to enroll an ingressd-connector",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := e.loadConfig()
			if err != nil {
				return err
			}
			name := args[0]
			t, ok := cfg.Tunnels[name]
			if !ok {
				return fmt.Errorf("unknown tunnel %q", name)
			}
			if t.Site != config.SiteConnector {
				return fmt.Errorf("tunnel %q is a %s site; set site: connector to use ingressd-connector", name, t.Site)
			}
			host := cfg.Edge.Admin.Hostname
			if host == "" {
				return fmt.Errorf("edge.admin.hostname must be set: connectors enroll through it")
			}
			now := time.Now()
			tok, err := connector.NewStore(e.stateDir).CreateToken(name, now)
			if err != nil {
				return err
			}
			if join {
				return printJoinString(cmd, cmp.Or(edgeURL, "https://"+host), tok, caFile, now)
			}
			out := cmd.OutOrStdout()
			fmt.Fprintln(out, tok)
			fmt.Fprintf(cmd.ErrOrStderr(), "Valid until %s. On the site run:\n  ingressd-connector enroll https://%s %s\n",
				now.Add(connector.TokenTTL).Format(time.RFC3339), host, tok)
			return nil
		},
	}
	f := cmd.Flags()
	f.BoolVar(&join, "join", false, "print a join string (edge URL, token and optional CA) instead of the bare token")
	f.StringVar(&caFile, "ca", "", "with --join: PEM file of the CA the edge certificate chains to (pinned by the connector)")
	f.StringVar(&edgeURL, "url", "", "with --join: edge URL (default https://<edge.admin.hostname>)")
	return cmd
}

// connectorSummary describes the connector's last health report for status
// output, or "-" for tunnels without one.
func connectorSummary(e *env, name string, now time.Time) string {
	st, err := connector.NewStore(e.stateDir).Load()
	if err != nil {
		return "-"
	}
	c := st.Connectors[name]
	if c == nil {
		return "-"
	}
	h := c.Health
	if h == nil {
		return "enrolled, no report"
	}
	s := fmt.Sprintf("%s/%s mtu=%d %s ago", h.Mode, h.Transport, h.MTU, now.Sub(h.Time).Round(time.Second))
	if bad := unreachable(h); len(bad) > 0 {
		s += " unreachable=" + strings.Join(bad, ",")
	}
	return s
}

// connectorHealth returns an error when an enrolled connector has stopped
// reporting or cannot reach its targets.
func connectorHealth(e *env, name string, now time.Time) error {
	st, err := connector.NewStore(e.stateDir).Load()
	if err != nil {
		return err
	}
	c := st.Connectors[name]
	if c == nil {
		return nil
	}
	if c.Health == nil {
		return fmt.Errorf("connector enrolled but has not reported yet")
	}
	if age := now.Sub(c.Health.Time); age > 2*time.Minute {
		return fmt.Errorf("connector last reported %s ago", age.Round(time.Second))
	}
	if bad := unreachable(c.Health); len(bad) > 0 {
		return fmt.Errorf("connector cannot reach %s", strings.Join(bad, ", "))
	}
	return nil
}

func unreachable(h *proto.Health) []string {
	var bad []string
	for _, r := range h.Reachability {
		if !r.OK {
			bad = append(bad, r.Target)
		}
	}
	return bad
}

// serveTunnelControl serves the connector endpoints on the tunnel control
// port (proto.TunnelControlPort). The handler only answers requests from a
// connector tunnel's site address to its edge address, so binding every
// address is safe; the managed firewall additionally admits the port only
// on tunnel interfaces.
func serveTunnelControl(ctx context.Context, e *env, log *slog.Logger) {
	addr := net.JoinHostPort("0.0.0.0", strconv.Itoa(proto.TunnelControlPort))
	ln, err := net.Listen("tcp4", addr)
	if err != nil {
		log.Warn("connector tunnel control port unavailable: multi-edge connectors cannot refresh from this node", "addr", addr, "err", err)
		return
	}
	srv := &http.Server{Handler: connectorServer(e).TunnelControlHandler(), ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		_ = srv.Close()
	}()
	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Error("connector tunnel control port", "err", err)
	}
}

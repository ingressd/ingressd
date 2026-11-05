// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/ingressd/ingressd/internal/mesh"
	"github.com/ingressd/ingressd/internal/nodeagent"
	"github.com/ingressd/ingressd/internal/secrets"
	"github.com/ingressd/ingressd/internal/smartdns"
	"github.com/ingressd/ingressd/pkg/config"
	"github.com/ingressd/ingressd/pkg/nodeproto"
)

func (e *env) smartDNSStatusPath() string { return filepath.Join(e.stateDir, "smartdns-status.json") }

// smartDNSRuntime runs the node exit (smartdns.exit) and the node mesh.
type smartDNSRuntime struct {
	exit *smartdns.ExitServer
	mesh *mesh.Mesh
}

// Hooks for the node agent (internal/nodeagent/hooks.go).
func (r *smartDNSRuntime) Exits() []nodeproto.ExitStatus   { return r.exit.Exits() }
func (r *smartDNSRuntime) MeshPeers() []nodeproto.MeshPeer { return r.mesh.Status() }
func (r *smartDNSRuntime) Capabilities() []string {
	return []string{nodeproto.CapabilityConnectorSmartDNS, "mesh"}
}

func startSmartDNS(ctx context.Context, e *env, log *slog.Logger) *smartDNSRuntime {
	r := &smartDNSRuntime{
		exit: smartdns.NewExitServer(smartdns.ExitServerOptions{Log: log, StatusPath: e.smartDNSStatusPath()}),
		mesh: mesh.New(log.With("component", "mesh")),
	}
	nodeagent.SetSmartDNS(r)
	go r.exit.Run(ctx)
	go r.mesh.Run(ctx)
	return r
}

func (r *smartDNSRuntime) applied(cfg *config.Config) {
	r.exit.Reconfigure(cfg)
	r.mesh.Reconfigure(cfg)
}

// ensureMeshKey generates the node's mesh key when the config has a mesh.
func ensureMeshKey(cfg *config.Config, st *secrets.Store, changed bool) (bool, error) {
	if cfg.Mesh == nil {
		return changed, nil
	}
	c, err := mesh.EnsureKey(st)
	return changed || c, err
}

func newSmartDNSCmd(e *env) *cobra.Command {
	cmd := &cobra.Command{Use: "smartdns", Short: "Smart DNS node exit and node mesh status"}
	var asJSON bool
	status := &cobra.Command{
		Use:   "status",
		Short: "Show this node's exit (the connector sites leaving from its IP) and edge checks",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			s, err := smartdns.ReadExitStatus(e.smartDNSStatusPath())
			if err != nil {
				return fmt.Errorf("no status (is ingressd serve running?): %w", err)
			}
			out := cmd.OutOrStdout()
			if asJSON {
				enc := json.NewEncoder(out)
				enc.SetIndent("", "  ")
				return enc.Encode(s)
			}
			sites := "none"
			if len(s.Sites) > 0 {
				sites = strings.Join(s.Sites, ", ")
			}
			fmt.Fprintf(out, "Updated %s ago; exit for: %s\n", time.Since(s.Updated).Round(time.Second), sites)
			tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
			fmt.Fprintln(tw, "\nEXIT\tUP\tEGRESS\tCOUNTRY\tMESSAGE")
			for _, x := range s.Exits {
				fmt.Fprintf(tw, "%s\t%v\t%s\t%s\t%s\n", x.Name, x.Up, x.Egress, x.Country, x.Message)
			}
			if len(s.Edges) > 0 {
				fmt.Fprintln(tw, "\nEDGE\tVERDICT\tSEEN\tWANT")
				for _, ed := range s.Edges {
					fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", ed.IP, ed.Verdict, ed.Seen, ed.Want)
				}
			}
			fmt.Fprintf(tw, "\nrefused connections: %d\n", s.Refused)
			return tw.Flush()
		},
	}
	status.Flags().BoolVar(&asJSON, "json", false, "print JSON")

	key := &cobra.Command{
		Use:   "mesh-key",
		Short: "Print this node's mesh public key (generating the key if needed)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			st, err := e.openSecrets()
			if err != nil {
				return err
			}
			changed, err := mesh.EnsureKey(st)
			if err != nil {
				return err
			}
			if changed {
				if err := st.Save(); err != nil {
					return err
				}
			}
			pub, err := mesh.PublicKey(st)
			if err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), pub)
			return nil
		},
	}
	cmd.AddCommand(status, key)
	return cmd
}

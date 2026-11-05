// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/ingressd/ingressd/internal/mesh"
	"github.com/ingressd/ingressd/internal/nodeagent"
	"github.com/ingressd/ingressd/internal/secrets"
	"github.com/ingressd/ingressd/internal/smartdns"
	"github.com/ingressd/ingressd/pkg/config"
)

// Smart DNS and the node mesh run inside `ingressd serve` for the life of
// the process; the serve loop reconfigures them after every apply.
var (
	smartDNSMu  sync.Mutex
	smartDNSMgr *smartdns.Manager
)

// SmartDNS returns the running Smart DNS manager (nil outside serve). It
// implements the node agent hooks (Exits, MeshPeers, TakeServiceUsage,
// RecentLookups, Capabilities): register it with nodeagent.SetSmartDNS.
func SmartDNS() *smartdns.Manager {
	smartDNSMu.Lock()
	defer smartDNSMu.Unlock()
	return smartDNSMgr
}

func (e *env) smartDNSStatusPath() string { return filepath.Join(e.stateDir, "smartdns-status.json") }

type smartDNSRuntime struct {
	e *env
	m *smartdns.Manager
}

func startSmartDNS(ctx context.Context, e *env, log *slog.Logger) *smartDNSRuntime {
	m := smartdns.New(smartdns.Options{Log: log, StatusPath: e.smartDNSStatusPath()})
	smartDNSMu.Lock()
	smartDNSMgr = m
	smartDNSMu.Unlock()
	nodeagent.SetSmartDNS(m) // exits, mesh, usage and recent lookups for managed mode
	go m.Run(ctx)
	return &smartDNSRuntime{e: e, m: m}
}

// applied reconfigures Smart DNS and the mesh runtime with the config now
// in effect.
func (r *smartDNSRuntime) applied(cfg *config.Config) {
	st, err := r.e.openSecrets()
	res := func(v string) (string, error) {
		if err != nil {
			return "", err
		}
		return st.Resolve(v)
	}
	r.m.Reconfigure(cfg, res)
}

// ensureSmartDNSKeys creates the mesh key and VPN exit key secrets.
func ensureSmartDNSKeys(cfg *config.Config, st *secrets.Store, changed bool) (bool, error) {
	c, err := smartdns.Prepare(cfg, st)
	return changed || c, err
}

func newSmartDNSCmd(e *env) *cobra.Command {
	cmd := &cobra.Command{Use: "smartdns", Short: "Smart DNS and node mesh status"}
	var asJSON bool
	status := &cobra.Command{
		Use:   "status",
		Short: "Show exits, mesh peers, relay usage and edge checks (from the running serve process)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			s, err := smartdns.ReadStatus(e.smartDNSStatusPath())
			if err != nil {
				return fmt.Errorf("no status (is ingressd serve running?): %w", err)
			}
			out := cmd.OutOrStdout()
			if asJSON {
				enc := json.NewEncoder(out)
				enc.SetIndent("", "  ")
				return enc.Encode(s)
			}
			fmt.Fprintf(out, "Updated %s ago; listening on %s\n", time.Since(s.Updated).Round(time.Second), strings.Join(s.Listen, ", "))
			tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
			fmt.Fprintln(tw, "\nMESH PEER\tUP\tHANDSHAKE\tRTT")
			for _, p := range s.Mesh {
				hs := "never"
				if !p.LastHandshake.IsZero() {
					hs = time.Since(p.LastHandshake).Round(time.Second).String() + " ago"
				}
				fmt.Fprintf(tw, "%s\t%v\t%s\t%.1fms\n", p.NodeID, p.Up, hs, p.RTTMillis)
			}
			fmt.Fprintln(tw, "\nEXIT\tWHERE\tUP\tCOUNTRY\tMESSAGE")
			for _, x := range s.Exits {
				via := "self"
				if x.VPN {
					via = "self (vpn)"
				}
				fmt.Fprintf(tw, "%s\t%s\t%v\t%s\t%s\n", x.Name, via, x.Up, x.Country, x.Message)
			}
			for _, x := range s.RemoteExits {
				fmt.Fprintf(tw, "%s\t%s\t%v\t%s\t%s\n", x.Name, x.Node, x.Up, x.Country, x.Message)
			}
			if len(s.Services) > 0 {
				fmt.Fprintln(tw, "\nSERVICE\tEXITS\tACTIVE\tSINCE\tMESSAGE")
				for _, sv := range s.Services {
					active, since := sv.Active, "-"
					if active == "" {
						active = "none (fail closed)"
					}
					if !sv.Since.IsZero() {
						since = sv.Since.Local().Format("15:04:05")
					}
					fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", sv.Name, strings.Join(sv.Exits, ","), active, since, sv.Message)
				}
			}
			fmt.Fprintln(tw, "\nSERVICE\tBYTES\tCONNECTIONS")
			for _, u := range s.Usage {
				fmt.Fprintf(tw, "%s\t%d\t%d\n", u.Service, u.Bytes, u.Conns)
			}
			if len(s.Edges) > 0 {
				fmt.Fprintln(tw, "\nEDGE\tEXIT\tVERDICT\tSEEN\tWANT")
				for _, ed := range s.Edges {
					fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", ed.IP, ed.Exit, ed.Verdict, ed.Seen, ed.Want)
				}
			}
			return tw.Flush()
		},
	}
	status.Flags().BoolVar(&asJSON, "json", false, "print JSON")

	var limit int
	recent := &cobra.Command{
		Use:   "recent",
		Short: "Show recent resolver lookups (point a device at the resolver to discover a service's domains)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			s, err := smartdns.ReadStatus(e.smartDNSStatusPath())
			if err != nil {
				return fmt.Errorf("no status (is ingressd serve running?): %w", err)
			}
			tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
			fmt.Fprintln(tw, "TIME\tCLIENT\tSITE\tTYPE\tNAME\tSERVICE\tRESULT")
			for i, l := range s.Recent {
				if limit > 0 && i >= limit {
					break
				}
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", l.Time.Local().Format("15:04:05"), l.Client, l.Site, l.Type, l.Name, l.Service, l.Result)
			}
			return tw.Flush()
		},
	}
	recent.Flags().IntVarP(&limit, "limit", "n", 50, "number of lookups")

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
	cmd.AddCommand(status, recent, key)
	return cmd
}

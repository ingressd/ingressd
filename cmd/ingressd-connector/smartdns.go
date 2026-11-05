// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"fmt"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/ingressd/ingressd/internal/connector/client"
	"github.com/ingressd/ingressd/internal/smartdns"
)

func newSmartDNSCmd(statePath *string) *cobra.Command {
	cmd := &cobra.Command{Use: "smartdns", Short: "Smart DNS on this connector"}
	var asJSON bool
	status := &cobra.Command{
		Use:   "status",
		Short: "Show the resolver, exits, services and relay usage (from the running connector)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			s, err := smartdns.ReadStatus(client.SmartDNSStatusPath(*statePath))
			if err != nil {
				return fmt.Errorf("no Smart DNS status (is the connector running with a Smart DNS config?): %w", err)
			}
			out := cmd.OutOrStdout()
			if asJSON {
				enc := json.NewEncoder(out)
				enc.SetIndent("", "  ")
				return enc.Encode(s)
			}
			listen := "nothing (Smart DNS is off)"
			if len(s.Listen) > 0 {
				listen = strings.Join(s.Listen, ", ") + " (53, 80, 443)"
			}
			fmt.Fprintf(out, "Updated %s ago; listening on %s\n", time.Since(s.Updated).Round(time.Second), listen)
			for k, v := range s.BindErrors {
				fmt.Fprintf(out, "  cannot listen (%s): %s\n", k, v)
			}
			tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
			fmt.Fprintln(tw, "\nEXIT\tWHERE\tUP\tCOUNTRY\tMESSAGE")
			for _, x := range s.Exits {
				fmt.Fprintf(tw, "%s\tVPN on this connector\t%v\t%s\t%s\n", x.Name, x.Up, x.Country, x.Message)
			}
			for _, x := range s.RemoteExits {
				fmt.Fprintf(tw, "%s\tnode %s\t%v\t%s\t%s\n", x.Name, x.Node, x.Up, x.Country, x.Message)
			}
			if len(s.Services) > 0 {
				fmt.Fprintln(tw, "\nSERVICE\tEXITS\tACTIVE\tMESSAGE")
				for _, sv := range s.Services {
					active := sv.Active
					if active == "" {
						active = "none (fail closed)"
					}
					fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", sv.Name, strings.Join(sv.Exits, ","), active, sv.Message)
				}
			}
			fmt.Fprintln(tw, "\nSERVICE\tBYTES\tCONNECTIONS")
			for _, u := range s.Usage {
				fmt.Fprintf(tw, "%s\t%d\t%d\n", u.Service, u.Bytes, u.Conns)
			}
			return tw.Flush()
		},
	}
	status.Flags().BoolVar(&asJSON, "json", false, "print JSON")

	var limit int
	recent := &cobra.Command{
		Use:   "recent",
		Short: "Show recent lookups (point a device at the resolver to discover a service's domains)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			s, err := smartdns.ReadStatus(client.SmartDNSStatusPath(*statePath))
			if err != nil {
				return fmt.Errorf("no Smart DNS status (is the connector running?): %w", err)
			}
			tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
			fmt.Fprintln(tw, "TIME\tCLIENT\tTYPE\tNAME\tSERVICE\tRESULT")
			for i, l := range s.Recent {
				if limit > 0 && i >= limit {
					break
				}
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", l.Time.Local().Format("15:04:05"), l.Client, l.Type, l.Name, l.Service, l.Result)
			}
			return tw.Flush()
		},
	}
	recent.Flags().IntVarP(&limit, "limit", "n", 50, "number of lookups")
	cmd.AddCommand(status, recent)
	return cmd
}

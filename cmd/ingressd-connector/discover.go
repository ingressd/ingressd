// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/ingressd/ingressd/internal/connector/client"
)

// newDiscoverCmd runs a LAN scan locally and prints the results: the same
// scan the edge can request, useful to preview what the panel will see.
func newDiscoverCmd(statePath *string) *cobra.Command {
	var sc client.Scanner
	var ports []int
	var listOnly bool
	cmd := &cobra.Command{
		Use:   "discover",
		Short: "Scan this host's private LAN subnets for web services (what the panel's discovery sees)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			sc.Ports = ports
			if st, err := client.LoadState(*statePath); err == nil {
				sc.ExcludeTunnel(st, st.Mode)
			}
			out := cmd.OutOrStdout()
			if listOnly {
				subnets, err := sc.Subnets()
				if err != nil {
					return err
				}
				for _, p := range subnets {
					fmt.Fprintln(out, p)
				}
				return nil
			}
			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt)
			defer stop()
			start := time.Now()
			subnets, svcs, err := sc.Scan(ctx)
			if err != nil && len(svcs) == 0 {
				return err
			}
			names := make([]string, len(subnets))
			for i, p := range subnets {
				names[i] = p.String()
			}
			fmt.Fprintf(cmd.ErrOrStderr(), "Scanned %s in %s.\n", strings.Join(names, ", "), time.Since(start).Round(100*time.Millisecond))
			w := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
			fmt.Fprintln(w, "URL\tTITLE\tSERVER")
			for _, s := range svcs {
				fmt.Fprintf(w, "%s://%s:%d\t%s\t%s\n", s.Scheme, s.Address, s.Port, s.Title, s.Server)
			}
			if err := w.Flush(); err != nil {
				return err
			}
			if err != nil && !errors.Is(err, context.Canceled) {
				return err
			}
			return nil
		},
	}
	f := cmd.Flags()
	f.IntSliceVar(&ports, "ports", client.DefaultDiscoveryPorts, "TCP ports to probe")
	f.IntVar(&sc.Rate, "rate", 0, "maximum TCP connects per second (default 400)")
	f.DurationVar(&sc.Timeout, "timeout", 0, "give up after this long (default 3m)")
	f.BoolVar(&listOnly, "list-subnets", false, "only print the subnets that would be scanned")
	return cmd
}

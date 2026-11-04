// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/ingressd/ingressd/internal/connector"
	"github.com/ingressd/ingressd/internal/connector/proto"
)

// printJoinString prints a connector join string for `tunnel enroll-token
// --join`.
func printJoinString(cmd *cobra.Command, edgeURL, token, caFile string, now time.Time) error {
	j := proto.Join{URL: edgeURL, Token: token}
	if caFile != "" {
		pem, err := os.ReadFile(caFile) //nolint:gosec // operator-supplied CA file
		if err != nil {
			return err
		}
		j.CA = string(pem)
	}
	s, err := proto.EncodeJoin(j)
	if err != nil {
		return err
	}
	fmt.Fprintln(cmd.OutOrStdout(), s)
	fmt.Fprintf(cmd.ErrOrStderr(), "Valid until %s. On the site run:\n  ingressd-connector enroll %s\n",
		now.Add(connector.TokenTTL).Format(time.RFC3339), s)
	return nil
}

// newTunnelDiscoverCmd asks a connector to scan its LAN and prints the
// result. The request is delivered on the connector's next poll (within
// about 25 s when `ingressd serve` runs in another process).
func newTunnelDiscoverCmd(e *env) *cobra.Command {
	var wait time.Duration
	var last bool
	cmd := &cobra.Command{
		Use:   "discover <tunnel>",
		Short: "Ask the tunnel's ingressd-connector to scan its LAN for web services",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			st := connector.NewStore(e.stateDir)
			name := args[0]
			if !last {
				id, err := st.RequestDiscovery(name, time.Now())
				if err != nil {
					return err
				}
				fmt.Fprintf(cmd.ErrOrStderr(), "Discovery requested (%s); waiting up to %s for the report...\n", id, wait)
				deadline := time.Now().Add(wait)
				for {
					d, err := st.DiscoveryState(name)
					if err != nil {
						return err
					}
					if d != nil && d.Last != nil && d.Last.ID == id {
						break
					}
					if time.Now().After(deadline) {
						return fmt.Errorf("no report within %s (is the connector running and is ingressd serve up?)", wait)
					}
					time.Sleep(time.Second)
				}
			}
			d, err := st.DiscoveryState(name)
			if err != nil {
				return err
			}
			if d == nil || d.Last == nil {
				return fmt.Errorf("no discovery report for %q yet", name)
			}
			rep := d.Last
			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "Report %s at %s, subnets %v, %d services\n", rep.ID, d.ReceivedAt.Format(time.RFC3339), rep.Subnets, len(rep.Services))
			if rep.Error != "" {
				fmt.Fprintf(out, "Error: %s\n", rep.Error)
			}
			w := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
			fmt.Fprintln(w, "URL\tTITLE\tSERVER")
			for _, s := range rep.Services {
				fmt.Fprintf(w, "%s://%s:%d\t%s\t%s\n", s.Scheme, s.Address, s.Port, s.Title, s.Server)
			}
			return w.Flush()
		},
	}
	cmd.Flags().DurationVar(&wait, "wait", 2*time.Minute, "how long to wait for the connector's report")
	cmd.Flags().BoolVar(&last, "last", false, "print the last report without requesting a new scan")
	return cmd
}

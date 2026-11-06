// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"strings"

	"github.com/spf13/cobra"

	"github.com/ingressd/ingressd/internal/connector/client"
)

// newAllowCmd manages the local allowlist. Its file sits in the state
// directory, which only this account and administrators can write.
func newAllowCmd(statePath *string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "allow",
		Short: "Show or change the networks this host lets the edges reach",
		Long: "The allowlist is kept on this host and the edge cannot change it. The edges\n" +
			"reach only what the site's configuration asks for and this list also allows.\n\n" +
			"By default it holds the private networks (10.0.0.0/8, 172.16.0.0/12,\n" +
			"192.168.0.0/16, fc00::/7), this host's own LAN addresses among them, and what\n" +
			"the site reached at its first start, so an origin on a private address added\n" +
			"in the panel works with no step here. Use `enroll --allow`, or `allow remove`\n" +
			"and `allow add`, to narrow it to the networks this site needs. Loopback, the\n" +
			"cloud metadata address and public networks are refused: publishing an origin\n" +
			"on a public address needs `allow add`.\n\n" +
			"Changing it needs the root or administrator rights that own the state file;\n" +
			"a running connector applies the change within seconds by restarting its link.",
	}
	list := &cobra.Command{
		Use:   "list",
		Short: "List the allowed networks and any the edges ask for beyond them",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			st, err := client.LoadState(*statePath)
			if err != nil {
				return allowErr(err)
			}
			printReach(cmd.OutOrStdout(), client.DescribeReach(*statePath, st))
			return nil
		},
	}
	var anyNetwork bool
	add := &cobra.Command{
		Use:   "add <network>...",
		Short: "Allow networks (for example 192.168.1.0/24, or an address for one host)",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			a, err := client.AllowAdd(*statePath, args, anyNetwork)
			if err != nil {
				return allowErr(err)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Allowed networks: %s\n", networks(a.Networks))
			return nil
		},
	}
	add.Flags().BoolVar(&anyNetwork, "allow-any-network", false, "accept 0.0.0.0/0 or ::/0: the edges may then reach everything this host can")
	remove := &cobra.Command{
		Use:   "remove <network>...",
		Short: "Stop allowing networks",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			a, err := client.AllowRemove(*statePath, args)
			if err != nil {
				return allowErr(err)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Allowed networks: %s\n", networks(a.Networks))
			return nil
		},
	}
	cmd.AddCommand(list, add, remove)
	return cmd
}

func allowErr(err error) error {
	if errors.Is(err, fs.ErrPermission) {
		return fmt.Errorf("the allowlist can only be used as root or administrator: %w", err)
	}
	return err
}

func networks(n []string) string {
	if len(n) == 0 {
		return "none"
	}
	return strings.Join(n, ", ")
}

// printReach prints the allowlist and what it keeps from the edges.
func printReach(out io.Writer, r client.ReachReport) {
	fmt.Fprintf(out, "Allowed networks: %s\n", networks(r.Allowed))
	if r.Pending {
		fmt.Fprintln(out, "These are pinned at the next start.")
	}
	if r.Problem != "" {
		fmt.Fprintf(out, "Allowlist problem: %s\n", r.Problem)
	}
	for _, n := range r.Refused {
		fmt.Fprintf(out, "Refused: %s is configured for this site but not allowed here. To allow it: ingressd-connector allow add %s\n", n, n)
	}
}

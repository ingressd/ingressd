// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/ingressd/ingressd/internal/crawler"
	"github.com/ingressd/ingressd/internal/render"
)

func newSnapshotCmd(e *env) *cobra.Command {
	cmd := &cobra.Command{Use: "snapshot", Short: "Always Online snapshots of public apps"}

	cmd.AddCommand(&cobra.Command{
		Use:   "now <app>",
		Short: "Crawl the app's origin now and make the result its latest snapshot",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := e.loadConfig()
			if err != nil {
				return err
			}
			res, err := crawler.Snapshot(cmd.Context(), cfg, args[0], e.stateDir, crawler.Options{})
			if err != nil {
				return err
			}
			note := ""
			if res.Truncated {
				note = " (limit reached; snapshot is partial)"
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Snapshot %s of %s from origin %s: %d entries, %s%s\n",
				res.ID, args[0], res.Origin, res.Pages, humanBytes(res.Bytes), note)
			return nil
		},
	})

	cmd.AddCommand(&cobra.Command{
		Use:   "list <app>",
		Short: "List the app's stored snapshots",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := e.loadConfig()
			if err != nil {
				return err
			}
			if _, ok := cfg.Apps[args[0]]; !ok {
				return fmt.Errorf("unknown app %q", args[0])
			}
			list, err := crawler.List(render.SnapshotDir(e.stateDir, args[0]))
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			if len(list) == 0 {
				fmt.Fprintln(out, "No snapshots.")
				return nil
			}
			tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
			fmt.Fprintln(tw, "ID\tCREATED\tENTRIES\tSIZE\t")
			for i := len(list) - 1; i >= 0; i-- {
				s := list[i]
				flags := ""
				if s.Latest {
					flags += "latest "
				}
				if s.Truncated {
					flags += "partial"
				}
				fmt.Fprintf(tw, "%s\t%s\t%d\t%s\t%s\n", s.ID, s.Created.Local().Format(time.DateTime), s.Pages, humanBytes(s.Bytes), flags)
			}
			return tw.Flush()
		},
	})
	return cmd
}

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

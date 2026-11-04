// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"fmt"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/ingressd/ingressd/internal/render"
	"github.com/ingressd/ingressd/internal/waf"
)

func (e *env) wafEvents() ([]waf.Event, error) {
	cfg, err := e.loadConfig()
	if err != nil {
		return nil, err
	}
	events, err := waf.ReadFile(render.WAFAuditLog(e.stateDir))
	if err != nil {
		return nil, err
	}
	waf.AssignApps(cfg, events)
	return events, nil
}

func newWAFCmd(e *env) *cobra.Command {
	cmd := &cobra.Command{Use: "waf", Short: "Inspect WAF events and create exclusions"}

	var app string
	var since time.Duration
	var asJSON bool
	var limit int
	events := &cobra.Command{
		Use:   "events",
		Short: "List requests the WAF blocked (or would block, in detect mode)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			all, err := e.wafEvents()
			if err != nil {
				return err
			}
			var sel []waf.Event
			for _, ev := range all {
				if app != "" && ev.App != app {
					continue
				}
				if since > 0 && time.Since(ev.Time) > since {
					continue
				}
				sel = append(sel, ev)
			}
			if limit > 0 && len(sel) > limit {
				sel = sel[len(sel)-limit:]
			}
			out := cmd.OutOrStdout()
			if asJSON {
				enc := json.NewEncoder(out)
				for _, ev := range sel {
					if err := enc.Encode(ev); err != nil {
						return err
					}
				}
				return nil
			}
			tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
			fmt.Fprintln(tw, "ID\tTIME\tAPP\tCLIENT\tACTION\tREQUEST\tRULES")
			for _, ev := range sel {
				action := "detect"
				if ev.Blocked {
					action = "block"
				}
				var rules []string
				for _, r := range ev.Rules {
					if !r.Scoring() {
						rules = append(rules, fmt.Sprint(r.ID))
					}
				}
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s %s\t%s\n", ev.ID, ev.Time.Local().Format("2006-01-02 15:04:05"),
					ev.App, ev.ClientIP, action, ev.Method, truncate(ev.URI, 60), strings.Join(rules, ","))
			}
			return tw.Flush()
		},
	}
	events.Flags().StringVar(&app, "app", "", "only events for this app")
	events.Flags().DurationVar(&since, "since", 0, "only events newer than this (e.g. 1h)")
	events.Flags().BoolVar(&asJSON, "json", false, "print one JSON object per line")
	events.Flags().IntVarP(&limit, "limit", "n", 100, "show at most this many (newest) events; 0 for all")

	suggest := &cobra.Command{
		Use:   "suggest-exclusion <event-id>",
		Short: "Print a scoped exclusion for a false positive, to add to config.yaml",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			all, err := e.wafEvents()
			if err != nil {
				return err
			}
			for _, ev := range all {
				if ev.ID == args[0] {
					s, err := waf.SuggestExclusion(ev)
					if err != nil {
						return err
					}
					fmt.Fprint(cmd.OutOrStdout(), s)
					return nil
				}
			}
			return fmt.Errorf("no WAF event with ID %q", args[0])
		},
	}
	cmd.AddCommand(events, suggest)
	return cmd
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

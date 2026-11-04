// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/ingressd/ingressd/internal/alerts"
	"github.com/ingressd/ingressd/internal/observe"
)

// opsCommands are the Phase 10 commands: logs, stats, alerts, export,
// restore, backup and upgrade.
func opsCommands(e *env) []*cobra.Command {
	return []*cobra.Command{
		newLogsCmd(e), newStatsCmd(e), newAlertsCmd(e),
		newExportCmd(e), newRestoreCmd(e), newBackupCmd(e), newUpgradeCmd(e),
	}
}

func newLogsCmd(e *env) *cobra.Command {
	var (
		f            observe.Filter
		since, until string
		follow, asJS bool
	)
	cmd := &cobra.Command{
		Use:   "logs",
		Short: "Search access logs, or follow them live with -f",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			out := cmd.OutOrStdout()
			now := time.Now()
			var err error
			if f.Since, err = observe.ParseTime(since, now); err != nil {
				return err
			}
			if f.Until, err = observe.ParseTime(until, now); err != nil {
				return err
			}
			if err := f.Validate(); err != nil {
				return err
			}
			print := func(en observe.Entry) {
				if asJS {
					b, _ := json.Marshal(en)
					fmt.Fprintln(out, string(b))
					return
				}
				fmt.Fprintln(out, formatEntry(en))
			}
			if follow {
				return followLogs(cmd.Context(), e, f, print)
			}
			st, err := observe.OpenStoreReadOnly(e.observeDB())
			if err != nil {
				return err
			}
			defer st.Close()
			es, err := st.Query(cmd.Context(), f)
			if err != nil {
				return err
			}
			slices.Reverse(es) // oldest first, like a log file
			for _, en := range es {
				print(en)
			}
			return nil
		},
	}
	fl := cmd.Flags()
	fl.StringVar(&f.Host, "host", "", "only this host")
	fl.StringVar(&f.Status, "status", "", "status code, class or range (404, 5xx, 400-499)")
	fl.StringVar(&since, "since", "", "start time or age (15m, 24h, 7d, 2026-01-02 15:04)")
	fl.StringVar(&until, "until", "", "end time or age")
	fl.StringVar(&f.Path, "path", "", "path prefix")
	fl.StringVar(&f.ClientIP, "client-ip", "", "only this client address")
	fl.StringVar(&f.Method, "method", "", "only this HTTP method")
	fl.IntVarP(&f.Limit, "limit", "n", 50, "number of entries")
	fl.BoolVarP(&follow, "follow", "f", false, "stream new entries (needs ingressd serve)")
	fl.BoolVar(&asJS, "json", false, "print JSON lines")
	return cmd
}

func formatEntry(e observe.Entry) string {
	return fmt.Sprintf("%s  %3d  %-6s %s%s  %s  %s  %s",
		e.Time.Local().Format("2006-01-02 15:04:05"), e.Status, e.Method, e.Host, e.Path,
		alerts.HumanBytes(uint64(max(e.Bytes, 0))), e.Duration.Round(time.Microsecond*100), e.ClientIP)
}

// opsClient talks HTTP to serve's ops socket.
func opsClient(e *env) *http.Client {
	return &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", e.opsSocket())
		},
	}}
}

func followLogs(ctx context.Context, e *env, f observe.Filter, print func(observe.Entry)) error {
	q := url.Values{"follow": {"1"}, "limit": {strconv.Itoa(f.Limit)}}
	for k, v := range map[string]string{"host": f.Host, "status": f.Status, "path": f.Path, "client_ip": f.ClientIP, "method": f.Method} {
		if v != "" {
			q.Set(k, v)
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://ingressd/v1/logs?"+q.Encode(), nil)
	if err != nil {
		return err
	}
	resp, err := opsClient(e).Do(req)
	if err != nil {
		return fmt.Errorf("cannot reach ingressd serve at %s: %w", e.opsSocket(), err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("%s", strings.TrimSpace(string(b)))
	}
	sc := bufio.NewScanner(resp.Body)
	for sc.Scan() {
		var en observe.Entry
		if json.Unmarshal(sc.Bytes(), &en) == nil {
			print(en)
		}
	}
	if ctx.Err() != nil {
		return nil
	}
	return sc.Err()
}

func newStatsCmd(e *env) *cobra.Command {
	var (
		q            observe.StatsQuery
		since, until string
		asJS         bool
	)
	cmd := &cobra.Command{
		Use:   "stats",
		Short: "Show traffic totals per host (from per-minute aggregates)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			now := time.Now()
			var err error
			if q.Since, err = observe.ParseTime(since, now); err != nil {
				return err
			}
			if q.Until, err = observe.ParseTime(until, now); err != nil {
				return err
			}
			st, err := observe.OpenStoreReadOnly(e.observeDB())
			if err != nil {
				return err
			}
			defer st.Close()
			s, err := st.Stats(cmd.Context(), q)
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			if asJS {
				enc := json.NewEncoder(out)
				enc.SetIndent("", "  ")
				return enc.Encode(s)
			}
			fmt.Fprintf(out, "Traffic %s – %s\n\n", s.Since.Local().Format("2006-01-02 15:04"), s.Until.Local().Format("2006-01-02 15:04"))
			fmt.Fprintf(out, "%-32s %9s %7s %7s %7s %7s %10s %9s\n", "HOST", "REQUESTS", "2xx", "3xx", "4xx", "5xx", "SENT", "AVG")
			row := func(name string, t observe.Totals) {
				fmt.Fprintf(out, "%-32s %9d %7d %7d %7d %7d %10s %9s\n", name, t.Requests,
					t.Status[2], t.Status[3], t.Status[4], t.Status[5], alerts.HumanBytes(uint64(t.BytesOut)), t.AvgLatency.Round(time.Microsecond*100))
			}
			for _, h := range s.Hosts {
				row(h.Host, h.Totals)
			}
			if len(s.Hosts) > 1 {
				row("total", s.Totals)
			}
			if len(s.Hosts) == 0 {
				fmt.Fprintln(out, "(no requests in this period)")
			}
			return nil
		},
	}
	fl := cmd.Flags()
	fl.StringVar(&since, "since", "24h", "start time or age (1h, 7d, 2026-01-02)")
	fl.StringVar(&until, "until", "", "end time or age")
	fl.StringVar(&q.Host, "host", "", "only this host")
	fl.BoolVar(&asJS, "json", false, "print JSON (includes the time series)")
	return cmd
}

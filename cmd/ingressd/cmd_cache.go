// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

// purgePathRe limits --path to characters that are literal in a regexp and
// need no escaping in a request path (the cache API matches the raw URI).
var purgePathRe = regexp.MustCompile(`^/[A-Za-z0-9/_~.-]*$`)

func newCacheCmd(e *env) *cobra.Command {
	cmd := &cobra.Command{Use: "cache", Short: "Manage the edge response cache"}

	var path string
	var all bool
	purge := &cobra.Command{
		Use:   "purge <app> (--path <prefix> | --all)",
		Short: "Remove an app's cached responses, by path prefix or all of them",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if all == (path != "") {
				return fmt.Errorf("give exactly one of --path or --all")
			}
			if path == "/" {
				all = true
			}
			if path != "" && !purgePathRe.MatchString(path) {
				return fmt.Errorf("--path must be a path prefix using only letters, digits and / _ ~ . -")
			}
			cfg, err := e.loadConfig()
			if err != nil {
				return err
			}
			app, ok := cfg.Apps[args[0]]
			if !ok {
				return fmt.Errorf("unknown app %q", args[0])
			}
			if !app.CacheEnabled() {
				return fmt.Errorf("app %q does not have caching enabled", args[0])
			}
			for _, h := range app.Hosts {
				// Cache keys look like GET-https-<host>-<path>[-<vary>];
				// IDX_-prefixed mapping keys share the same suffix.
				// For a wildcard host, "." (any char) precedes the parent domain.
				pattern := "-https-" + h
				if d, ok := strings.CutPrefix(h, "*."); ok {
					pattern = "." + d
				}
				pattern += "-"
				if !all {
					pattern += path
				}
				if err := cachePurge(cmd.Context(), e.adminSocket(), pattern); err != nil {
					return err
				}
			}
			what := "all cached responses"
			if !all {
				what = "cached responses under " + path
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Purged %s of %s.\n", what, args[0])
			return nil
		},
	}
	purge.Flags().StringVar(&path, "path", "", "purge URLs starting with this path (e.g. /blog/)")
	purge.Flags().BoolVar(&all, "all", false, "purge every cached response of the app")
	cmd.AddCommand(purge)
	return cmd
}

// cachePurge deletes cache keys matching pattern through cache-handler's
// API, which is mounted only on Caddy's admin socket (admin.api.souin).
func cachePurge(ctx context.Context, socket, pattern string) error {
	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", socket)
		}},
	}
	req, err := http.NewRequestWithContext(ctx, "PURGE", "http://localhost/souin-api/souin/", nil)
	if err != nil {
		return err
	}
	// The API reads the pattern from the raw request URI; send it unescaped.
	req.URL.Opaque = "/souin-api/souin/" + pattern
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("cache API: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("cache API: %s: %s", resp.Status, strings.TrimSpace(string(b)))
	}
	return nil
}

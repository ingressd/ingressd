// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/ingressd/ingressd/internal/geoip"
	"github.com/ingressd/ingressd/internal/render"
)

func (e *env) geoipDir() string { return filepath.Join(e.stateDir, "geoip") }

// securityOptions tells the renderer which GeoIP databases exist and where
// the WAF audit log goes (creating its directory).
func securityOptions(e *env) render.SecurityOptions {
	_ = os.MkdirAll(filepath.Dir(render.WAFAuditLog(e.stateDir)), 0o750)
	return render.SecurityOptions{
		StateDir:  e.stateDir,
		CountryDB: geoip.CountryDB(e.geoipDir()),
		ASNDB:     geoip.ASNDB(e.geoipDir()),
	}
}

var errNoGeoIP = errors.New("edge.geoip is not configured; country and ASN rules are disabled")

// updateGeoIP downloads the configured MaxMind databases that are older
// than maxAge. It reports whether any database changed.
func updateGeoIP(ctx context.Context, e *env, out io.Writer, maxAge time.Duration) (bool, error) {
	cfg, err := e.loadConfig()
	if err != nil {
		return false, err
	}
	g := cfg.Edge.GeoIP
	if g == nil || g.MaxMindAccountID == "" || g.MaxMindLicenseKey == "" {
		return false, errNoGeoIP
	}
	st, err := e.openSecrets()
	if err != nil {
		return false, err
	}
	key, err := st.Resolve(g.MaxMindLicenseKey)
	if err != nil {
		return false, fmt.Errorf("edge.geoip.maxmind_license_key: %w", err)
	}
	u := &geoip.Updater{Dir: e.geoipDir(), AccountID: g.MaxMindAccountID, LicenseKey: key, Editions: g.Editions, MaxAge: maxAge}
	res, err := u.Update(ctx)
	changed := false
	for _, r := range res {
		switch {
		case r.Updated:
			changed = true
			fmt.Fprintf(out, "%s: downloaded %s\n", r.Edition, r.Path)
		case r.Path != "":
			fmt.Fprintf(out, "%s: up to date (%s)\n", r.Edition, r.Path)
		}
	}
	if err != nil {
		err = errors.New(st.Redact(err.Error()))
	}
	return changed, err
}

func newGeoIPCmd(e *env) *cobra.Command {
	cmd := &cobra.Command{Use: "geoip", Short: "Manage MaxMind GeoLite2 databases for country and ASN rules"}
	var force bool
	update := &cobra.Command{
		Use:   "update",
		Short: "Download the GeoLite2 databases (skips copies younger than a day unless --force)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			maxAge := 24 * time.Hour
			if force {
				maxAge = 0
			}
			changed, err := updateGeoIP(cmd.Context(), e, cmd.OutOrStdout(), maxAge)
			if errors.Is(err, errNoGeoIP) {
				fmt.Fprintln(cmd.OutOrStdout(), "Skipped:", err)
				return nil
			}
			if changed {
				fmt.Fprintln(cmd.OutOrStdout(), "Run ingressd apply (or let serve re-apply) to use the new databases.")
			}
			return err
		},
	}
	update.Flags().BoolVar(&force, "force", false, "download even if the local copy is recent")
	cmd.AddCommand(update)
	return cmd
}

// startGeoIPUpdater keeps the databases fresh while serve runs: it checks
// shortly after startup and then every few hours, downloading copies older
// than a day. It signals on the returned channel when a database changed so
// serve re-applies (the database path is part of the rendered config).
func startGeoIPUpdater(ctx context.Context, e *env, log *slog.Logger) <-chan struct{} {
	changed := make(chan struct{}, 1)
	go func() {
		t := time.NewTimer(30 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
			ok, err := updateGeoIP(ctx, e, logWriter{log}, 24*time.Hour)
			switch {
			case errors.Is(err, errNoGeoIP):
			case err != nil:
				log.Warn("geoip update failed", "err", err)
			}
			if ok {
				select {
				case changed <- struct{}{}:
				default:
				}
			}
			t.Reset(6 * time.Hour)
		}
	}()
	return changed
}

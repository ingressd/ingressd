// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"slices"
	"time"

	"github.com/spf13/cobra"

	"github.com/ingressd/ingressd/internal/apply"
	"github.com/ingressd/ingressd/internal/tunnel"
)

// Cloudflare's published IPv4 ranges: a host resolving here is proxied
// (orange cloud), so traffic would bypass the edge.
var cloudflareRanges = []string{
	"173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
	"141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
	"197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
	"104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
}

func newDoctorCmd(e *env) *cobra.Command {
	return &cobra.Command{
		Use:   "doctor",
		Short: "Check that the host, config, DNS and tunnels are healthy",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if failed := doctor(cmd.Context(), e, cmd.OutOrStdout()); failed > 0 {
				return fmt.Errorf("%d check(s) failed", failed)
			}
			return nil
		},
	}
}

func doctor(ctx context.Context, e *env, out io.Writer) int {
	failed := 0
	check := func(name string, err error) {
		if err != nil {
			failed++
			fmt.Fprintf(out, "✗ %s: %v\n", name, err)
		} else {
			fmt.Fprintf(out, "✓ %s\n", name)
		}
	}
	warn := func(name string, err error) {
		if err != nil {
			fmt.Fprintf(out, "! %s: %v\n", name, err)
		}
	}

	check("running as root", func() error {
		if os.Geteuid() != 0 {
			return fmt.Errorf("managing interfaces and nftables needs root")
		}
		return nil
	}())
	for _, bin := range []string{"nft", "git"} {
		_, err := exec.LookPath(bin)
		check(bin+" installed", err)
	}
	check("wireguard kernel module", func() error {
		if _, err := os.Stat("/sys/module/wireguard"); err != nil {
			return fmt.Errorf("not loaded (modprobe wireguard)")
		}
		return nil
	}())

	cctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	_, err := apply.NewCaddy(e.adminSocket()).Config(cctx)
	check("ingressd-edge reachable at "+e.adminSocket(), err)

	cfg, err := e.loadConfig()
	check("config valid", err)
	if err != nil {
		return failed
	}

	var cf []netip.Prefix
	for _, r := range cloudflareRanges {
		cf = append(cf, netip.MustParsePrefix(r))
	}
	for name, app := range cfg.Apps {
		for _, h := range app.Hosts {
			if h[0] == '*' {
				continue
			}
			warn(fmt.Sprintf("DNS for %s (app %s)", h, name), func() error {
				addrs, err := net.DefaultResolver.LookupNetIP(cctx, "ip4", h)
				if err != nil {
					return err
				}
				for _, a := range addrs {
					if slices.ContainsFunc(cf, func(p netip.Prefix) bool { return p.Contains(a) }) {
						return fmt.Errorf("resolves to Cloudflare (%s): set the record to DNS only", a)
					}
					if cfg.Edge.PublicIPv4 != "" && a.String() != cfg.Edge.PublicIPv4 {
						return fmt.Errorf("resolves to %s, not this edge (%s)", a, cfg.Edge.PublicIPv4)
					}
				}
				return nil
			}())
		}
	}

	if sts, err := tunnel.ReadStatus(cfg); err == nil {
		now := time.Now()
		for _, s := range sts {
			var err error
			if !s.Healthy(now) {
				err = fmt.Errorf("no handshake in the last %s (is the site connected?)", tunnel.HandshakeTimeout)
			}
			warn("tunnel "+s.Tunnel, err)
			warn("tunnel "+s.Tunnel+" connector", connectorHealth(e, s.Tunnel, now))
		}
	}
	doctorOps(e, cfg, check, warn)
	return failed
}

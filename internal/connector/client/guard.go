// SPDX-License-Identifier: Apache-2.0

package client

import (
	"cmp"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"strings"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/ingressd/ingressd/internal/connector/proto"
)

const (
	// maxConfigBody caps a tunnel config read from an edge (the largest
	// part, a signed Smart DNS config, is capped at 256 KiB).
	maxConfigBody = 4 << 20
	// maxReachTargets caps the reachability tests per report.
	maxReachTargets = 256
	// minMTU and maxMTU bound the tunnel MTU an edge may ask for.
	minMTU, maxMTU = 576, 9000
)

var (
	sharedAddressSpace = netip.MustParsePrefix("100.64.0.0/10")
	cloudMetadata      = netip.MustParseAddr("169.254.169.254")
)

// errRelayUnauthorized: the edge refused the WebSocket relay's credentials.
var errRelayUnauthorized = errors.New("relay refused the connector's authorization")

// transitPrefix parses an edge's Address for use on this host. Only the
// site and edge addresses of a transit network are ever used, and they are
// its first two hosts, so a wider prefix is narrowed to the four addresses
// holding them: managed nodes hand out /30s, standalone configs often /24s.
func transitPrefix(s string) (netip.Prefix, bool) {
	p, err := netip.ParsePrefix(s)
	if err != nil {
		return netip.Prefix{}, false
	}
	a := p.Addr()
	if a.IsUnspecified() || a.IsLoopback() || a.IsMulticast() || a.IsLinkLocalUnicast() {
		return netip.Prefix{}, false
	}
	if bits := a.BitLen() - 2; p.Bits() < bits {
		p = netip.PrefixFrom(a, bits)
	}
	return p, true
}

// privateTransit reports whether s is a usable Address in shared or private
// address space, the only ranges a running connector moves a transit to.
func privateTransit(s string) bool {
	p, ok := transitPrefix(s)
	return ok && (sharedAddressSpace.Contains(p.Addr()) || p.Addr().IsPrivate())
}

// hostOnly reports addresses that mean this machine, or its cloud provider,
// rather than a device on the site's network.
func hostOnly(a netip.Addr) bool {
	a = a.Unmap()
	return a.IsLoopback() || a.IsUnspecified() || a.IsMulticast() || a == cloudMetadata
}

// checkConfig refuses a polled config that could not run, leaving the
// connector on the one it has. old is the config it would replace.
func checkConfig(tc, old proto.TunnelConfig) error {
	if _, err := wgtypes.ParseKey(tc.EdgePublicKey); err != nil {
		return fmt.Errorf("edge public key: %w", err)
	}
	if _, _, err := net.SplitHostPort(tc.Endpoint); err != nil {
		return fmt.Errorf("endpoint %q: %w", tc.Endpoint, err)
	}
	if _, ok := transitPrefix(tc.Address); !ok {
		return fmt.Errorf("unusable transit address %q", tc.Address)
	}
	if tc.Address != old.Address && !privateTransit(tc.Address) {
		return fmt.Errorf("transit address %q is outside private address space", tc.Address)
	}
	return nil
}

// sanitizeConfig drops the entries of a config that would stop the link
// from starting, keeping the rest of the site running.
func sanitizeConfig(tc *proto.TunnelConfig, log *slog.Logger) {
	tc.Subnets = slices.DeleteFunc(slices.Clone(tc.Subnets), func(s string) bool {
		_, err := netip.ParsePrefix(s)
		if err != nil {
			log.Warn("ignoring an invalid subnet from the edge", "subnet", s)
		}
		return err != nil
	})
	tc.Transparent = slices.DeleteFunc(slices.Clone(tc.Transparent), func(s string) bool {
		_, ok := transparentAddr(s)
		if !ok {
			log.Warn("ignoring an invalid transparent source from the edge", "source", s)
		}
		return !ok
	})
	if tc.MTU != 0 && (tc.MTU < minMTU || tc.MTU > maxMTU) {
		log.Warn("ignoring an invalid MTU from the edge", "mtu", tc.MTU)
		tc.MTU = 0
	}
}

// transparentAddr parses a "tcp/192.168.0.17:25565" or "udp/..." source.
func transparentAddr(s string) (netip.AddrPort, bool) {
	network, addr, ok := strings.Cut(s, "/")
	if !ok || (network != "tcp" && network != "udp") {
		return netip.AddrPort{}, false
	}
	ap, err := netip.ParseAddrPort(addr)
	if err != nil || !ap.Addr().Is4() {
		return netip.AddrPort{}, false
	}
	return ap, true
}

// forwardPrefixes are the destinations the edges may reach through this
// host: the site subnets and the transparent L4 sources, leaving out
// prefixes inside another one.
func (s *State) forwardPrefixes() []netip.Prefix {
	var all []netip.Prefix
	for _, v := range s.Subnets() {
		if p, err := netip.ParsePrefix(v); err == nil {
			all = append(all, p.Masked())
		}
	}
	for _, v := range s.Transparent() {
		if ap, ok := transparentAddr(v); ok {
			all = append(all, netip.PrefixFrom(ap.Addr(), 32))
		}
	}
	slices.SortFunc(all, func(a, b netip.Prefix) int {
		return cmp.Or(cmp.Compare(a.Bits(), b.Bits()), a.Addr().Compare(b.Addr()))
	})
	var out []netip.Prefix
	for _, p := range all {
		if !slices.ContainsFunc(out, func(o netip.Prefix) bool { return o.Contains(p.Addr()) }) {
			out = append(out, p)
		}
	}
	return out
}

// reachTargets are the Targets this host tests: addresses inside the
// destinations it forwards to, at most maxReachTargets of them.
func (s *State) reachTargets() []string {
	allowed := s.forwardPrefixes()
	var out []string
	for _, t := range s.Targets() {
		ap, err := netip.ParseAddrPort(t)
		if err != nil || hostOnly(ap.Addr()) {
			continue
		}
		a := ap.Addr().Unmap()
		if !slices.ContainsFunc(allowed, func(p netip.Prefix) bool { return p.Contains(a) }) {
			continue
		}
		if out = append(out, t); len(out) == maxReachTargets {
			break
		}
	}
	return out
}

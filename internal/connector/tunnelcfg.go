// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/ingressd/ingressd/internal/connector/proto"
	"github.com/ingressd/ingressd/internal/render"
	"github.com/ingressd/ingressd/pkg/config"
)

// EdgeKeys provides the edge's WireGuard public key per tunnel
// (tunnel.Keys implements it).
type EdgeKeys interface {
	EdgePublic(tunnel string) (string, error)
}

// TransparentSources returns the "tcp/host:port" origins on a tunnel that are
// published in transparent L4 mode, so the connector routes their replies
// back through the tunnel. The L4 feature sets it; nil means none.
var TransparentSources func(cfg *config.Config, tunnel string) []string

// DefaultHost, if set, returns the node's own hostname or public IP (managed
// mode: edge-endpoint.json). It is used when edge.admin.hostname is unset.
var DefaultHost func() string

// TunnelConfig builds the connector-facing config for a tunnel.
func TunnelConfig(cfg *config.Config, keys EdgeKeys, name string) (proto.TunnelConfig, error) {
	t, ok := cfg.Tunnels[name]
	if !ok {
		return proto.TunnelConfig{}, fmt.Errorf("unknown tunnel %q", name)
	}
	transit, err := netip.ParsePrefix(t.Transit)
	if err != nil {
		return proto.TunnelConfig{}, err
	}
	machine := ""
	if DefaultHost != nil {
		machine = DefaultHost()
	}
	host := cmp.Or(cfg.Edge.Admin.Hostname, machine, cfg.Edge.PublicIPv4)
	if host == "" {
		return proto.TunnelConfig{}, fmt.Errorf("no endpoint: set edge.admin.hostname or edge.public_ipv4")
	}
	pub, err := keys.EdgePublic(name)
	if err != nil {
		return proto.TunnelConfig{}, err
	}
	tc := proto.TunnelConfig{
		Tunnel:        name,
		EdgePublicKey: pub,
		Endpoint:      net.JoinHostPort(host, strconv.Itoa(t.ListenPort)),
		Address:       netip.PrefixFrom(render.SiteAddr(transit), transit.Bits()).String(),
		EdgeAddress:   render.EdgeAddr(transit).String(),
		Subnets:       cfg.TunnelRoutes(name), // what the connector forwards to
		Keepalive:     t.Keepalive,
		MTU:           render.DefaultMTU,
		FallbackWS:    t.FallbackWS,
		Targets:       Targets(cfg, name),
		Siblings:      siblings(t),
		KeyAuth:       proto.KeyAuthV2,
	}
	if wsHost := cmp.Or(cfg.Edge.Admin.Hostname, machine); t.FallbackWS && wsHost != "" {
		tc.WSURL = "wss://" + wsHost + proto.TunnelPathPrefix + name
	}
	if TransparentSources != nil {
		tc.Transparent = TransparentSources(cfg, name)
	}
	b, _ := json.Marshal(tc)
	sum := sha256.Sum256(b)
	tc.Revision = hex.EncodeToString(sum[:8])
	return tc, nil
}

// Targets lists the distinct host:port origins reached through a tunnel.
func Targets(cfg *config.Config, tunnel string) []string {
	var out []string
	add := func(t, addr string) {
		if t != tunnel || addr == "" {
			return
		}
		if hp := hostPort(addr); hp != "" {
			out = append(out, hp)
		}
	}
	for _, a := range cfg.Apps {
		add(a.Tunnel, a.Origin)
	}
	for _, p := range cfg.Pools {
		for _, o := range p.Origins {
			add(o.Tunnel, o.Address)
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// hostPort turns an origin ("http://192.168.0.17:8080", "10.0.0.5:22") into
// host:port, defaulting the port from the scheme.
func hostPort(addr string) string {
	if !strings.Contains(addr, "://") {
		if _, _, err := net.SplitHostPort(addr); err == nil {
			return addr
		}
		return ""
	}
	u, err := url.Parse(addr)
	if err != nil || u.Hostname() == "" {
		return ""
	}
	port := u.Port()
	if port == "" {
		switch u.Scheme {
		case "https", "wss":
			port = "443"
		default:
			port = "80"
		}
	}
	return net.JoinHostPort(u.Hostname(), port)
}

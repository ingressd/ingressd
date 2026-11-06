// SPDX-License-Identifier: Apache-2.0

package render

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/ingressd/ingressd/pkg/config"
)

// ForwardServer is the Caddy server name of the forward listener.
const ForwardServer = "forward"

// withForwarding lets an app's reverse_proxy fall back to its siblings'
// forward listeners (edge.forward.siblings): the edge_forward selection
// policy keeps local upstreams while their tunnel is up, and the
// edge_forward transport signs the requests it sends to a sibling.
func withForwarding(cfg *config.Config, res Resolver, name string, app config.App, rp obj) (obj, error) {
	sibs := cfg.ForwardSiblings(name)
	if len(sibs) == 0 || rp["handler"] != "reverse_proxy" {
		return rp, nil
	}
	secret, err := res.Resolve(cfg.Edge.Forward.Secret)
	if err != nil {
		return nil, fmt.Errorf("edge.forward.secret: %w", err)
	}
	self, _ := cfg.Mesh.MeshPrefix()
	tunnels := obj{}
	for _, o := range proxiedOrigins(app, poolFor(cfg, app)) {
		if o.Tunnel == "" {
			continue
		}
		dial, _, err := dialAddress(cfg, o)
		if err != nil {
			return nil, err
		}
		tunnels[dial] = o.Tunnel
	}
	ups := rp["upstreams"].([]obj)
	for _, s := range sibs {
		ups = append(ups, obj{"dial": s})
	}
	rp["upstreams"] = ups
	lb := rp["load_balancing"].(obj)
	lb["selection_policy"] = obj{"policy": "edge_forward", "local": lb["selection_policy"], "tunnels": tunnels, "siblings": sibs}
	// Long enough to retry a sibling after one local dial timeout (a dead
	// tunnel swallows the SYN until its handshake goes stale).
	lb["try_duration"] = "12s"
	rp["health_checks"] = obj{"passive": obj{"fail_duration": "30s", "max_fails": 1}}
	tr := rp["transport"].(obj)
	tr["protocol"] = "edge_forward"
	tr["forward"] = obj{"secret": secret, "node": self.Addr().String(), "app": name, "siblings": sibs}
	return rp, nil
}

// forwardServer is the forward listener (edge.forward.listen_mesh): on the
// mesh address only, it accepts signed hops from mesh peers and proxies each
// to the local origins of the app the hop names. It runs no access, WAF or
// cache handlers (the first node did), never forwards again, and keeps no
// access log, so a forwarded request is logged and metered once.
func forwardServer(cfg *config.Config, res Resolver) (obj, error) {
	f := cfg.Edge.Forward
	self, ok := cfg.Mesh.MeshPrefix()
	if f == nil || !f.ListenMesh || !ok {
		return nil, nil
	}
	secret, err := res.Resolve(f.Secret)
	if err != nil {
		return nil, fmt.Errorf("edge.forward.secret: %w", err)
	}
	peers, ranges := []string{}, []string{}
	for _, id := range sortedKeys(cfg.Mesh.Peers) {
		if a, ok := cfg.Mesh.Peers[id].PeerAddr(); ok {
			peers = append(peers, a.String())
			ranges = append(ranges, netip.PrefixFrom(a, 32).String())
		}
	}
	routes := []obj{{"handle": []obj{{"handler": "edge_forward_verify", "secret": secret, "self": self.Addr().String(), "peers": peers}}}}
	for _, name := range sortedKeys(cfg.Apps) {
		if !cfg.ForwardTarget(name) {
			continue
		}
		rp, err := reverseProxy(cfg, cfg.Apps[name])
		if err != nil {
			return nil, fmt.Errorf("app %s: %w", name, err)
		}
		routes = append(routes, obj{
			"match":    []obj{{"vars": obj{"edge_forward_app": []string{name}}}},
			"handle":   []obj{rp},
			"terminal": true,
		})
	}
	routes = append(routes, obj{"handle": []obj{{"handler": "static_response", "status_code": 404, "body": "Unknown app\n"}}})
	return obj{
		"listen":          []string{netip.AddrPortFrom(self.Addr(), config.ForwardPort).String()},
		"routes":          routes,
		"automatic_https": obj{"disable": true},
		// The first node set X-Forwarded-For; keep the visitor's address.
		"trusted_proxies": obj{"source": "static", "ranges": ranges},
	}, nil
}

// forwardInputRules opens the forward listener to mesh peers on ix-mesh.
func forwardInputRules(cfg *config.Config) string {
	f := cfg.Edge.Forward
	if f == nil || !f.ListenMesh || cfg.Mesh == nil {
		return ""
	}
	var peers []string
	for _, id := range sortedKeys(cfg.Mesh.Peers) {
		if a, ok := cfg.Mesh.Peers[id].PeerAddr(); ok {
			peers = append(peers, a.String())
		}
	}
	if len(peers) == 0 {
		return ""
	}
	return fmt.Sprintf("\t\tiifname %q ip saddr { %s } tcp dport %d accept\n", config.MeshInterface, strings.Join(peers, ", "), config.ForwardPort)
}

// forwardOutputRule exempts the siblings' forward listeners from the
// restricted output chain's mesh drop (the proxy runs unprivileged).
func forwardOutputRule(cfg *config.Config) string {
	var addrs []string
	seen := map[string]bool{}
	for _, name := range sortedKeys(cfg.Apps) {
		for _, s := range cfg.ForwardSiblings(name) {
			a := strings.TrimSuffix(s, fmt.Sprintf(":%d", config.ForwardPort))
			if !seen[a] {
				seen[a] = true
				addrs = append(addrs, a)
			}
		}
	}
	if len(addrs) == 0 {
		return ""
	}
	return fmt.Sprintf("\t\tip daddr { %s } tcp dport %d accept\n", strings.Join(addrs, ", "), config.ForwardPort)
}

// SPDX-License-Identifier: Apache-2.0

package render

import (
	"maps"
	"net/netip"
	"slices"
	"strings"

	"github.com/ingressd/ingressd/pkg/config"
)

// ControlHosts are the hostnames Caddy forwards to the control plane's own
// HTTP server: the admin hostname (machine endpoints under /.ingressd/;
// there is no local admin UI since rev1), the access portal (Phase 3) and
// login-to-play hosts (Phase 4).
func ControlHosts(cfg *config.Config) []string {
	var hosts []string
	if h := cfg.Edge.Admin.Hostname; h != "" {
		hosts = append(hosts, h)
	}
	hosts = append(hosts, cfg.LoginToPlayHosts()...)
	if a := cfg.Access; a != nil && a.PortalHost != "" {
		hosts = append(hosts, a.PortalHost)
	}
	return hosts
}

// controlHosts adds the machine host (managed mode) to ControlHosts unless
// an app already claims it.
func controlHosts(cfg *config.Config, opts Options) []string {
	hosts := ControlHosts(cfg)
	if m := strings.ToLower(opts.MachineHost); m != "" && !slices.Contains(hosts, m) && !appHost(cfg, m) {
		hosts = append(hosts, m)
	}
	return hosts
}

func appHost(cfg *config.Config, host string) bool {
	for _, a := range cfg.Apps {
		for _, h := range a.Hosts {
			if strings.EqualFold(h, host) {
				return true
			}
		}
	}
	return false
}

// machineIP returns the machine host if it is a bare IP address that needs
// an internal-CA certificate.
func machineIP(cfg *config.Config, opts Options) (string, bool) {
	a, err := netip.ParseAddr(opts.MachineHost)
	if err != nil || appHost(cfg, opts.MachineHost) {
		return "", false
	}
	return a.String(), true
}

// controlRoutes proxies the control hosts to the control socket. They come
// before app routes so an app can never shadow them. An admin hostname that
// an app also claims keeps only the machine endpoints (/.ingressd/*); the
// app serves everything else on it.
func controlRoutes(cfg *config.Config, opts Options) []obj {
	if opts.ControlSocket == "" {
		return nil
	}
	hosts := controlHosts(cfg, opts)
	var shared, restricted []string
	allowed, limited := adminAllowed(cfg)
	if a := strings.ToLower(cfg.Edge.Admin.Hostname); a != "" && (limited || appHost(cfg, a)) {
		hosts = slices.DeleteFunc(hosts, func(h string) bool { return strings.EqualFold(h, a) })
		if appHost(cfg, a) {
			shared = []string{a}
		} else {
			restricted = []string{a}
		}
	}
	proxy := []obj{{
		"handler":   "reverse_proxy",
		"upstreams": []obj{{"dial": "unix/" + opts.ControlSocket}},
	}}
	machine := []string{"/.ingressd/*", legacyMachinePath}
	var routes []obj
	if len(hosts) > 0 {
		routes = append(routes, obj{"match": []obj{{"host": hosts}}, "handle": proxy, "terminal": true})
	}
	if len(shared) > 0 {
		routes = append(routes, obj{"match": []obj{{"host": shared, "path": machine}}, "handle": proxy, "terminal": true})
	}
	if len(restricted) > 0 {
		// The machine endpoints stay public: connectors enrol and fall back
		// to the WebSocket tunnel from anywhere, authenticated by their
		// token or credential. Everything else on the admin hostname is
		// limited to the allowed clients.
		routes = append(routes, obj{"match": []obj{{"host": restricted, "path": machine}}, "handle": proxy, "terminal": true})
		if len(allowed) > 0 {
			routes = append(routes, obj{"match": []obj{{"host": restricted, "remote_ip": obj{"ranges": allowed}}}, "handle": proxy, "terminal": true})
		}
		routes = append(routes, obj{"match": []obj{{"host": restricted}}, "handle": forbidden, "terminal": true})
	}
	return routes
}

// adminAllowed returns the client ranges edge.admin.exposure allows on the
// admin hostname (beyond the machine endpoints), and whether it is limited
// at all: ip_allowlist allows its list; tunnel_only allows the tunnels'
// transit networks and the mesh, i.e. clients reaching the edge over
// WireGuard. An empty list allows no one.
func adminAllowed(cfg *config.Config) ([]string, bool) {
	var ranges []string
	switch cfg.Edge.Admin.Exposure {
	case config.ExposureIPAllowlist:
		for _, c := range cfg.Edge.Admin.IPAllowlist {
			if p, err := config.ParseCIDR(c); err == nil {
				ranges = append(ranges, p.String())
			}
		}
	case config.ExposureTunnelOnly:
		for _, name := range slices.Sorted(maps.Keys(cfg.Tunnels)) {
			if p, err := netip.ParsePrefix(cfg.Tunnels[name].Transit); err == nil {
				ranges = append(ranges, p.Masked().String())
			}
		}
		if p, ok := cfg.Mesh.MeshPrefix(); ok {
			ranges = append(ranges, p.Masked().String())
		}
	default:
		return nil, false
	}
	return ranges, true
}

// legacyMachinePath keeps old connectors' machine endpoints routed.
const legacyMachinePath = "/.homeedge/*" // legacy homeedge name, remove after 2027-01

// machineIPTLS gives a bare-IP machine host a certificate from Caddy's
// internal CA (the connector pins that CA via the join string), ahead of
// the default ACME policy.
func machineIPTLS(cfg *config.Config, opts Options, apps obj, tlsApp obj) {
	ip, ok := machineIP(cfg, opts)
	if !ok || opts.ControlSocket == "" {
		return
	}
	auto, _ := tlsApp["automation"].(obj)
	if auto == nil {
		return
	}
	pols, _ := auto["policies"].([]obj)
	auto["policies"] = append([]obj{{"subjects": []string{ip}, "issuers": []obj{{"module": "internal"}}}}, pols...)
	if _, ok := apps["pki"]; !ok {
		apps["pki"] = obj{"certificate_authorities": obj{"local": obj{"install_trust": false}}}
	}
}

// SPDX-License-Identifier: Apache-2.0

package render

import (
	"cmp"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/ingressd/ingressd/pkg/config"
)

type obj = map[string]any

var acmeDirectories = map[string]string{
	"letsencrypt":         "https://acme-v02.api.letsencrypt.org/directory",
	"letsencrypt_staging": "https://acme-staging-v02.api.letsencrypt.org/directory",
}

func renderCaddy(cfg *config.Config, res Resolver, opts Options) (json.RawMessage, error) {
	// Exact hosts must match before wildcards, so they go first.
	var exact, wild []obj
	for _, name := range sortedKeys(cfg.Apps) {
		app := cfg.Apps[name]
		redirected := map[string]bool{}
		for _, r := range app.Redirects {
			redirected[r.From] = true
			exact = append(exact, obj{
				"match": []obj{{"host": []string{r.From}}},
				"handle": []obj{{
					"handler":     "static_response",
					"status_code": r.Code,
					"headers":     obj{"Location": []string{"https://" + r.To + "{http.request.uri}"}},
				}},
				"terminal": true,
			})
		}

		handlers, err := appHandlers(cfg, name, app, res, opts)
		if err != nil {
			return nil, fmt.Errorf("app %s: %w", name, err)
		}
		handlers = withCacheAndFallback(name, app, opts, handlers)
		if handlers, err = withAccess(cfg, res, opts, name, handlers); err != nil {
			return nil, fmt.Errorf("app %s: %w", name, err)
		}
		var exactHosts, wildHosts []string
		for _, h := range app.Hosts {
			switch {
			case redirected[h]:
			case strings.HasPrefix(h, "*."):
				wildHosts = append(wildHosts, h)
			default:
				exactHosts = append(exactHosts, h)
			}
		}
		route := func(hosts []string) obj {
			return obj{
				"match":    []obj{{"host": hosts}},
				"handle":   []obj{{"handler": "subroute", "routes": []obj{{"handle": handlers}}}},
				"terminal": true,
			}
		}
		if len(exactHosts) > 0 {
			exact = append(exact, route(exactHosts))
		}
		if len(wildHosts) > 0 {
			wild = append(wild, route(wildHosts))
		}
	}
	routes := append(controlRoutes(cfg, opts), exact...)
	routes = append(routes, wild...)
	routes = append(routes, obj{"handle": []obj{{
		"handler": "static_response", "status_code": 404, "body": "Unknown host\n",
	}}})

	httpsPort := cmp.Or(opts.HTTPSPort, 443)
	// Hosts covered by a wildcard in tls.certificates.automate use that
	// certificate automatically; Caddy only issues for the rest.
	httpApp := obj{"servers": obj{"edge": obj{
		"listen": []string{fmt.Sprintf(":%d", httpsPort)},
		"routes": routes,
	}}}
	if opts.HTTPPort != 0 {
		httpApp["http_port"] = opts.HTTPPort
	}
	if opts.HTTPSPort != 0 {
		httpApp["https_port"] = opts.HTTPSPort
	}

	tlsApp, err := renderTLS(cfg, res)
	if err != nil {
		return nil, err
	}
	apps := obj{"http": httpApp, "tls": tlsApp}
	if l4 := l4CaddyApp(cfg); l4 != nil {
		apps["layer4"] = l4
	}
	if err := renderSecurityApps(cfg, res, apps); err != nil {
		return nil, err
	}
	if c := renderCacheApp(cfg); c != nil {
		apps["cache"] = c
	}
	machineIPTLS(cfg, opts, apps, tlsApp)
	if cfg.Edge.ACME.CA == "internal" {
		apps["pki"] = obj{"certificate_authorities": obj{"local": obj{"install_trust": false}}}
	}

	root := obj{"admin": obj{"listen": opts.AdminListen}, "apps": apps}
	renderLogging(root, httpApp, opts)
	fwd, err := forwardServer(cfg, res)
	if err != nil {
		return nil, err
	}
	if fwd != nil {
		httpApp["servers"].(obj)[ForwardServer] = fwd
	}
	if st := renderStorage(opts); st != nil {
		root["storage"] = st
	}
	b, err := json.MarshalIndent(root, "", "  ")
	return b, err
}

func renderTLS(cfg *config.Config, res Resolver) (obj, error) {
	var issuer obj
	if ca := cfg.Edge.ACME.CA; ca == "internal" {
		issuer = obj{"module": "internal"}
	} else {
		dir := cmp.Or(acmeDirectories[ca], ca)
		// test_ca = ca: without it Caddy retries every failed Let's Encrypt
		// issuance against LE's staging CA, which some hosting networks
		// cannot reach, and stays stuck there until the edge restarts.
		issuer = obj{"module": "acme", "ca": dir, "test_ca": dir}
		if e := cfg.Edge.ACME.Email; e != "" { // optional for Let's Encrypt
			issuer["email"] = e
		}
		if dp := cfg.Edge.ACME.DNSProvider; dp != nil {
			tok, err := res.Resolve(dp.APIToken)
			if err != nil {
				return nil, fmt.Errorf("edge.acme.dns_provider.api_token: %w", err)
			}
			issuer["challenges"] = obj{"dns": obj{"provider": obj{"name": dp.Type, "api_token": tok}}}
		}
	}
	t := obj{"automation": obj{"policies": []obj{{"issuers": []obj{issuer}}}}}
	if w := cfg.Certificates.Wildcards; len(w) > 0 {
		t["certificates"] = obj{"automate": w}
	}
	return t, nil
}

func appHandlers(cfg *config.Config, name string, app config.App, res Resolver, opts Options) ([]obj, error) {
	var hs []obj
	if h := app.Headers; h != nil {
		if req := h.Request; req != nil && (len(req.Set) > 0 || len(req.Delete) > 0) {
			hs = append(hs, obj{"handler": "headers", "request": headerOps(req.Set, req.Delete)})
		}
		if resp := responseHeaders(h); resp != nil {
			hs = append(hs, obj{"handler": "headers", "response": resp})
		}
	}
	if px := app.Proxy; px != nil && px.MaxBody != "" {
		n, err := config.ParseSize(px.MaxBody)
		if err != nil {
			return nil, err
		}
		hs = append(hs, obj{"handler": "request_body", "max_size": n})
	}
	sec, err := securityHandlers(cfg, name, app, res, opts)
	if err != nil {
		return nil, err
	}
	hs = append(hs, sec...)
	rp, err := reverseProxy(cfg, app)
	if err != nil {
		return nil, err
	}
	if rp, err = withForwarding(cfg, res, name, app, rp); err != nil {
		return nil, err
	}
	return append(hs, rp), nil
}

var headerPresets = map[string]map[string]string{
	"basic": {
		"X-Content-Type-Options": "nosniff",
		"Referrer-Policy":        "strict-origin-when-cross-origin",
	},
	"strict": {
		"X-Content-Type-Options":    "nosniff",
		"Referrer-Policy":           "strict-origin-when-cross-origin",
		"Strict-Transport-Security": "max-age=31536000",
		"X-Frame-Options":           "DENY",
		"Permissions-Policy":        "camera=(), microphone=(), geolocation=()",
	},
}

func responseHeaders(h *config.Headers) obj {
	set := map[string]string{}
	var del []string
	if p, ok := headerPresets[h.Preset]; ok {
		for k, v := range p {
			set[k] = v
		}
		del = append(del, "Server")
	}
	if r := h.Response; r != nil {
		for k, v := range r.Set {
			set[k] = v
		}
		del = append(del, r.Delete...)
	}
	if len(set) == 0 && len(del) == 0 {
		return nil
	}
	ops := headerOps(set, del)
	ops["deferred"] = true
	return ops
}

// literal escapes Caddy placeholder braces: configured header names and
// values are text, never {env.*}/{file.*} lookups (validation already
// rejects braces; this is defence in depth).
var literal = strings.NewReplacer(`{`, `\{`, `}`, `\}`).Replace

func headerOps(set map[string]string, del []string) obj {
	o := obj{}
	if len(set) > 0 {
		s := obj{}
		for k, v := range set {
			s[literal(k)] = []string{literal(v)}
		}
		o["set"] = s
	}
	if len(del) > 0 {
		d := make([]string, len(del))
		for i, k := range del {
			d[i] = literal(k)
		}
		o["delete"] = d
	}
	return o
}

// poolFor returns the app's pool, expanding the origin shorthand.
func poolFor(cfg *config.Config, app config.App) config.Pool {
	if app.Pool != "" {
		return cfg.Pools[app.Pool]
	}
	return config.Pool{
		Steering: "round_robin",
		Origins: []config.Origin{{
			Name: "origin", Tunnel: app.Tunnel, Address: app.Origin,
			Weight: 1, Priority: 1, State: config.OriginActive,
		}},
	}
}

var selectionPolicies = map[string]string{
	"round_robin": "round_robin",
	"weighted":    "weighted_round_robin",
	"least_conn":  "least_conn",
	"failover":    "first",
	"random":      "random",
	"ip_hash":     "ip_hash",
}

func reverseProxy(cfg *config.Config, app config.App) (obj, error) {
	pool := poolFor(cfg, app)
	origins := proxiedOrigins(app, pool)
	if len(origins) == 0 {
		return obj{"handler": "static_response", "status_code": 503, "body": "No origin available\n"}, nil
	}
	if pool.Steering == "failover" {
		slices.SortStableFunc(origins, func(a, b config.Origin) int { return cmp.Compare(a.Priority, b.Priority) })
	}

	var ups []obj
	var weights []int
	useTLS := false
	for _, o := range origins {
		dial, scheme, err := dialAddress(cfg, o)
		if err != nil {
			return nil, err
		}
		useTLS = useTLS || scheme == "https"
		ups = append(ups, obj{"dial": dial})
		weights = append(weights, o.Weight)
	}

	sel := obj{"policy": selectionPolicies[pool.Steering]}
	if pool.Steering == "weighted" {
		sel["weights"] = weights
	}
	if app.Pool != "" {
		var err error
		if sel, err = tieredSelection(cfg, app.Pool, pool, origins); err != nil {
			return nil, err
		}
	}
	transport := obj{"protocol": "http", "dial_timeout": "5s"}
	if useTLS {
		if err := originTLS(cfg, app, transport); err != nil { // tls.go
			return nil, err
		}
	}
	if px := app.Proxy; px != nil && px.Timeout > 0 {
		d := time.Duration(px.Timeout).String()
		transport["read_timeout"] = d
		transport["write_timeout"] = d
	}
	lb := obj{"selection_policy": sel}
	rp := obj{"handler": "reverse_proxy", "upstreams": ups, "load_balancing": lb, "transport": transport}
	// Retrying and ejecting failed upstreams only helps when there is another
	// upstream to fail over to; with one origin it would just delay errors.
	if len(ups) > 1 {
		lb["try_duration"] = "5s"
		rp["health_checks"] = obj{"passive": obj{"fail_duration": "30s", "max_fails": 1}}
	}
	return rp, nil
}

// dialAddress returns host:port for an origin as reached from the edge,
// translating addresses on remapped tunnels to their virtual prefix.
func dialAddress(cfg *config.Config, o config.Origin) (dial, scheme string, err error) {
	u, err := url.Parse(o.Address)
	if err != nil {
		return "", "", err
	}
	host, port := u.Hostname(), u.Port()
	if port == "" {
		port = map[string]string{"http": "80", "https": "443"}[u.Scheme]
	}
	if a, err := netip.ParseAddr(host); err == nil && o.Tunnel != "" {
		host = Virtual(cfg.Tunnels[o.Tunnel], a).String()
	}
	return net.JoinHostPort(host, port), u.Scheme, nil
}

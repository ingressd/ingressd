// SPDX-License-Identifier: Apache-2.0

package nodeagent

import (
	"cmp"
	"fmt"
	"time"

	"github.com/ingressd/ingressd/internal/connector"
	"github.com/ingressd/ingressd/internal/connector/proto"
	"github.com/ingressd/ingressd/internal/edgecert"
	"github.com/ingressd/ingressd/internal/secrets"
	"github.com/ingressd/ingressd/internal/tunnel"
	"github.com/ingressd/ingressd/pkg/config"
	"github.com/ingressd/ingressd/pkg/nodeproto"
)

// endpoint is how sites and connectors reach this node: the enrolment
// hostname or public IP, else the config's admin hostname / public IP.
func (a *Agent) endpoint(cfg *config.Config) (host string, isIP bool) {
	st := a.State()
	ep := Endpoint{Hostname: st.Hostname, PublicIPv4: st.PublicIPv4}
	if ep.Host() == "" {
		ep = LoadEndpoint(a.o.StateDir)
	}
	if ep.Host() == "" && cfg != nil {
		ep = Endpoint{Hostname: cfg.Edge.Admin.Hostname, PublicIPv4: cfg.Edge.PublicIPv4}
	}
	return ep.Host(), ep.HostIsIP()
}

// ConnectorToken answers connector_token_request: a one-time enrolment
// token for a connector site, packed into a join string with the edge URL
// (and, for a bare-IP edge, the internal CA the connector must pin).
func (a *Agent) ConnectorToken(req nodeproto.ConnectorTokenRequest) nodeproto.ConnectorToken {
	res := nodeproto.ConnectorToken{Site: req.Site}
	cfg, err := a.loadConfig()
	if err != nil {
		res.Error = "config: " + err.Error()
		return res
	}
	t, ok := cfg.Tunnels[req.Site]
	if !ok {
		res.Error = fmt.Sprintf("unknown site %q (has the snapshot that adds it been applied?)", req.Site)
		return res
	}
	if t.Site != config.SiteConnector {
		res.Error = fmt.Sprintf("site %q is a %s site, not a connector site", req.Site, t.Site)
		return res
	}
	host, isIP := a.endpoint(cfg)
	if host == "" {
		res.Error = "this node has neither a hostname nor a public IP for connectors to reach"
		return res
	}
	j := proto.Join{URL: "https://" + host}
	if isIP {
		pem, err := edgecert.InternalCARoot(a.o.CaddyStorage)
		if err != nil {
			res.Error = "the edge's internal CA is not initialised yet (retry once the node has applied its config): " + err.Error()
			return res
		}
		j.CA = string(pem)
	}
	now := time.Now()
	tok, err := a.o.ConnectorStore.CreateToken(req.Site, now)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	j.Token = tok
	s, err := proto.EncodeJoin(j)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	res.JoinString = s
	res.ExpiresAt = now.Add(connector.TokenTTL).UTC()
	return res
}

// SiteConfig answers site_config_request with the router's WireGuard config.
func (a *Agent) SiteConfig(req nodeproto.SiteConfigRequest) nodeproto.SiteConfig {
	res := nodeproto.SiteConfig{Site: req.Site}
	cfg, err := a.loadConfig()
	if err != nil {
		res.Error = "config: " + err.Error()
		return res
	}
	if _, ok := cfg.Tunnels[req.Site]; !ok {
		res.Error = fmt.Sprintf("unknown site %q", req.Site)
		return res
	}
	host, _ := a.endpoint(cfg)
	format := cmp.Or(req.Format, tunnel.FormatWGQuick)
	if format != tunnel.FormatWGQuick && format != tunnel.FormatWG {
		res.Error = fmt.Sprintf("unknown format %q (wg-quick or wg)", req.Format)
		return res
	}
	err = a.o.Pipeline.WithSecrets(func(st *secrets.Store) error {
		keys := tunnel.Keys{Cfg: cfg, Store: st}
		if a.o.Keys != nil {
			keys = a.o.Keys(cfg, st)
		}
		c, err := tunnel.SiteConfig(cfg, keys, req.Site, tunnel.SiteOptions{Endpoint: host, Format: format})
		res.Config = c
		return err
	})
	if err != nil {
		res.Error = err.Error()
		res.Config = ""
	}
	return res
}

// discover asks a site's connector to scan its LAN; the results arrive
// later through the connector's report and are forwarded as `discovery`.
func (a *Agent) discover(s *session, envID string, req nodeproto.DiscoverRequest) {
	fail := func(msg string) {
		_ = a.sendOn(s, nodeproto.TypeEvent, envID, nodeproto.Event{
			Kind: "discovery_failed", Severity: "warning", Message: msg,
			Fields: map[string]string{"site": req.Site}, Time: time.Now().UTC(),
		})
	}
	if a.o.Connectors == nil {
		fail("connector discovery is not available on this node")
		return
	}
	cfg, err := a.loadConfig()
	if err != nil {
		fail("config: " + err.Error())
		return
	}
	if t, ok := cfg.Tunnels[req.Site]; !ok || t.Site != config.SiteConnector {
		fail(fmt.Sprintf("site %q is not a connector site on this node", req.Site))
		return
	}
	a.discMu.Lock()
	a.discReqs[req.Site] = envID
	a.discMu.Unlock()
	if _, err := a.o.Connectors.RequestDiscovery(req.Site); err != nil {
		fail(err.Error())
	}
}

// onDiscovery relays a connector's discovery report to the panel.
func (a *Agent) onDiscovery(site string, r proto.DiscoveryReport) {
	a.discMu.Lock()
	id := a.discReqs[site]
	delete(a.discReqs, site)
	a.discMu.Unlock()
	if r.Error != "" { // the scan could not run: tell the panel why
		_ = a.send(nodeproto.TypeEvent, "", nodeproto.Event{
			Kind: "discovery_failed", Severity: "warning", Message: r.Error,
			Fields: map[string]string{"site": site}, Time: time.Now().UTC(),
		})
	}
	d := nodeproto.Discovery{Site: site, Services: []nodeproto.DiscoveredService{}}
	for _, sv := range r.Services {
		d.Services = append(d.Services, nodeproto.DiscoveredService{
			Address: sv.Address, Port: sv.Port, Scheme: sv.Scheme, Title: sv.Title, Server: sv.Server,
		})
	}
	if err := a.send(nodeproto.TypeDiscovery, id, d); err != nil {
		a.log.Warn("could not forward discovery results", "site", site, "err", err)
	}
}

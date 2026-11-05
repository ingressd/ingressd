// SPDX-License-Identifier: Apache-2.0

package nodeagent

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/ingressd/ingressd/internal/alerts"
	"github.com/ingressd/ingressd/internal/apply"
	"github.com/ingressd/ingressd/internal/connector/proto"
	"github.com/ingressd/ingressd/internal/edgecert"
	"github.com/ingressd/ingressd/internal/observe"
	"github.com/ingressd/ingressd/internal/tunnel"
	"github.com/ingressd/ingressd/pkg/config"
	"github.com/ingressd/ingressd/pkg/nodeproto"
)

// Check names whose failure means the node cannot serve at all.
const (
	checkEdge   = "edge proxy reachable"
	checkConfig = "config valid"
)

// minFreeDisk below which status warns.
const minFreeDisk = 1 << 30

func (a *Agent) loadConfig() (*config.Config, error) {
	cfg, err := config.Load(a.o.ConfigPath)
	if err != nil {
		return nil, err
	}
	return cfg, cfg.Validate()
}

// buildStatus assembles a status report.
func (a *Agent) buildStatus(ctx context.Context) nodeproto.Status {
	now := time.Now()
	st := nodeproto.Status{
		Time:            now.UTC(),
		AppliedRevision: a.State().AppliedRevision,
		Uptime:          int64(time.Since(a.start).Seconds()),
	}
	var checks []nodeproto.Check
	add := func(name string, err error, warn bool) {
		c := nodeproto.Check{Name: name, OK: err == nil}
		if err != nil {
			c.Message = err.Error()
			c.Warn = warn
		}
		checks = append(checks, c)
	}
	if runtime.GOOS == "linux" {
		add("running as root", boolErr(os.Geteuid() == 0, "managing interfaces and nftables needs root"), false)
		for _, bin := range []string{"nft", "git"} {
			_, err := exec.LookPath(bin)
			add(bin+" installed", err, false)
		}
		_, err := os.Stat("/sys/module/wireguard")
		add("wireguard kernel module", boolErr(err == nil, "not loaded (modprobe wireguard)"), false)
	}
	if a.o.AdminSocket != "" {
		cctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		_, err := apply.NewCaddy(a.o.AdminSocket).Config(cctx)
		cancel()
		add(checkEdge, err, false)
	}
	cfg, cerr := a.loadConfig()
	add(checkConfig, cerr, false)
	if u, err := alerts.DiskUsage(a.o.StateDir); err == nil {
		st.DiskFreeBytes = int64(u.Free)
		add("disk space", boolErr(u.Free >= minFreeDisk, fmt.Sprintf("only %d MiB free on the state disk", u.Free>>20)), true)
	}
	if cfg != nil && cerr == nil {
		st.Tunnels = a.tunnelStatus(cfg, now)
		for _, t := range st.Tunnels {
			add("tunnel "+t.Site, boolErr(t.Up, "no handshake in the last "+tunnel.HandshakeTimeout.String()+" (is the site connected?)"), true)
		}
		st.Certs = a.certStatus(cfg, now)
	}
	if a.o.ExtraChecks != nil {
		checks = append(checks, a.o.ExtraChecks(ctx)...)
	}
	st.Exits = hookExits()
	st.SmartDNSServices = hookServices()
	st.Mesh = hookMesh()
	st.Checks = checks
	st.Health = health(checks)
	return st
}

func boolErr(ok bool, msg string) error {
	if ok {
		return nil
	}
	return fmt.Errorf("%s", msg)
}

// health: down when the edge cannot serve, degraded on any other problem.
func health(checks []nodeproto.Check) string {
	h := nodeproto.HealthOK
	for _, c := range checks {
		if c.OK {
			continue
		}
		if !c.Warn && (c.Name == checkEdge || c.Name == checkConfig) {
			return nodeproto.HealthDown
		}
		h = nodeproto.HealthDegraded
	}
	return h
}

func (a *Agent) tunnelStatus(cfg *config.Config, now time.Time) []nodeproto.TunnelStatus {
	if len(cfg.Tunnels) == 0 {
		return nil
	}
	sts, err := tunnel.ReadStatus(cfg)
	if err != nil {
		return nil
	}
	cs, _ := a.o.ConnectorStore.Load()
	edgeKeys := a.edgePublicKeys(cfg)
	var out []nodeproto.TunnelStatus
	for _, s := range sts {
		ts := nodeproto.TunnelStatus{
			Site: s.Tunnel, Up: s.Healthy(now), LastHandshake: s.LastHandshake.UTC(),
			Endpoint: s.Endpoint, RxBytes: s.RxBytes, TxBytes: s.TxBytes,
			EdgePublicKey: edgeKeys[s.Tunnel],
		}
		if cfg.Tunnels[s.Tunnel].Site == config.SiteConnector {
			ts.Transport = "udp"
			ts.ConnectorPublicKey = connectorKey(cfg, cs, s.Tunnel)
			if cs != nil {
				if c := cs.Connectors[s.Tunnel]; c != nil && c.Health != nil {
					if c.Health.Transport != "" {
						ts.Transport = c.Health.Transport
					}
					h := c.Health
					ts.ConnectorVersion, ts.ConnectorInstall, ts.ConnectorOS, ts.ConnectorArch = h.Version, h.Install, h.OS, h.Arch
					ts.ConnectorUpdate = connectorUpdateState(h.Update)
					ts.ConnectorEdges = connectorEdges(h.Edges)
				}
			}
		}
		out = append(out, ts)
	}
	return out
}

// certHosts are the hostnames that need an edge certificate.
func certHosts(cfg *config.Config) []string {
	var hosts []string
	for _, app := range cfg.Apps {
		hosts = append(hosts, app.Hosts...)
		for _, r := range app.Redirects {
			hosts = append(hosts, r.From)
		}
	}
	if a := cfg.Access; a != nil && a.PortalHost != "" {
		hosts = append(hosts, a.PortalHost)
	}
	for i := range hosts {
		hosts[i] = strings.ToLower(hosts[i])
	}
	slices.Sort(hosts)
	return slices.Compact(hosts)
}

func (a *Agent) certStatus(cfg *config.Config, now time.Time) []nodeproto.CertStatus {
	certs, _ := edgecert.List(a.o.CaddyStorage)
	var out []nodeproto.CertStatus
	for _, h := range certHosts(cfg) {
		out = append(out, CertState(certs, h, now, certFailures.failure(h)))
	}
	return out
}

// CertState maps the certificates Caddy holds (and the last issuance error
// seen in its tls log for host, if any) to a CertStatus.
func CertState(certs []*x509.Certificate, host string, now time.Time, failure string) nodeproto.CertStatus {
	cs := nodeproto.CertStatus{Host: host}
	c := edgecert.Best(certs, host)
	switch {
	case c != nil && edgecert.Valid(c, now):
		cs.State = nodeproto.CertValid
		cs.Issuer = edgecert.IssuerName(c)
		cs.NotAfter = c.NotAfter.UTC()
	case failure != "":
		cs.State = nodeproto.CertFailed
		cs.Error = failure
	default:
		cs.State = nodeproto.CertIssuing
		if c != nil {
			cs.Issuer = edgecert.IssuerName(c)
			cs.NotAfter = c.NotAfter.UTC()
			cs.Error = "certificate expired; renewing"
		}
	}
	return cs
}

// certTracker remembers Caddy's latest certificate issuance error per host.
type certTracker struct {
	mu     sync.Mutex
	failed map[string]string
}

var certFailures = &certTracker{failed: map[string]string{}}

// ObserveCaddyEvent feeds Caddy's non-access log lines (observe.Options.
// OnEvent) to the certificate tracker, so status can report `failed` with
// the ACME error.
func ObserveCaddyEvent(ev observe.LogEvent) {
	if !strings.HasPrefix(ev.Logger, "tls.obtain") && !strings.HasPrefix(ev.Logger, "tls.renew") && !strings.HasPrefix(ev.Logger, "tls.issuance") {
		return
	}
	id, _ := ev.Fields["identifier"].(string)
	if id == "" {
		return
	}
	id = strings.ToLower(id)
	msg := strings.ToLower(ev.Msg)
	certFailures.mu.Lock()
	defer certFailures.mu.Unlock()
	switch {
	case strings.Contains(msg, "obtained successfully") || strings.Contains(msg, "renewed successfully"):
		delete(certFailures.failed, id)
	case ev.Level == "error" || strings.Contains(msg, "could not get certificate"):
		e, _ := ev.Fields["error"].(string)
		if e == "" {
			e = ev.Msg
		}
		if len(e) > 500 {
			e = e[:500]
		}
		certFailures.failed[id] = e
	}
}

func (t *certTracker) failure(host string) string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.failed[host]
}

// statusSignature covers the fields whose change triggers an immediate
// status message (not counters or timestamps).
func statusSignature(s nodeproto.Status) string {
	type tun struct {
		Site string
		Up   bool
		T    string
		V    string // connector version and update state
	}
	type ex struct {
		Name string
		Up   bool
	}
	sig := struct {
		H     string
		R     int64
		C     []nodeproto.Check
		T     []tun
		Certs []string
		E     []ex
		M     []ex
	}{H: s.Health, R: s.AppliedRevision, C: s.Checks}
	for _, t := range s.Tunnels {
		v := t.ConnectorVersion
		if u := t.ConnectorUpdate; u != nil {
			v += "/" + u.ID + "/" + u.State
		}
		sig.T = append(sig.T, tun{t.Site, t.Up, t.Transport, v})
	}
	for _, c := range s.Certs {
		sig.Certs = append(sig.Certs, c.Host+"="+c.State)
	}
	for _, e := range s.Exits {
		sig.E = append(sig.E, ex{e.Name, e.Up})
	}
	for _, m := range s.Mesh {
		sig.M = append(sig.M, ex{m.NodeID, m.Up})
	}
	b, _ := json.Marshal(sig)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func connectorEdges(in []proto.EdgeReport) []nodeproto.ConnectorEdge {
	var out []nodeproto.ConnectorEdge
	for _, e := range in {
		out = append(out, nodeproto.ConnectorEdge{Node: e.Node, EdgePublicKey: e.EdgePublicKey, RTTMillis: e.RTTMillis, Up: e.Up, Transport: e.Transport})
	}
	return out
}

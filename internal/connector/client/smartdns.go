// SPDX-License-Identifier: Apache-2.0

package client

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"filippo.io/age"
	"filippo.io/age/armor"

	"github.com/ingressd/ingressd/internal/smartdns"
	"github.com/ingressd/ingressd/pkg/config"
	"github.com/ingressd/ingressd/pkg/nodeproto"
)

// Smart DNS on the connector (docs/rev1/CONNECTOR-SMARTDNS.md): the
// resolver and relay listen on a LAN address of this host, VPN exits run
// here, and node exits are reached through the tunnel to that node. The
// config comes from the edges, signed by the org key; no edge can change
// it or read the VPN configs inside.

// SmartDNSStatusPath is the connector's Smart DNS status file.
func SmartDNSStatusPath(statePath string) string {
	return filepath.Join(filepath.Dir(statePath), "smartdns-status.json")
}

// recentReported is how many lookups each health report carries.
const recentReported = 100

type sdController struct {
	statePath string
	log       *slog.Logger
	mgr       *smartdns.Manager

	mu      sync.Mutex
	sess    *session
	age     *age.X25519Identity
	applied string // signature of the config in effect
	issued  time.Time
	errMsg  string
	listen  string
	vpns    map[string]*vpnExit
	ctx     context.Context
	pending []nodeproto.ServiceUsage
}

func newSDController(ctx context.Context, statePath string, log *slog.Logger) *sdController {
	c := &sdController{statePath: statePath, log: log, vpns: map[string]*vpnExit{}, ctx: ctx}
	c.mgr = smartdns.New(smartdns.Options{
		Log:        log,
		StatusPath: SmartDNSStatusPath(statePath),
		Remote: &smartdns.TunnelExitClient{
			Addr:   c.nodeAddr,
			NodeUp: c.nodeUp,
			Dial:   c.dialTunnel,
		},
	})
	go c.mgr.Run(ctx)
	go c.watch(ctx)
	return c
}

// ensureAgeIdentity generates the connector's age key on first start.
func ensureAgeIdentity(st *State) (*age.X25519Identity, bool, error) {
	if st.AgeIdentity != "" {
		id, err := age.ParseX25519Identity(st.AgeIdentity)
		return id, false, err
	}
	id, err := age.GenerateX25519Identity()
	if err != nil {
		return nil, false, err
	}
	st.AgeIdentity = id.String()
	return id, true, nil
}

// attach makes s the session whose tunnels the node exits use, and applies
// the newest config its edges carry.
func (c *sdController) attach(s *session, id *age.X25519Identity) {
	c.mu.Lock()
	c.sess, c.age = s, id
	c.mu.Unlock()
	c.update()
}

func (c *sdController) detach(s *session) {
	c.mu.Lock()
	if c.sess == s {
		c.sess = nil
	}
	c.mu.Unlock()
}

func (c *sdController) session() *session {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.sess
}

// edgeFor returns the session's edge runner for a node id.
func (c *sdController) edgeFor(node string) *edge {
	s := c.session()
	if s == nil || node == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, e := range s.edges {
		if e.config().Node == node {
			return e
		}
	}
	return nil
}

func (c *sdController) nodeAddr(node string) (netip.Addr, bool) {
	e := c.edgeFor(node)
	if e == nil {
		return netip.Addr{}, false
	}
	a, err := netip.ParseAddr(e.config().Config.EdgeAddress)
	return a, err == nil
}

func (c *sdController) nodeUp(node string) bool {
	e := c.edgeFor(node)
	return e != nil && e.tunnelUp()
}

func (c *sdController) dialTunnel(ctx context.Context, network, addr string) (net.Conn, error) {
	if !strings.HasPrefix(network, "tcp") {
		return nil, fmt.Errorf("the tunnel carries only TCP to node exits, not %s", network)
	}
	s := c.session()
	if s == nil {
		return nil, errors.New("the tunnel is not up")
	}
	return s.link.DialTunnel(ctx, addr)
}

// candidate is one edge's signed config.
type candidate struct {
	env nodeproto.SignedSmartDNS
	raw string
}

// update applies the newest valid config any edge carries; with none,
// Smart DNS stops.
func (c *sdController) update() {
	s := c.session()
	if s == nil {
		return
	}
	st := s.stateCopy()
	connector := s.priv.PublicKey().String()
	var best *candidate
	var refused []string
	for _, es := range st.Edges {
		raw := es.Config.SmartDNS
		if len(raw) == 0 {
			continue
		}
		var env nodeproto.SignedSmartDNS
		if err := json.Unmarshal(raw, &env); err != nil {
			refused = append(refused, "unreadable config: "+err.Error())
			continue
		}
		if err := env.Verify(connector); err != nil {
			refused = append(refused, err.Error())
			continue
		}
		if st.OrgKey != "" && env.Key != st.OrgKey {
			refused = append(refused, "config signed by another org key than the pinned one")
			continue
		}
		if best == nil || env.Issued.After(best.env.Issued) {
			best = &candidate{env: env, raw: string(raw)}
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if best == nil && len(refused) > 0 {
		// A config that does not verify never replaces or stops the one in
		// effect: otherwise an edge could turn Smart DNS off.
		c.errMsg = strings.Join(refused, "; ")
		return
	}
	if best == nil {
		if c.applied != "" {
			c.log.Info("smart DNS turned off (no edge carries a config)")
		}
		c.stopLocked()
		c.applied, c.listen = "", ""
		c.errMsg = strings.Join(refused, "; ")
		return
	}
	if best.env.Signature == c.applied {
		c.errMsg = strings.Join(refused, "; ")
		return
	}
	if best.env.Issued.Before(st.SmartDNSIssued) {
		c.errMsg = fmt.Sprintf("refused a config issued %s, older than the one in effect", best.env.Issued.UTC().Format(time.RFC3339))
		return
	}
	plan, listen, err := c.planLocked(st, best.env)
	if err != nil {
		c.errMsg = err.Error()
		c.log.Warn("smart DNS config not applied", "err", err)
		return
	}
	c.mgr.Reconfigure(plan)
	c.applied, c.issued, c.listen, c.errMsg = best.env.Signature, best.env.Issued, listen, ""
	c.log.Info("smart DNS config applied", "issued", best.env.Issued, "listen", listen, "services", len(plan.Services), "exits", len(plan.Exits))
	s.mu.Lock()
	changed := false
	if s.st.OrgKey == "" {
		s.st.OrgKey, changed = best.env.Key, true
		c.log.Warn("pinned the org key from the first smart DNS config (the join string carried none)")
	}
	if best.env.Issued.After(s.st.SmartDNSIssued) {
		s.st.SmartDNSIssued, changed = best.env.Issued, true
	}
	if changed {
		if err := s.st.Save(s.r.StatePath); err != nil {
			c.log.Warn("save state", "err", err)
		}
	}
	s.mu.Unlock()
}

// planLocked turns a verified config into the engine's plan, starting and
// stopping VPN exits to match.
func (c *sdController) planLocked(st *State, env nodeproto.SignedSmartDNS) (smartdns.Plan, string, error) {
	var site config.SmartDNSSite
	dec := json.NewDecoder(bytes.NewReader(env.Config))
	if err := dec.Decode(&site); err != nil {
		return smartdns.Plan{}, "", fmt.Errorf("smart DNS config: %w", err)
	}
	site.Normalize()
	if err := site.Validate(); err != nil {
		return smartdns.Plan{}, "", fmt.Errorf("smart DNS config: %w", err)
	}
	listen := site.ListenAddr()
	if !listen.IsValid() {
		a, err := defaultLANAddr()
		if err != nil {
			return smartdns.Plan{}, "", err
		}
		listen = a
	}
	plan := smartdns.Plan{
		Site: st.Tunnel(), Listen: []netip.Addr{listen}, Upstream: site.Upstream,
		FailbackAfter: site.FailbackDuration(), Services: site.Services, Exits: map[string]smartdns.PlanExit{}, Checks: site.Checks,
	}
	keep := map[string]bool{}
	for name, ex := range site.Exits {
		switch ex.At {
		case config.ExitAtNode:
			plan.Exits[name] = smartdns.PlanExit{Country: ex.Country, Node: ex.Node}
		case config.ExitAtConnector:
			v, err := c.vpnLocked(name, ex.VPN)
			if err != nil {
				return smartdns.Plan{}, "", fmt.Errorf("exit %s: %w", name, err)
			}
			keep[name] = true
			plan.Exits[name] = smartdns.PlanExit{Country: ex.Country, Egress: &smartdns.EgressOptions{
				DNS: v.dnsServers(site.Upstream), Dial: v.dial, Health: v.health, Endpoint: v.endpointNow, VPN: true, Sig: v.sigHash(),
			}}
		}
	}
	for name, v := range c.vpns {
		if !keep[name] {
			v.close()
			delete(c.vpns, name)
		}
	}
	return plan, listen.String(), nil
}

// vpnLocked returns the running VPN exit for name, restarting it when its
// config changed.
func (c *sdController) vpnLocked(name, ciphertext string) (*vpnExit, error) {
	text, err := c.decrypt(ciphertext)
	if err != nil {
		return nil, err
	}
	if v, ok := c.vpns[name]; ok {
		if v.sig == text {
			return v, nil
		}
		v.close()
		delete(c.vpns, name)
	}
	v, err := startVPNExit(c.ctx, name, text, c.log)
	if err != nil {
		return nil, err
	}
	c.vpns[name] = v
	return v, nil
}

// decrypt opens a VPN config encrypted to this connector (ASCII armor or
// base64 of the binary format).
func (c *sdController) decrypt(ciphertext string) (string, error) {
	if c.age == nil {
		return "", errors.New("no age identity")
	}
	var src io.Reader
	if strings.HasPrefix(strings.TrimSpace(ciphertext), armor.Header) {
		src = armor.NewReader(strings.NewReader(strings.TrimSpace(ciphertext)))
	} else {
		b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(ciphertext))
		if err != nil {
			return "", errors.New("VPN config is neither age armor nor base64")
		}
		src = bytes.NewReader(b)
	}
	r, err := age.Decrypt(src, c.age)
	if err != nil {
		return "", fmt.Errorf("VPN config is not encrypted to this connector (re-import it in the panel): %w", err)
	}
	b, err := io.ReadAll(io.LimitReader(r, config.MaxExitVPNConfig))
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func (c *sdController) stopLocked() {
	if c.applied != "" {
		c.mgr.Reconfigure(smartdns.Plan{})
	}
	for name, v := range c.vpns {
		v.close()
		delete(c.vpns, name)
	}
}

// report is the connector's Smart DNS state for its health reports.
func (c *sdController) report() *nodeproto.ConnectorSmartDNS {
	c.mu.Lock()
	r := &nodeproto.ConnectorSmartDNS{Issued: c.issued, Error: c.errMsg, Listen: c.listen, Addresses: lanAddrs()}
	if c.age != nil {
		r.AgeRecipient = c.age.Recipient().String()
	}
	running := c.applied != ""
	c.mu.Unlock()
	if !running {
		return r
	}
	if be := c.mgr.BindErrors(); len(be) > 0 {
		r.BindErrors = be
	}
	r.Exits = c.mgr.Exits()
	snap := c.mgr.Snapshot()
	for _, x := range snap.RemoteExits {
		r.Exits = append(r.Exits, nodeproto.ExitStatus{Name: x.Name, Country: x.Country, Up: x.Up, Message: x.Message})
	}
	r.Services = c.mgr.Services()
	r.Recent = c.mgr.RecentLookups(recentReported)
	return r
}

// takeUsage returns the relay usage not yet delivered to an edge.
func (c *sdController) takeUsage() []nodeproto.ServiceUsage {
	fresh := c.mgr.TakeServiceUsage()
	c.mu.Lock()
	defer c.mu.Unlock()
	out := append(c.pending, fresh...)
	c.pending = nil
	return out
}

// returnUsage keeps usage whose report failed for the next one.
func (c *sdController) returnUsage(u []nodeproto.ServiceUsage) {
	if len(u) == 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.pending) < 4096 {
		c.pending = append(c.pending, u...)
	}
}

// defaultLANAddr is the private IPv4 address of the interface holding the
// default route (no packet is sent).
func defaultLANAddr() (netip.Addr, error) {
	conn, err := net.Dial("udp4", "192.0.2.1:53")
	if err != nil {
		return netip.Addr{}, fmt.Errorf("no default route to pick a listen address: %w", err)
	}
	defer conn.Close()
	ap, err := netip.ParseAddrPort(conn.LocalAddr().String())
	if err != nil {
		return netip.Addr{}, err
	}
	a := ap.Addr().Unmap()
	if !a.IsPrivate() {
		return netip.Addr{}, fmt.Errorf("this host's address %s is not a private LAN address; set a listen address in the panel", a)
	}
	return a, nil
}

// lanAddrs lists this host's private IPv4 addresses.
func lanAddrs() []string {
	ifs, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	var out []string
	for _, a := range ifs {
		p, err := netip.ParsePrefix(a.String())
		if err != nil {
			continue
		}
		if ad := p.Addr().Unmap(); ad.Is4() && ad.IsPrivate() {
			out = append(out, ad.String())
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// dnsServers: the VPN config's DNS servers (the provider's resolver sees the
// exit's location), else the upstream resolvers asked through the tunnel.
func (v *vpnExit) dnsServers(upstream []string) []string {
	if len(v.dns) > 0 {
		return v.dns
	}
	return upstream
}

func (v *vpnExit) sigHash() string {
	sum := sha256.Sum256([]byte(v.sig))
	return hex.EncodeToString(sum[:8])
}

// smartDNSWatchEvery is how often the state is compared with what the
// edges last heard: a change is reported at once, not on the next 30 s
// report, so the panel shows an exit coming up within seconds.
const smartDNSWatchEvery = 2 * time.Second

func (c *sdController) watch(ctx context.Context) {
	t := time.NewTicker(smartDNSWatchEvery)
	defer t.Stop()
	last := ""
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		last = c.reportIfChanged(last)
	}
}

// reportIfChanged kicks every edge's reporter when the state differs from
// last, and returns the state's fingerprint.
func (c *sdController) reportIfChanged(last string) string {
	r := c.report()
	r.Recent = nil
	b, err := json.Marshal(r)
	if err != nil || string(b) == last {
		return last
	}
	if s := c.session(); s != nil {
		s.mu.Lock()
		for _, e := range s.edges {
			select {
			case e.kick <- struct{}{}:
			default:
			}
		}
		s.mu.Unlock()
	}
	return string(b)
}

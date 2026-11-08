// SPDX-License-Identifier: Apache-2.0

package smartdns

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/miekg/dns"
)

const (
	// serviceTTL is the TTL of the synthesized "name → this node" answer.
	serviceTTL = 300
	// remoteDownHold keeps an exit marked down after its node said so.
	remoteDownHold = 15 * time.Second
	queryTimeout   = 6 * time.Second
)

var privateSources = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("127.0.0.0/8"),
}

// allowedClient: the resolver and relay serve homes (tunnel and LAN
// sources), never the internet.
func allowedClient(a netip.Addr) bool {
	a = a.Unmap()
	for _, p := range privateSources {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

func netAddr(a net.Addr) netip.Addr {
	switch v := a.(type) {
	case *net.UDPAddr:
		ip, _ := netip.AddrFromSlice(v.IP)
		return ip.Unmap()
	case *net.TCPAddr:
		ip, _ := netip.AddrFromSlice(v.IP)
		return ip.Unmap()
	}
	if a == nil {
		return netip.Addr{}
	}
	ap, err := netip.ParseAddrPort(a.String())
	if err != nil {
		return netip.Addr{}
	}
	return ap.Addr().Unmap()
}

func (m *Manager) listenDNS(network, addr string) (io.Closer, error) {
	srv := &dns.Server{Handler: m, Net: network}
	if network == "udp" {
		pc, err := m.listenPktFn("udp4", addr)
		if err != nil {
			return nil, err
		}
		srv.PacketConn = pc
	} else {
		ln, err := m.listenFn("tcp4", addr)
		if err != nil {
			return nil, err
		}
		srv.Listener = ln
	}
	go func() {
		if err := srv.ActivateAndServe(); err != nil {
			m.log.Debug("DNS server stopped", "addr", addr, "err", err)
		}
	}()
	return closerFunc(srv.Shutdown), nil
}

// ServeDNS answers one query (dns.Handler).
func (m *Manager) ServeDNS(w dns.ResponseWriter, req *dns.Msg) {
	resp := m.answer(w.LocalAddr(), w.RemoteAddr(), req)
	if resp == nil {
		return
	}
	if _, udp := w.RemoteAddr().(*net.UDPAddr); udp {
		size := dns.MinMsgSize
		if opt := req.IsEdns0(); opt != nil {
			size = max(int(opt.UDPSize()), dns.MinMsgSize)
		}
		resp.Truncate(size)
	}
	w.WriteMsg(resp)
}

func reply(req *dns.Msg, rcode int) *dns.Msg {
	r := new(dns.Msg)
	r.SetRcode(req, rcode)
	r.RecursionAvailable = true
	return r
}

// answer builds the response to req received on local from remote.
func (m *Manager) answer(localAddr, remoteAddr net.Addr, req *dns.Msg) *dns.Msg {
	if req.Response || len(req.Question) != 1 {
		return reply(req, dns.RcodeFormatError)
	}
	if req.Opcode != dns.OpcodeQuery {
		return reply(req, dns.RcodeNotImplemented)
	}
	local, client := netAddr(localAddr), netAddr(remoteAddr)
	st := m.state()
	q := req.Question[0]
	name := normalize(q.Name)
	entry := Lookup{Time: time.Now().UTC(), Client: client.String(), Site: st.plan.Site, Name: name, Type: dns.TypeToString[q.Qtype]}
	if entry.Type == "" {
		entry.Type = fmt.Sprintf("TYPE%d", q.Qtype)
	}
	defer func() { m.recent.add(entry) }()
	if !allowedClient(client) {
		entry.Result = "refused (client not allowed)"
		return reply(req, dns.RcodeRefused)
	}

	ctx, cancel := context.WithTimeout(m.ctx(), queryTimeout)
	defer cancel()
	r, routed := st.match.match(name)
	if !routed || r.Direct {
		entry.Service = r.Service
		resp, err := m.forward(ctx, st, req)
		if err != nil {
			entry.Result = "SERVFAIL (upstream: " + err.Error() + ")"
			return reply(req, dns.RcodeServerFailure)
		}
		entry.Result = "upstream " + dns.RcodeToString[resp.Rcode]
		return resp
	}

	entry.Routed, entry.Service = true, r.Service
	switch q.Qtype {
	case dns.TypeAAAA, dns.TypeHTTPS, dns.TypeSVCB:
		// Keep clients on IPv4 and the plain hostname: the relay and
		// the exits are IPv4 only.
		entry.Result = "suppressed (IPv4 only)"
		return reply(req, dns.RcodeSuccess)
	case dns.TypeA:
	default:
		entry.Result = "empty (only A is routed)"
		return reply(req, dns.RcodeSuccess)
	}
	a, rcode, how, exit, err := m.lookup(ctx, st, r, name)
	entry.Exit = exit
	if err != nil {
		// Fail closed: never answer a service name from anywhere else.
		entry.Result = "SERVFAIL (" + err.Error() + ")"
		return reply(req, dns.RcodeServerFailure)
	}
	if rcode != dns.RcodeSuccess {
		entry.Result = how + ": " + dns.RcodeToString[rcode]
		return reply(req, rcode)
	}
	if len(a.Addrs) == 0 || !local.Is4() {
		entry.Result = how + ": no A records"
		return reply(req, dns.RcodeSuccess)
	}
	resp := reply(req, dns.RcodeSuccess)
	resp.Answer = []dns.RR{&dns.A{
		Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: serviceTTL},
		A:   local.AsSlice(),
	}}
	entry.Result = fmt.Sprintf("%s: %s -> %s", how, joinAddrs(a.Addrs), local)
	return resp
}

func joinAddrs(as []netip.Addr) string {
	s := make([]string, len(as))
	for i, a := range as {
		s[i] = a.String()
	}
	return strings.Join(s, ", ")
}

// forward sends a non-service query to the upstream resolvers.
func (m *Manager) forward(ctx context.Context, st *state, req *dns.Msg) (*dns.Msg, error) {
	return exchange(ctx, st.upstream, hostDial, req)
}

// exitUp reports whether an exit can egress right now.
func (m *Manager) exitUp(st *state, exit string) (bool, string) {
	ex, ok := st.exit(exit)
	if !ok {
		return false, fmt.Sprintf("unknown exit %q", exit)
	}
	if ex.Egress != nil {
		e, ok := st.egress[exit]
		if !ok {
			return false, "exit not configured"
		}
		return e.up()
	}
	if m.remote == nil || !m.remote.Up(ex.Node) {
		return false, fmt.Sprintf("the tunnel to exit node %s is down", ex.Node)
	}
	m.downMu.Lock()
	d, down := m.remoteDown[exit]
	m.downMu.Unlock()
	if down && m.now().Sub(d.at) < remoteDownHold {
		if d.msg != "" {
			return false, fmt.Sprintf("exit node %s reports the exit down: %s", ex.Node, d.msg)
		}
		return false, fmt.Sprintf("exit node %s reports the exit down", ex.Node)
	}
	return true, ""
}

type downMark struct {
	at  time.Time
	msg string
}

func (m *Manager) setRemoteDown(exit string, down bool, msg string) {
	m.downMu.Lock()
	defer m.downMu.Unlock()
	if down {
		m.remoteDown[exit] = downMark{m.now(), msg}
	} else {
		delete(m.remoteDown, exit)
	}
}

// lookup resolves a service name at the exit pick chooses and returns that
// exit, so the relay connects through the exit whose location the answer
// is for. An exit found down while resolving makes it try the next one;
// with every exit down it fails closed, whatever is cached.
func (m *Manager) lookup(ctx context.Context, st *state, r route, name string) (answer, int, string, string, error) {
	tried := map[string]bool{}
	var lastErr error
	for {
		exit, err := m.pick(st, r)
		if err != nil {
			return answer{}, 0, "", "", err
		}
		if tried[exit] {
			return answer{}, 0, "", exit, lastErr
		}
		tried[exit] = true
		a, rcode, how, err := m.lookupAt(ctx, st, exit, name)
		if err == nil || !errors.Is(err, errExitDown) || ctx.Err() != nil {
			return a, rcode, how, exit, err
		}
		lastErr = err
	}
}

// lookupAt resolves name at exit through the cache: fresh answers are
// returned as is, expired ones (up to 24 h) are returned at once and
// refreshed in the background, so a failing exit resolver keeps the last
// good answer. The caller checked that exit is up.
func (m *Manager) lookupAt(ctx context.Context, st *state, exit, name string) (answer, int, string, error) {
	k := cacheKey{exit, name}
	a, cs := m.cache.get(k)
	switch cs {
	case cacheFresh:
		return a, dns.RcodeSuccess, "cached", nil
	case cacheStale:
		if m.cache.startRefresh(k) {
			go func() {
				defer m.cache.endRefresh(k)
				ctx, cancel := context.WithTimeout(m.ctx(), queryTimeout)
				defer cancel()
				if _, _, err := m.resolveAtExit(ctx, st, exit, name); err != nil {
					m.log.Warn("background refresh failed; serving the stale answer", "name", name, "exit", exit, "err", err)
				}
			}()
		}
		return a, dns.RcodeSuccess, "stale (refreshing)", nil
	}
	rcode, a, err := m.resolveAtExit(ctx, st, exit, name)
	if err != nil {
		return answer{}, 0, "", err
	}
	return a, rcode, "exit " + exit, nil
}

// resolveAtExit asks the exit (a local egress or a node exit) and caches a
// good answer.
func (m *Manager) resolveAtExit(ctx context.Context, st *state, exit, name string) (int, answer, error) {
	ex, ok := st.exit(exit)
	if !ok {
		return 0, answer{}, fmt.Errorf("unknown exit %q", exit)
	}
	local := ex.Egress != nil
	var resp resolveResponse
	if local {
		e, ok := st.egress[exit]
		if !ok {
			return 0, answer{}, fmt.Errorf("exit %q not configured", exit)
		}
		resp = resolveVia(ctx, e, m.edges, name)
	} else {
		if m.remote == nil {
			return 0, answer{}, fmt.Errorf("%w: no tunnel to exit node %s", errExitDown, ex.Node)
		}
		var err error
		resp, err = m.remote.Resolve(ctx, ex.Node, name)
		if err != nil {
			m.setRemoteDown(exit, true, err.Error())
			return 0, answer{}, fmt.Errorf("%w: %v", errExitDown, err)
		}
	}
	if !resp.ExitUp {
		if !local {
			m.setRemoteDown(exit, true, resp.Error)
		}
		return 0, answer{}, fmt.Errorf("%w: %s", errExitDown, resp.Error)
	}
	if !local {
		m.setRemoteDown(exit, false, "")
	}
	if resp.Error != "" {
		return 0, answer{}, fmt.Errorf("exit %s could not resolve %s: %s", exit, name, resp.Error)
	}
	a := answer{Addrs: resp.Addrs, TTL: time.Duration(resp.TTL) * time.Second}
	if resp.Rcode == dns.RcodeSuccess {
		m.cache.put(cacheKey{exit, name}, a)
	}
	return resp.Rcode, a, nil
}

// resolveVia resolves name from a local egress (a connector VPN exit, or a
// node exit serving its connector sites).
func resolveVia(ctx context.Context, e *egress, edges *edgeChecker, name string) resolveResponse {
	if up, msg := e.up(); !up {
		return resolveResponse{Error: msg}
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	rcode, a, err := e.resolve(ctx, name)
	if err != nil {
		return resolveResponse{ExitUp: true, Error: err.Error()}
	}
	if len(a.Addrs) > 0 {
		edges.prewarm(e, name, a.Addrs)
	}
	return resolveResponse{ExitUp: true, Rcode: rcode, Addrs: a.Addrs, TTL: int(a.TTL / time.Second)}
}

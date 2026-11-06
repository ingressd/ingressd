// SPDX-License-Identifier: Apache-2.0

package client

import (
	"bytes"
	"cmp"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/ingressd/ingressd/internal/connector/proto"
	"github.com/ingressd/ingressd/internal/version"
)

// errNoPath: the edge can be reached neither over the tunnel nor publicly
// (a learned edge without a usable URL before its tunnel is up).
var errNoPath = errors.New("waiting for the tunnel (no public control URL for this edge)")

// tunnelControlRetry is how long to use only the public control channel
// after the tunnel control port failed (an older node without it).
const tunnelControlRetry = time.Minute

// edge runs one edge: its WireGuard peer and transport (UDP, WebSocket
// fallback), its control channel (long poll) and health reports.
type edge struct {
	s   *session
	key wgtypes.Key

	runCtx context.Context // the edge runner's context (discovery scans)
	cancel context.CancelFunc
	wg     sync.WaitGroup
	kick   chan struct{} // asks the reporter to report now

	// Fixed for the edge runner's lifetime (a URL change restarts it).
	host       string       // hostname of the public URL ("" = none)
	public     dialFunc     // dials the public URL (honours Addr)
	control    *http.Client // public HTTPS control channel (nil = none)
	ws         *http.Client // WebSocket relay
	tunnelHTTP *http.Client // plain HTTP to the tunnel control port

	mu          sync.Mutex
	cfg         EdgeState
	transport   string
	endpoint    string
	mtu         int
	lastPoll    time.Time
	pollErr     string
	tunnelFail  time.Time
	pollCancel  context.CancelFunc
	discoverID  string
	discovering atomic.Bool
	// keyAuthV1 sends v1 headers to a learned edge not polled yet; it flips
	// whenever such an edge refuses the version sent.
	keyAuthV1 atomic.Bool
	rtt       ewma // round trip through the tunnel (rtt.go)
}

func newEdge(s *session, key wgtypes.Key, es EdgeState) *edge {
	e := &edge{s: s, key: key, cfg: es, kick: make(chan struct{}, 1)}
	tunnelDial := func(ctx context.Context, _, addr string) (net.Conn, error) {
		tctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		return s.link.DialTunnel(tctx, addr)
	}
	e.tunnelHTTP = &http.Client{
		Timeout:   proto.PollWait + 20*time.Second,
		Transport: &http.Transport{DialContext: tunnelDial, IdleConnTimeout: 30 * time.Second, MaxIdleConnsPerHost: 2},
	}
	if host, err := edgeHost(es.URL); err == nil {
		e.host = host
		e.public = publicDialer(host, es.Addr)
		if tc, err := tlsConfig(host, es.CAFile, es.CAPEM, es.Insecure); err == nil {
			e.control = httpClient(tc, e.public, proto.PollWait+20*time.Second)
		} else {
			s.log.Warn("edge TLS settings", "edge", es.URL, "err", err)
		}
	}
	// The WebSocket relay only carries WireGuard datagrams, which WireGuard
	// authenticates end to end; its TLS protects the authorization header,
	// which only grants relaying for this tunnel. A learned edge with no
	// known CA (e.g. a bare-IP node with its own internal CA) is therefore
	// relayed without verifying the certificate. Configs are never taken
	// from an unverified connection, and an edge that accepts v2 key auth
	// gets a header bound to the relay request and usable once, so whoever
	// terminates that TLS cannot reuse it on the poll, report or discovery
	// endpoints. (Pinning instead needs the sibling's CA in the sibling
	// list, which the panel does not send yet.)
	wsHost := e.host
	if u, err := url.Parse(es.Config.WSURL); err == nil && u.Hostname() != "" {
		wsHost = u.Hostname()
	}
	wsTLS, _ := tlsConfig(wsHost, es.CAFile, es.CAPEM, es.Insecure || (es.Learned && es.CAFile == "" && es.CAPEM == ""))
	if wsTLS == nil {
		wsTLS = &tls.Config{ServerName: wsHost, NextProtos: []string{"http/1.1"}}
	}
	e.ws = httpClient(wsTLS, publicDialer(e.host, es.Addr), 0)
	return e
}

func (e *edge) config() EdgeState {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.cfg
}

func (e *edge) setConfig(es EdgeState) {
	e.mu.Lock()
	e.cfg = es
	e.mu.Unlock()
}

// label names the edge in logs and status.
func (e *edge) label() string {
	c := e.config()
	return cmp.Or(c.Node, c.URL, c.Config.Endpoint)
}

func (e *edge) start(ctx context.Context) {
	ctx, e.cancel = context.WithCancel(ctx)
	e.runCtx = ctx
	e.wg.Add(4)
	go func() { defer e.wg.Done(); e.transportLoop(ctx) }()
	go func() { defer e.wg.Done(); e.controlLoop(ctx) }()
	go func() { defer e.wg.Done(); e.reportLoop(ctx) }()
	go func() { defer e.wg.Done(); e.rttLoop(ctx) }()
}

func (e *edge) stop() {
	if e.cancel != nil {
		e.cancel()
	}
	e.wg.Wait()
}

func (e *edge) peerStats() (peerStats, bool) {
	ps, err := e.s.link.Stats()
	if err != nil {
		return peerStats{}, false
	}
	p, ok := ps[e.key]
	return p, ok
}

func (e *edge) stale() bool {
	p, ok := e.peerStats()
	return !ok || p.LastHandshake.IsZero() || time.Since(p.LastHandshake) > staleAfter
}

func (e *edge) tunnelUp() bool {
	p, ok := e.peerStats()
	return ok && !p.LastHandshake.IsZero() && time.Since(p.LastHandshake) < staleAfter
}

// waitHandshake waits for a handshake newer than since.
func (e *edge) waitHandshake(ctx context.Context, since time.Time, timeout time.Duration) bool {
	t := time.NewTicker(250 * time.Millisecond)
	defer t.Stop()
	deadline := time.After(timeout)
	for {
		if p, ok := e.peerStats(); ok && p.LastHandshake.After(since) {
			return true
		}
		select {
		case <-ctx.Done():
			return false
		case <-deadline:
			return false
		case <-t.C:
		}
	}
}

func (e *edge) setPeer(ep netip.AddrPort, reset bool) error {
	return e.s.link.SetPeer(peerConfig{
		PublicKey:  e.key,
		Endpoint:   ep,
		AllowedIPs: e.s.allowedIPs(e),
		Keepalive:  cmp.Or(e.config().Config.Keepalive, 25),
	}, reset)
}

// setPeerIPs updates the peer's AllowedIPs, keeping its endpoint.
func (e *edge) setPeerIPs() error { return e.setPeer(netip.AddrPort{}, false) }

// resolveEndpoint returns the edge's UDP endpoint.
func (e *edge) resolveEndpoint(ctx context.Context) (netip.AddrPort, error) {
	c := e.config()
	host, port, err := net.SplitHostPort(c.Config.Endpoint)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("endpoint %q: %w", c.Config.Endpoint, err)
	}
	if c.Addr != "" && host == e.host {
		host = c.Addr
	}
	ap, err := netip.ParseAddrPort(net.JoinHostPort(host, port))
	if err == nil {
		return ap, nil
	}
	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("resolve %s: %w", host, err)
	}
	if len(ips) == 0 {
		return netip.AddrPort{}, fmt.Errorf("resolve %s: no addresses", host)
	}
	slices.SortStableFunc(ips, func(a, b netip.Addr) int { // prefer IPv4
		return cmp.Compare(boolInt(!a.Unmap().Is4()), boolInt(!b.Unmap().Is4()))
	})
	p, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("endpoint port %q: %w", port, err)
	}
	return netip.AddrPortFrom(ips[0].Unmap(), uint16(p)), nil
}

// tryUDP points the peer at the edge's UDP endpoint and waits for a handshake.
func (e *edge) tryUDP(ctx context.Context) bool {
	ep, err := e.resolveEndpoint(ctx)
	if err != nil {
		e.s.log.Warn("UDP endpoint", "edge", e.label(), "err", err)
		return false
	}
	start := time.Now().Add(-time.Second)
	if err := e.setPeer(ep, true); err != nil {
		e.s.log.Error("configure peer", "edge", e.label(), "err", err)
		return false
	}
	timeout := cmp.Or(e.s.r.UDPTimeout, DefaultUDPTimeout)
	if !e.waitHandshake(ctx, start, timeout) {
		e.s.log.Info("no UDP handshake", "edge", e.label(), "endpoint", ep, "timeout", timeout)
		return false
	}
	mtu := e.s.probeUDPMTU(e.config().Config.EdgeAddress)
	e.s.log.Info("tunnel up over UDP", "edge", e.label(), "endpoint", ep, "mtu", mtu)
	e.setTransport(proto.TransportUDP, ep.String(), mtu)
	return true
}

// authHeader authenticates one request (method, URL path, body) to the
// edge's public endpoints: the enrolment credential, else a IngressdKey
// header from the site's WireGuard key, bound to the request (v2) when the
// edge accepts that, else v1 (an edge from before v2).
func (e *edge) authHeader(method, path string, body []byte) string {
	c := e.config()
	if c.Credential != "" {
		return proto.Bearer(c.Config.Tunnel, c.Credential)
	}
	var h string
	var err error
	if e.keyAuthVersion(c) >= proto.KeyAuthV2 {
		h, err = proto.KeyAuthRequest(c.Config.Tunnel, e.s.priv[:], e.key[:], time.Now(), method, path, body)
	} else {
		h, err = proto.KeyAuth(c.Config.Tunnel, e.s.priv[:], e.key[:], time.Now())
	}
	if err != nil {
		return ""
	}
	return h
}

// keyAuthVersion is the header version to send: what the edge's config
// advertises, and v2 first for a learned edge whose config is not known yet.
func (e *edge) keyAuthVersion(c EdgeState) int {
	if c.Config.KeyAuth >= proto.KeyAuthV2 {
		return proto.KeyAuthV2
	}
	if c.Learned && c.LastSeen.IsZero() && !e.keyAuthV1.Load() {
		return proto.KeyAuthV2
	}
	return 1
}

// authRejected notes that the edge answered 401 to header h, so a learned
// edge that may predate v2 gets the other version next. It keeps alternating
// because a new edge also answers 401 until it learns this connector's key.
func (e *edge) authRejected(h string) {
	c := e.config()
	if c.Credential != "" || c.Config.KeyAuth >= proto.KeyAuthV2 || !c.Learned || !c.LastSeen.IsZero() {
		return
	}
	if proto.KeyAuthVersion(h) == e.keyAuthVersion(c) {
		e.keyAuthV1.Store(!e.keyAuthV1.Load())
	}
}

// relaySource reports whether a datagram from addr came from this link's
// WireGuard socket.
func (e *edge) relaySource(addr netip.AddrPort) bool {
	p, err := e.s.link.ListenPort()
	return err != nil || p == 0 || p == int(addr.Port())
}

// tryWS connects the WebSocket relay and moves the peer onto it.
func (e *edge) tryWS(ctx context.Context) *wsRelay {
	cfg := e.config().Config
	if !cfg.FallbackWS || cfg.WSURL == "" {
		return nil
	}
	wsPath := ""
	if u, err := url.Parse(cfg.WSURL); err == nil {
		wsPath = u.Path
	}
	dctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	auth := e.authHeader(http.MethodGet, wsPath, nil)
	relay, err := dialRelay(dctx, cfg.WSURL, e.ws, http.Header{"Authorization": {auth}}, e.relaySource)
	cancel()
	if err != nil {
		if errors.Is(err, errRelayUnauthorized) {
			e.authRejected(auth)
		}
		e.s.log.Warn("WebSocket fallback failed", "edge", e.label(), "url", cfg.WSURL, "err", err)
		return nil
	}
	if !e.useRelay(ctx, relay) {
		relay.Close()
		return nil
	}
	return relay
}

func (e *edge) useRelay(ctx context.Context, relay *wsRelay) bool {
	start := time.Now().Add(-time.Second)
	e.mu.Lock()
	e.mtu = wsMTU // the device follows the smallest MTU any edge needs
	e.mu.Unlock()
	e.s.applyMTU()
	if err := e.setPeer(relay.Endpoint(), true); err != nil {
		e.s.log.Error("configure peer", "edge", e.label(), "err", err)
		return false
	}
	if !e.waitHandshake(ctx, start, cmp.Or(e.s.r.UDPTimeout, DefaultUDPTimeout)) {
		e.s.log.Warn("no handshake over WebSocket", "edge", e.label())
		return false
	}
	url := e.config().Config.WSURL
	e.s.log.Info("tunnel up over WebSocket", "edge", e.label(), "url", url, "mtu", wsMTU)
	e.setTransport(proto.TransportWebSocket, url, wsMTU)
	return true
}

// transportLoop selects and maintains the edge's transport: UDP first,
// WebSocket when UDP gets no handshake, and periodic UDP retries while on
// WebSocket. A lost tunnel also makes the session re-check the edge list.
func (e *edge) transportLoop(ctx context.Context) {
	var relay *wsRelay
	var wsSince time.Time
	transport := ""
	defer func() {
		if relay != nil {
			relay.Close()
		}
	}()
	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()
	var relayDone <-chan struct{}
	for ctx.Err() == nil {
		if transport == "" {
			e.setTransport("", "", 0)
			if e.tryUDP(ctx) {
				transport = proto.TransportUDP
				continue
			}
			if relay = e.tryWS(ctx); relay != nil {
				transport, wsSince, relayDone = proto.TransportWebSocket, time.Now(), relay.Done()
				continue
			}
			sleep(ctx, 5*time.Second)
			continue
		}
		select {
		case <-ctx.Done():
			return
		case <-relayDone:
			e.s.log.Warn("WebSocket relay closed", "edge", e.label(), "err", relay.err)
			relay, relayDone, transport = nil, nil, ""
			e.lost()
			continue
		case <-tick.C:
		}
		if e.stale() {
			e.s.log.Warn("handshake lost", "edge", e.label(), "transport", transport)
			if relay != nil {
				relay.Close()
				relay, relayDone = nil, nil
			}
			transport = ""
			e.lost()
			continue
		}
		if transport == proto.TransportWebSocket && time.Since(wsSince) > cmp.Or(e.s.r.UDPRetry, DefaultUDPRetry) {
			e.s.log.Info("retrying UDP", "edge", e.label())
			if e.tryUDP(ctx) {
				relay.Close()
				relay, relayDone, transport = nil, nil, proto.TransportUDP
				continue
			}
			wsSince = time.Now()
			if !e.useRelay(ctx, relay) {
				relay.Close()
				relay, relayDone, transport = nil, nil, ""
			}
		}
	}
}

// lost handles a lost tunnel: abort a poll running over it and re-check
// the edge list.
func (e *edge) lost() {
	e.mu.Lock()
	cancel := e.pollCancel
	e.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	e.setTransport("", "", 0)
	e.s.triggerRefresh()
}

func (e *edge) setTransport(t, endpoint string, mtu int) {
	e.mu.Lock()
	if t != e.transport {
		e.rtt.reset() // another path: old samples no longer apply
	}
	e.transport, e.endpoint, e.mtu = t, endpoint, mtu
	e.mu.Unlock()
	e.s.applyMTU()
	e.s.writeStatus()
	if t != "" {
		select {
		case e.kick <- struct{}{}:
		default:
		}
	}
}

// wantMTU is the MTU this edge's transport needs (0 = not connected).
func (e *edge) wantMTU() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.transport == "" {
		return 0
	}
	return e.mtu
}

func (e *edge) status(p peerStats) EdgeStatus {
	e.mu.Lock()
	defer e.mu.Unlock()
	return EdgeStatus{
		Node: e.cfg.Node, URL: e.cfg.URL, EdgePublicKey: e.key.String(),
		Address: e.cfg.Config.Address, EdgeAddress: e.cfg.Config.EdgeAddress, Learned: e.cfg.Learned,
		Transport: e.transport, Endpoint: e.endpoint,
		LastHandshake: p.LastHandshake, RxBytes: p.RxBytes, TxBytes: p.TxBytes,
		LastPoll: e.lastPoll, PollError: e.pollErr, RTTMillis: millis(e.rtt.value()),
	}
}

// do sends a request to the edge: over the tunnel to the edge's control
// port when the tunnel is up (authenticated by WireGuard, so it needs no
// credential and works on every node of the site), else to the public
// HTTPS URL with the credential or a IngressdKey header.
func (e *edge) do(ctx context.Context, method, path string, q url.Values, body []byte) (*http.Response, error) {
	c := e.config()
	suffix := path
	if len(q) > 0 {
		suffix += "?" + q.Encode()
	}
	newReq := func(base string) (*http.Request, error) {
		var r io.Reader
		if body != nil {
			r = bytes.NewReader(body)
		}
		req, err := http.NewRequestWithContext(ctx, method, base+suffix, r)
		if err != nil {
			return nil, err
		}
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		return req, nil
	}
	e.mu.Lock()
	tunnelOK := time.Since(e.tunnelFail) > tunnelControlRetry
	e.mu.Unlock()
	if c.Config.EdgeAddress != "" && tunnelOK && e.tunnelUp() {
		req, err := newReq("http://" + net.JoinHostPort(c.Config.EdgeAddress, strconv.Itoa(proto.TunnelControlPort)))
		if err != nil {
			return nil, err
		}
		resp, err := e.tunnelHTTP.Do(req)
		if err == nil && resp.StatusCode != http.StatusForbidden && resp.StatusCode != http.StatusNotFound {
			return resp, nil
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if err == nil {
			_ = resp.Body.Close()
			err = errors.New(resp.Status)
		}
		e.s.log.Debug("control over the tunnel failed; using the public URL", "edge", e.label(), "err", err)
		e.mu.Lock()
		e.tunnelFail = time.Now()
		e.mu.Unlock()
	}
	if e.control == nil {
		return nil, errNoPath
	}
	req, err := newReq(c.URL)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", e.authHeader(method, req.URL.Path, body))
	return e.control.Do(req)
}

// controlLoop long-polls the edge for config changes.
func (e *edge) controlLoop(ctx context.Context) {
	backoff := time.Second
	for ctx.Err() == nil {
		pctx, cancel := context.WithCancel(ctx)
		e.mu.Lock()
		e.pollCancel = cancel
		e.mu.Unlock()
		err := e.pollOnce(pctx)
		cancel()
		if ctx.Err() != nil {
			return
		}
		e.mu.Lock()
		e.pollCancel = nil
		if !errors.Is(err, errNoPath) {
			e.lastPoll = time.Now().UTC()
		}
		e.pollErr = ""
		if err != nil {
			e.pollErr = err.Error()
		}
		e.mu.Unlock()
		switch {
		case errors.Is(err, errNoPath), errors.Is(err, context.Canceled):
			sleep(ctx, 2*time.Second)
		case err != nil:
			lvl := slog.LevelWarn
			if e.config().Learned && !e.tunnelUp() {
				// Expected until the tunnel is up: a learned edge's public
				// URL may not be verifiable (internal CA) and is only a
				// fallback.
				lvl = slog.LevelDebug
			}
			e.s.log.Log(ctx, lvl, "control channel", "edge", e.label(), "err", err)
			sleep(ctx, backoff)
			backoff = min(backoff*2, time.Minute)
		default:
			backoff = time.Second
		}
	}
}

// pollOnce performs one long poll of the edge.
func (e *edge) pollOnce(ctx context.Context) error {
	c := e.config()
	q := url.Values{"rev": {c.Config.Revision}, "wait": {proto.PollWait.String()}}
	q.Set(proto.UpdateParam, e.s.upd.seenID())
	if e.s.discover {
		e.mu.Lock()
		q.Set(proto.DiscoverParam, e.discoverID)
		e.mu.Unlock()
	}
	resp, err := e.do(ctx, http.MethodGet, proto.PollPath, q, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusNoContent:
		e.s.markSeen(e)
		return nil
	case http.StatusOK:
	case http.StatusUnauthorized:
		e.authRejected(resp.Request.Header.Get("Authorization"))
		if c.Credential != "" {
			return errors.New("the edge rejected this connector's credential (re-enroll with a new token)")
		}
		return errors.New("the edge does not accept this connector's key yet (it learns it from the panel)")
	case http.StatusGone:
		e.s.log.Warn("edge no longer serves this site", "edge", e.label())
		e.s.markGone(e)
		return errors.New("the edge no longer serves this site")
	default:
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("poll: %s: %s", resp.Status, strings.TrimSpace(string(msg)))
	}
	var tc proto.TunnelConfig
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxConfigBody)).Decode(&tc); err != nil {
		return fmt.Errorf("poll: %w", err)
	}
	if tc.EdgePublicKey != "" && tc.EdgePublicKey != e.key.String() {
		e.s.log.Warn("edge changed its key", "edge", e.label())
	}
	if n := tc.Update; n != nil {
		tc.Update = nil
		if e.s.upd.claim(n.ID) {
			go e.s.onNotice(e, *n)
		}
		if tc.Revision == c.Config.Revision && tc.DiscoverID == "" {
			e.s.markSeen(e)
			return nil
		}
	}
	if id := tc.DiscoverID; id != "" {
		tc.DiscoverID = ""
		if e.s.discover {
			// A request arriving during a scan is answered by that scan.
			e.mu.Lock()
			e.discoverID = id
			e.mu.Unlock()
			if e.discovering.CompareAndSwap(false, true) {
				go e.runDiscovery(e.runCtx)
			}
		}
		if tc.Revision == c.Config.Revision {
			e.s.markSeen(e)
			return nil
		}
	}
	return e.s.applyEdgeConfig(e, tc)
}

// reportLoop sends health reports every 30 s and on transport changes.
func (e *edge) reportLoop(ctx context.Context) {
	t := time.NewTicker(reportInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-e.kick:
		}
		p, _ := e.peerStats()
		es := e.status(p)
		h := proto.Health{
			Time: time.Now().UTC(), Version: version.String(), Hostname: e.s.hostname, Mode: e.s.mode,
			Transport: es.Transport, MTU: e.s.link.MTU(), LastHandshake: p.LastHandshake,
			RxBytes: p.RxBytes, TxBytes: p.TxBytes, Discovery: e.s.discover,
			OS: runtime.GOOS, Arch: runtime.GOARCH, Install: e.s.upd.install, Update: e.s.upd.snapshot(),
		}
		h.Reachability = testReachability(ctx, e.s.stateCopy().reachTargets())
		h.Edges = e.s.edgeReports()
		if sd := e.s.r.sd; sd != nil {
			h.SmartDNS = sd.report()
			h.SmartDNSUsage = sd.takeUsage()
		}
		err := e.postJSON(ctx, proto.ReportPath, h)
		if err != nil && e.s.r.sd != nil {
			e.s.r.sd.returnUsage(h.SmartDNSUsage)
		}
		if err != nil && ctx.Err() == nil && !errors.Is(err, errNoPath) {
			e.s.log.Warn("health report", "edge", e.label(), "err", err)
		}
	}
}

// postJSON posts v to the edge.
func (e *edge) postJSON(ctx context.Context, path string, v any) error {
	body, err := json.Marshal(v)
	if err != nil {
		return err
	}
	resp, err := e.do(ctx, http.MethodPost, path, nil, body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("%s: %s: %s", path, resp.Status, strings.TrimSpace(string(msg)))
	}
	return nil
}

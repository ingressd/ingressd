// SPDX-License-Identifier: Apache-2.0

package smartdns

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/ingressd/ingressd/pkg/envcompat"
)

// Exit health beyond "is the tunnel up": where the egress really comes out
// (IP and country, from a trace endpoint reached through the egress itself)
// and, for VPN exits, keeping the provider endpoint current when its host
// name moves to another address.

// TraceURLEnv overrides the trace endpoint (tests, or a self-hosted
// equivalent). It must answer plain "key=value" lines including ip= and
// loc= (Cloudflare's /cdn-cgi/trace format).
const TraceURLEnv = "INGRESSD_SMARTDNS_TRACE_URL"

const defaultTraceURL = "https://1.1.1.1/cdn-cgi/trace"

var (
	traceEvery      = 10 * time.Minute // after a successful trace
	traceRetry      = time.Minute      // after a failed one
	traceTimeout    = 8 * time.Second
	endpointRefresh = 30 * time.Second // re-resolve VPN endpoint host names
)

// probeState is the latest trace for one exit; it survives reconfigures as
// long as the exit's egress does not change.
type probeState struct {
	sig string // egress signature: interface, endpoint, mark

	mu      sync.Mutex
	ip      string
	country string
	err     string
	at      time.Time
	running bool
	wasUp   bool
}

func (p *probeState) snapshot() (ip, country, err string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.ip, p.country, p.err
}

func (e *egress) sig() string {
	return fmt.Sprintf("%s|%d|%s|%s", e.ifname, e.mark, e.endpoint, e.peerKey)
}

func (m *Manager) probe(e *egress) *probeState {
	m.probeMu.Lock()
	defer m.probeMu.Unlock()
	p, ok := m.probes[e.exit]
	if !ok || p.sig != e.sig() {
		p = &probeState{sig: e.sig()}
		m.probes[e.exit] = p
	}
	return p
}

// watchEgress runs from Run's ticker: starts due traces and refreshes VPN
// endpoints.
func (m *Manager) watchEgress(now time.Time) {
	st := m.state()
	m.probeMu.Lock()
	for name := range m.probes {
		if _, ok := st.egress[name]; !ok {
			delete(m.probes, name)
		}
	}
	m.probeMu.Unlock()
	for _, name := range sortedKeys(st.egress) {
		e := st.egress[name]
		p := m.probe(e)
		up, _ := e.up()
		p.mu.Lock()
		due := false
		switch {
		case !up:
			p.wasUp = false
		case p.running:
		case !p.wasUp, p.at.IsZero():
			due = true
		case p.err != "":
			due = now.Sub(p.at) >= traceRetry
		default:
			due = now.Sub(p.at) >= traceEvery
		}
		if up {
			p.wasUp = true
		}
		if due {
			p.running = true
		}
		p.mu.Unlock()
		if due {
			go m.runTrace(e, p)
		}
		if e.ifname != "" && now.Sub(e.lastRefresh()) >= endpointRefresh {
			e.setRefresh(now)
			go m.refreshEndpoint(e)
		}
	}
}

func (m *Manager) runTrace(e *egress, p *probeState) {
	ctx, cancel := context.WithTimeout(m.ctx(), traceTimeout)
	defer cancel()
	ip, country, err := trace(ctx, e, m.traceURL)
	p.mu.Lock()
	defer p.mu.Unlock()
	p.running, p.at = false, time.Now()
	if err != nil {
		p.err = err.Error()
		m.log.Debug("egress trace failed", "exit", e.exit, "err", err)
		return
	}
	if ip != p.ip || country != p.country {
		m.log.Info("exit egress", "exit", e.exit, "ip", ip, "country", country)
	}
	p.ip, p.country, p.err = ip, country, ""
}

// trace fetches the trace URL through the egress and returns the ip= and
// loc= values.
func trace(ctx context.Context, e *egress, url string) (ip, country string, err error) {
	tr := &http.Transport{DialContext: e.dialer().DialContext, Proxy: nil, DisableKeepAlives: true, ForceAttemptHTTP2: false}
	defer tr.CloseIdleConnections()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", "", err
	}
	req.Header.Set("User-Agent", "ingressd-smartdns")
	resp, err := (&http.Client{Transport: tr}).Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("trace: HTTP %d", resp.StatusCode)
	}
	return parseTrace(io.LimitReader(resp.Body, 8<<10))
}

func parseTrace(r io.Reader) (ip, country string, err error) {
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		k, v, ok := strings.Cut(strings.TrimSpace(sc.Text()), "=")
		if !ok {
			continue
		}
		switch k {
		case "ip":
			if a, err := netip.ParseAddr(v); err == nil {
				ip = a.String()
			}
		case "loc":
			if len(v) == 2 && v != "XX" && v != "T1" {
				country = strings.ToUpper(v)
			}
		}
	}
	if ip == "" {
		return "", "", fmt.Errorf("trace: no ip in the answer")
	}
	return ip, country, nil
}

// refreshEndpoint re-resolves a VPN exit's endpoint host name and points
// the peer at the new address when the current one is no longer listed
// (providers move servers; an unresolvable name at apply time leaves the
// peer without an endpoint until this succeeds).
func (m *Manager) refreshEndpoint(e *egress) {
	host, port, err := net.SplitHostPort(e.endpoint)
	if err != nil || e.peerKey == "" {
		return
	}
	pk, err := wgtypes.ParseKey(e.peerKey)
	if err != nil {
		return
	}
	pn, err := strconv.Atoi(port)
	if err != nil {
		return
	}
	var addrs []netip.Addr
	if a, err := netip.ParseAddr(host); err == nil {
		addrs = []netip.Addr{a}
	} else {
		ctx, cancel := context.WithTimeout(m.ctx(), 5*time.Second)
		addrs, err = m.resolveHost(ctx, host)
		cancel()
		if err != nil || len(addrs) == 0 {
			m.log.Warn("VPN endpoint does not resolve", "exit", e.exit, "endpoint", e.endpoint, "err", err)
			return
		}
	}
	// IPv4 first, like the apply step.
	slices.SortStableFunc(addrs, func(a, b netip.Addr) int {
		switch {
		case a.Is4() == b.Is4():
			return 0
		case a.Is4():
			return -1
		}
		return 1
	})
	dev, err := e.device(e.ifname)
	if err != nil {
		return
	}
	for _, p := range dev.Peers {
		if p.PublicKey != pk {
			continue
		}
		if p.Endpoint != nil {
			if cur, ok := netip.AddrFromSlice(p.Endpoint.IP); ok && slices.Contains(addrs, cur.Unmap()) && p.Endpoint.Port == pn {
				return
			}
		}
		next := &net.UDPAddr{IP: addrs[0].AsSlice(), Port: pn}
		err := m.configure(e.ifname, wgtypes.Config{Peers: []wgtypes.PeerConfig{{PublicKey: pk, UpdateOnly: true, Endpoint: next}}})
		if err != nil {
			m.log.Warn("cannot update VPN endpoint", "exit", e.exit, "err", err)
			return
		}
		m.log.Info("VPN endpoint updated", "exit", e.exit, "endpoint", e.endpoint, "from", p.Endpoint, "to", next)
		return
	}
}

// endpointNow is the address the tunnel's peer currently uses.
func (e *egress) endpointNow() string {
	if e.ifname == "" || e.device == nil {
		return ""
	}
	dev, err := e.device(e.ifname)
	if err != nil {
		return ""
	}
	for _, p := range dev.Peers {
		if p.Endpoint != nil && (e.peerKey == "" || p.PublicKey.String() == e.peerKey) {
			return p.Endpoint.String()
		}
	}
	return ""
}

func (e *egress) lastRefresh() time.Time {
	e.refreshMu.Lock()
	defer e.refreshMu.Unlock()
	return e.refreshed
}

func (e *egress) setRefresh(t time.Time) {
	e.refreshMu.Lock()
	defer e.refreshMu.Unlock()
	e.refreshed = t
}

func traceURLFromEnv() string {
	if u := strings.TrimSpace(envcompat.Get(TraceURLEnv)); u != "" {
		return u
	}
	return defaultTraceURL
}

// exitHealth describes what the trace found, for the exit's status.
func exitHealth(e *egress, ip, country, traceErr string, up bool) (egressIP, msg string) {
	egressIP = e.public
	if ip != "" {
		egressIP = ip
	}
	switch {
	case !up:
	case country != "" && e.country != "" && country != e.country:
		msg = fmt.Sprintf("egress %s geolocates to %s, expected %s", egressIP, country, e.country)
	case traceErr != "" && ip == "":
		msg = "egress check failed: " + traceErr
	}
	return egressIP, msg
}

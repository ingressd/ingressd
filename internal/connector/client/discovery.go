// SPDX-License-Identifier: Apache-2.0

package client

import (
	"cmp"
	"context"
	"crypto/tls"
	"errors"
	"html"
	"io"
	"net"
	"net/http"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ingressd/ingressd/internal/connector/proto"
)

// LAN service discovery: on request from the edge, the connector scans the
// private IPv4 subnets its host is directly connected to for web services
// and reports their address, scheme, <title> and Server header, so the panel
// can offer them as apps. The scan is deliberately gentle: at most a /22 per
// interface, a global probe rate limit, short timeouts and a bounded number
// of concurrent probes.

// DefaultDiscoveryPorts are the TCP ports probed on every host.
var DefaultDiscoveryPorts = []int{80, 443, 3000, 5000, 5001, 8000, 8006, 8080, 8081, 8123, 8443, 8888, 9000, 9090, 32400}

// tlsFirstPorts are tried with HTTPS before plain HTTP.
var tlsFirstPorts = map[int]bool{443: true, 5001: true, 8006: true, 8443: true, 9443: true}

// Discovery limits.
const (
	// MaxDiscoveryPrefix caps each interface's scanned subnet (a /16 LAN is
	// scanned as the /22 around the host's own address).
	MaxDiscoveryPrefix = 22
	defaultProbeRate   = 400 // TCP connects per second, all interfaces
	defaultConcurrency = 128
	defaultDialTimeout = 400 * time.Millisecond
	defaultHTTPTimeout = 3 * time.Second
	defaultScanTimeout = 3 * time.Minute
	maxTitleLen        = 200
	maxServerLen       = 120
	maxBodyRead        = 64 << 10
)

// Iface is one network interface as seen by the scanner.
type Iface struct {
	Name     string
	Up       bool
	Loopback bool
	Prefixes []netip.Prefix // interface addresses with their prefix length
}

// Scanner finds web services on directly connected private subnets.
type Scanner struct {
	// Interfaces lists the host's interfaces (default: net.Interfaces).
	Interfaces func() ([]Iface, error)
	// Ports to probe (default DefaultDiscoveryPorts).
	Ports []int
	// ExcludeIfaces are interface names never scanned (the tunnel device).
	ExcludeIfaces []string
	// ExcludePrefixes are never scanned (the tunnel transit network).
	ExcludePrefixes []netip.Prefix
	// Within returns the parts of a subnet that may be scanned (default:
	// all of it).
	Within func(netip.Prefix) []netip.Prefix
	// Eligible decides whether an interface address may be scanned
	// (default: RFC 1918 private IPv4). Tests allow loopback.
	Eligible func(netip.Addr) bool
	// Rate is the maximum number of TCP connects per second.
	Rate        int
	Concurrency int
	DialTimeout time.Duration
	HTTPTimeout time.Duration
	// Timeout bounds the whole scan.
	Timeout time.Duration
	// Dial is overridable in tests.
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
}

// SystemInterfaces returns the host's interfaces and IPv4 prefixes.
func SystemInterfaces() ([]Iface, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	out := make([]Iface, 0, len(ifs))
	for _, ifc := range ifs {
		i := Iface{Name: ifc.Name, Up: ifc.Flags&net.FlagUp != 0, Loopback: ifc.Flags&net.FlagLoopback != 0}
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip, ok := netip.AddrFromSlice(ipn.IP)
			if !ok {
				continue
			}
			ones, _ := ipn.Mask.Size()
			ip = ip.Unmap()
			if ip.Is4() && ones > 0 {
				i.Prefixes = append(i.Prefixes, netip.PrefixFrom(ip, ones))
			}
		}
		out = append(out, i)
	}
	return out, nil
}

var privateV4 = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
}

// IsPrivateV4 reports whether a is an RFC 1918 address.
func IsPrivateV4(a netip.Addr) bool {
	a = a.Unmap()
	if !a.Is4() {
		return false
	}
	for _, p := range privateV4 {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// scanTarget is one subnet to scan and the host's own address in it.
type scanTarget struct {
	prefix netip.Prefix
	self   netip.Addr
}

// Subnets returns the subnets the scanner would scan, capped at /22 each.
func (s *Scanner) Subnets() ([]netip.Prefix, error) {
	ts, err := s.targets()
	if err != nil {
		return nil, err
	}
	out := make([]netip.Prefix, len(ts))
	for i, t := range ts {
		out[i] = t.prefix
	}
	return out, nil
}

func (s *Scanner) targets() ([]scanTarget, error) {
	list := s.Interfaces
	if list == nil {
		list = SystemInterfaces
	}
	ifs, err := list()
	if err != nil {
		return nil, err
	}
	eligible := s.Eligible
	if eligible == nil {
		eligible = IsPrivateV4
	}
	var out []scanTarget
	seen := map[netip.Prefix]bool{}
	for _, ifc := range ifs {
		if !ifc.Up || ifc.Loopback && s.Eligible == nil || slices.Contains(s.ExcludeIfaces, ifc.Name) {
			continue
		}
	prefixes:
		for _, p := range ifc.Prefixes {
			a := p.Addr().Unmap()
			if !a.Is4() || !eligible(a) || p.Bits() >= 32 {
				continue
			}
			bits := max(p.Bits(), MaxDiscoveryPrefix)
			np := netip.PrefixFrom(a, bits).Masked()
			for _, x := range s.ExcludePrefixes {
				if x.Overlaps(np) {
					continue prefixes
				}
			}
			parts := []netip.Prefix{np}
			if s.Within != nil {
				parts = s.Within(np)
			}
			for _, part := range parts {
				if !seen[part] {
					seen[part] = true
					out = append(out, scanTarget{prefix: part, self: a})
				}
			}
		}
	}
	return out, nil
}

// hosts lists the usable host addresses of p, excluding self (and the
// network and broadcast addresses for prefixes up to /30).
func hosts(p netip.Prefix, self netip.Addr) []netip.Addr {
	var out []netip.Addr
	p = p.Masked()
	first := p.Addr()
	n := 1 << (32 - p.Bits())
	a := first
	for i := 0; i < n; i++ {
		edge := p.Bits() <= 30 && (i == 0 || i == n-1)
		if !edge && a != self {
			out = append(out, a)
		}
		a = a.Next()
	}
	return out
}

// Scan probes every host and port and returns the web services found,
// sorted by address and port. A cancelled or timed-out scan returns what
// it found so far together with the context error.
func (s *Scanner) Scan(ctx context.Context) ([]netip.Prefix, []proto.DiscoveredService, error) {
	ts, err := s.targets()
	if err != nil {
		return nil, nil, err
	}
	subnets := make([]netip.Prefix, len(ts))
	for i, t := range ts {
		subnets[i] = t.prefix
	}
	if len(ts) == 0 {
		return nil, nil, errors.New("no directly connected private IPv4 subnets to scan")
	}
	ctx, cancel := context.WithTimeout(ctx, cmp.Or(s.Timeout, defaultScanTimeout))
	defer cancel()

	ports := s.Ports
	if len(ports) == 0 {
		ports = DefaultDiscoveryPorts
	}
	rate := cmp.Or(s.Rate, defaultProbeRate)
	tick := time.NewTicker(time.Second / time.Duration(rate))
	defer tick.Stop()
	sem := make(chan struct{}, cmp.Or(s.Concurrency, defaultConcurrency))

	var (
		mu    sync.Mutex
		found []proto.DiscoveredService
		wg    sync.WaitGroup
	)
loop:
	for _, t := range ts {
		for _, h := range hosts(t.prefix, t.self) {
			for _, port := range ports {
				select {
				case <-ctx.Done():
					break loop
				case <-tick.C:
				}
				select {
				case <-ctx.Done():
					break loop
				case sem <- struct{}{}:
				}
				wg.Add(1)
				go func() {
					defer wg.Done()
					defer func() { <-sem }()
					if svc, ok := s.probe(ctx, h, port); ok {
						mu.Lock()
						found = append(found, svc)
						mu.Unlock()
					}
				}()
			}
		}
	}
	wg.Wait()
	slices.SortFunc(found, func(a, b proto.DiscoveredService) int {
		aa, _ := netip.ParseAddr(a.Address)
		ba, _ := netip.ParseAddr(b.Address)
		return cmp.Or(aa.Compare(ba), cmp.Compare(a.Port, b.Port))
	})
	return subnets, found, ctx.Err()
}

func (s *Scanner) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	if s.Dial != nil {
		return s.Dial(ctx, network, addr)
	}
	d := net.Dialer{Timeout: cmp.Or(s.DialTimeout, defaultDialTimeout)}
	return d.DialContext(ctx, network, addr)
}

// probe checks one host:port: a TCP connect, then an HTTP(S) GET /.
func (s *Scanner) probe(ctx context.Context, h netip.Addr, port int) (proto.DiscoveredService, bool) {
	addr := net.JoinHostPort(h.String(), strconv.Itoa(port))
	dctx, cancel := context.WithTimeout(ctx, cmp.Or(s.DialTimeout, defaultDialTimeout))
	c, err := s.dial(dctx, "tcp", addr)
	cancel()
	if err != nil {
		return proto.DiscoveredService{}, false
	}
	_ = c.Close()
	schemes := []string{"http", "https"}
	if tlsFirstPorts[port] {
		schemes = []string{"https", "http"}
	}
	for _, scheme := range schemes {
		svc, ok := s.fetch(ctx, scheme, h, port)
		if ok {
			return svc, true
		}
	}
	return proto.DiscoveredService{}, false
}

var titleRE = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

// fetch GETs / with the given scheme and extracts the title and Server
// header. Redirects are followed (up to 3) only on the same host.
func (s *Scanner) fetch(ctx context.Context, scheme string, h netip.Addr, port int) (proto.DiscoveredService, bool) {
	hostport := net.JoinHostPort(h.String(), strconv.Itoa(port))
	tr := &http.Transport{
		DialContext:           s.dial,
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // fingerprinting LAN services that use self-signed certs; nothing is sent
		TLSHandshakeTimeout:   cmp.Or(s.HTTPTimeout, defaultHTTPTimeout),
		ResponseHeaderTimeout: cmp.Or(s.HTTPTimeout, defaultHTTPTimeout),
		DisableKeepAlives:     true,
	}
	defer tr.CloseIdleConnections()
	cl := &http.Client{
		Transport: tr,
		Timeout:   cmp.Or(s.HTTPTimeout, defaultHTTPTimeout) + time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 || req.URL.Host != hostport {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, scheme+"://"+hostport+"/", nil)
	if err != nil {
		return proto.DiscoveredService{}, false
	}
	req.Header.Set("User-Agent", "ingressd-connector-discovery")
	req.Header.Set("Accept", "text/html,*/*;q=0.5")
	resp, err := cl.Do(req)
	if err != nil {
		return proto.DiscoveredService{}, false
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBodyRead))
	// nginx and others answer plain HTTP on a TLS port with a 400 page;
	// let the caller try HTTPS.
	if scheme == "http" && resp.StatusCode == http.StatusBadRequest && strings.Contains(strings.ToLower(string(body)), "https") {
		return proto.DiscoveredService{}, false
	}
	svc := proto.DiscoveredService{
		Address: h.String(),
		Port:    port,
		Scheme:  scheme,
		Server:  clip(resp.Header.Get("Server"), maxServerLen),
	}
	if m := titleRE.FindSubmatch(body); m != nil {
		svc.Title = clip(strings.Join(strings.Fields(html.UnescapeString(string(m[1]))), " "), maxTitleLen)
	}
	return svc, true
}

func clip(s string, n int) string {
	s = strings.ToValidUTF8(strings.TrimSpace(s), "")
	if len(s) <= n {
		return s
	}
	r := []rune(s)
	if len(r) > n {
		r = r[:n]
	}
	return string(r)
}

// ExcludeTunnel keeps an enrolled connector's tunnel out of the scan: the
// TUN interface (in TUN mode) and every edge's transit network.
func (sc *Scanner) ExcludeTunnel(st *State, mode string) {
	if mode == ModeTUN {
		sc.ExcludeIfaces = append(sc.ExcludeIfaces, cmp.Or(st.Interface, DefaultInterface))
	}
	for _, p := range st.Addresses() {
		sc.ExcludePrefixes = append(sc.ExcludePrefixes, p.Masked())
	}
}

// scanner is the scan an edge may ask for: off the tunnel, and inside the
// local allowlist.
func (e *edge) scanner() *Scanner {
	st := e.s.stateCopy()
	sc := &Scanner{Within: func(p netip.Prefix) []netip.Prefix { return outermost(st.reach.narrow(p)) }}
	sc.ExcludeTunnel(st, e.s.mode)
	return sc
}

// runDiscovery scans and posts the report to the edge that asked,
// answering its latest request.
func (e *edge) runDiscovery(ctx context.Context) {
	defer e.discovering.Store(false)
	log := e.s.log
	rep := proto.DiscoveryReport{Started: time.Now().UTC()}
	log.Info("LAN discovery requested", "edge", e.label())
	subnets, svcs, err := e.scanner().Scan(ctx)
	if ctx.Err() != nil {
		return // link restarting or shutting down; the edge asks again
	}
	rep.Finished = time.Now().UTC()
	e.mu.Lock()
	rep.ID = e.discoverID
	e.mu.Unlock()
	for _, p := range subnets {
		rep.Subnets = append(rep.Subnets, p.String())
	}
	rep.Services = svcs
	if rep.Services == nil {
		rep.Services = []proto.DiscoveredService{}
	}
	if err != nil {
		rep.Error = err.Error()
	}
	log.Info("LAN discovery finished", "id", rep.ID, "subnets", rep.Subnets, "services", len(svcs), "took", rep.Finished.Sub(rep.Started).Round(time.Millisecond))
	backoff := time.Second
	for attempt := 0; attempt < 5 && ctx.Err() == nil; attempt++ {
		if err = e.postJSON(ctx, proto.DiscoveryPath, rep); err == nil {
			return
		}
		log.Warn("discovery report", "edge", e.label(), "err", err)
		sleep(ctx, backoff)
		backoff *= 2
	}
}

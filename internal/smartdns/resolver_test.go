// SPDX-License-Identifier: Apache-2.0

package smartdns

import (
	"bufio"
	"cmp"
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/ingressd/ingressd/pkg/config"
)

// fakeExits stands in for node exits.
type fakeExits struct {
	mu       sync.Mutex
	up       bool
	addrs    []netip.Addr
	rcode    int
	resErr   error  // transport failure
	exitErr  string // the exit's resolver failed
	exitDown bool
	resolves int
	connect  func(req ConnectRequest) (net.Conn, error)

	// Per node and per exit behaviour for failover tests (nil: unused).
	exitOf      map[string]string       // node -> the exit it hosts
	downNodes   map[string]bool         // tunnel to the node is down
	brokenNodes map[string]bool         // transport fails while the tunnel still says up
	downExits   map[string]bool         // the exit node reports these exits down
	exitAddrs   map[string][]netip.Addr // what each exit resolves names to
	resolved    []string                // exit of every Resolve call
	health      func(node string) (exitState, error)
}

func (f *fakeExits) Resolve(_ context.Context, node, name string) (resolveResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.resolves++
	exit := cmp.Or(f.exitOf[node], node)
	f.resolved = append(f.resolved, exit)
	if f.resErr != nil || f.downNodes[node] || f.brokenNodes[node] {
		return resolveResponse{}, cmp.Or(f.resErr, errors.New("no route to host"))
	}
	if f.exitDown || f.downExits[exit] {
		return resolveResponse{Error: "vpn down"}, nil
	}
	if a, ok := f.exitAddrs[exit]; ok {
		return resolveResponse{ExitUp: true, Addrs: a, TTL: 60}, nil
	}
	if f.exitErr != "" {
		return resolveResponse{ExitUp: true, Error: f.exitErr}, nil
	}
	return resolveResponse{ExitUp: true, Rcode: f.rcode, Addrs: f.addrs, TTL: 60}, nil
}

func (f *fakeExits) Connect(_ context.Context, _ string, req ConnectRequest) (net.Conn, error) {
	return f.connect(req)
}

func (f *fakeExits) Health(_ context.Context, node string) (exitState, error) {
	if f.health == nil {
		return exitState{Up: true}, nil
	}
	return f.health(node)
}

func (f *fakeExits) Up(node string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.up && !f.downNodes[node]
}

func (f *fakeExits) set(fn func()) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fn()
}

// fakeUpstream is a DNS server on 127.0.0.1 answering every A query with
// answerIP.
func fakeUpstream(t *testing.T, answerIP string) string {
	t.Helper()
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		q := r.Question[0]
		switch {
		case strings.HasPrefix(q.Name, "nx."):
			m.Rcode = dns.RcodeNameError
		case q.Qtype == dns.TypeA:
			m.Answer = append(m.Answer, &dns.A{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 120}, A: net.ParseIP(answerIP)})
		case q.Qtype == dns.TypeAAAA:
			m.Answer = append(m.Answer, &dns.AAAA{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 120}, AAAA: net.ParseIP("2001:db8::1")})
		}
		w.WriteMsg(m)
	})}
	go srv.ActivateAndServe()
	t.Cleanup(func() { srv.Shutdown() })
	return pc.LocalAddr().String()
}

// testPlan routes streamtv through a node exit and local through a local
// exit on the host's own route.
func testPlan(upstream string) Plan {
	return Plan{
		Site:     "home",
		Upstream: []string{upstream},
		Exits: map[string]PlanExit{
			"nl":   {Node: "nod_nl", Country: "NL"},
			"home": {Country: "GB", Egress: &EgressOptions{DNS: []string{upstream}}},
		},
		Services: map[string]config.SmartDNSSiteService{
			"streamtv": {Domains: []string{"stream.example", "streamtv.example"}, Exits: []string{"nl"}},
			"local":    {Domains: []string{"local.test"}, Exits: []string{"home"}},
		},
	}
}

func newTestManager(t *testing.T, upstream string) (*Manager, *fakeExits) {
	t.Helper()
	m := New(Options{})
	fx := &fakeExits{up: true, addrs: addrs("192.0.2.20", "192.0.2.21")}
	m.remote = fx
	m.Reconfigure(testPlan(upstream))
	t.Cleanup(m.listeners.closeAll)
	return m, fx
}

var (
	transit = &net.UDPAddr{IP: net.ParseIP("10.100.1.1"), Port: 53}
	tv      = &net.UDPAddr{IP: net.ParseIP("192.168.0.17"), Port: 40000}
)

func query(m *Manager, name string, qtype uint16) *dns.Msg {
	q := new(dns.Msg)
	q.SetQuestion(dns.Fqdn(name), qtype)
	return m.answer(transit, tv, q)
}

func aRecords(r *dns.Msg) []string {
	var out []string
	for _, rr := range r.Answer {
		if a, ok := rr.(*dns.A); ok {
			out = append(out, a.A.String())
		}
	}
	return out
}

func TestServiceAnsweredWithTransitIP(t *testing.T) {
	m, fx := newTestManager(t, fakeUpstream(t, "203.0.113.5"))
	r := query(m, "TV.stream.example", dns.TypeA)
	if r.Rcode != dns.RcodeSuccess || strings.Join(aRecords(r), ",") != "10.100.1.1" {
		t.Fatalf("answer %v", r)
	}
	if r.Answer[0].Header().Ttl != serviceTTL {
		t.Errorf("ttl %d", r.Answer[0].Header().Ttl)
	}
	// Cached: the exit is not asked again.
	query(m, "tv.stream.example", dns.TypeA)
	if fx.resolves != 1 {
		t.Errorf("exit asked %d times, want 1", fx.resolves)
	}
	rec := m.RecentLookups(10)
	if len(rec) != 2 || !rec[0].Routed || rec[0].Service != "streamtv" || rec[0].Site != "home" || rec[0].Type != "A" {
		t.Errorf("recent = %+v", rec)
	}
}

func TestAAAAAndHTTPSSuppressed(t *testing.T) {
	m, fx := newTestManager(t, fakeUpstream(t, "203.0.113.5"))
	for _, qt := range []uint16{dns.TypeAAAA, dns.TypeHTTPS, dns.TypeSVCB} {
		r := query(m, "streamtv.example", qt)
		if r.Rcode != dns.RcodeSuccess || len(r.Answer) != 0 {
			t.Errorf("%s: %v", dns.TypeToString[qt], r)
		}
	}
	if fx.resolves != 0 {
		t.Error("suppressed queries reached the exit")
	}
	// Non-service AAAA passes through.
	if r := query(m, "example.org", dns.TypeAAAA); len(r.Answer) != 1 {
		t.Errorf("non-service AAAA: %v", r)
	}
}

func TestNonServiceGoesUpstream(t *testing.T) {
	m, fx := newTestManager(t, fakeUpstream(t, "203.0.113.5"))
	r := query(m, "www.bbc.co.uk", dns.TypeA)
	if strings.Join(aRecords(r), ",") != "203.0.113.5" {
		t.Fatalf("answer %v", r)
	}
	if r := query(m, "nx.example.org", dns.TypeA); r.Rcode != dns.RcodeNameError {
		t.Errorf("NXDOMAIN not passed through: %v", r)
	}
	if fx.resolves != 0 {
		t.Error("non-service name sent to the exit")
	}
	if rec := m.RecentLookups(1); rec[0].Routed {
		t.Errorf("recent %+v", rec)
	}
}

func TestFailClosedWhenExitDown(t *testing.T) {
	m, fx := newTestManager(t, fakeUpstream(t, "203.0.113.5"))
	query(m, "tv.stream.example", dns.TypeA) // cache it
	fx.up = false
	for _, name := range []string{"tv.stream.example", "api.stream.example"} {
		if r := query(m, name, dns.TypeA); r.Rcode != dns.RcodeServerFailure || len(r.Answer) != 0 {
			t.Errorf("%s with exit down: %v", name, r)
		}
	}
	if fx.resolves != 1 {
		t.Errorf("down exit asked %d times", fx.resolves)
	}

	// A transport failure fails closed.
	fx.up, fx.resErr = true, errors.New("connection refused")
	if r := query(m, "id.stream.example", dns.TypeA); r.Rcode != dns.RcodeServerFailure {
		t.Errorf("transport failure: %v", r)
	}

	// The exit node reports its VPN down: fail closed, even if cached.
	fx.up, fx.resErr, fx.exitDown = true, nil, true
	if r := query(m, "account.stream.example", dns.TypeA); r.Rcode != dns.RcodeServerFailure {
		t.Errorf("exit reports down: %v", r)
	}
	if r := query(m, "tv.stream.example", dns.TypeA); r.Rcode != dns.RcodeServerFailure {
		t.Errorf("cached name served while exit reports down: %v", r)
	}
}

func TestStaleServedWhenExitResolverFails(t *testing.T) {
	m, fx := newTestManager(t, fakeUpstream(t, "203.0.113.5"))
	now := time.Now()
	m.cache.now = func() time.Time { return now }
	query(m, "tv.stream.example", dns.TypeA)
	fx.exitErr = "upstream timeout"
	now = now.Add(2 * time.Hour) // expired, within 24 h
	r := query(m, "tv.stream.example", dns.TypeA)
	if r.Rcode != dns.RcodeSuccess || strings.Join(aRecords(r), ",") != "10.100.1.1" {
		t.Fatalf("stale not served: %v", r)
	}
	if res := m.recent.list(1)[0].Result; !strings.HasPrefix(res, "stale") {
		t.Errorf("result %q", res)
	}
	// A name never resolved before has nothing stale: SERVFAIL.
	if r := query(m, "new.stream.example", dns.TypeA); r.Rcode != dns.RcodeServerFailure {
		t.Errorf("uncached name: %v", r)
	}
	// After 24 h the stale answer is gone.
	time.Sleep(50 * time.Millisecond) // let the background refresh finish
	now = now.Add(staleMax)
	if r := query(m, "tv.stream.example", dns.TypeA); r.Rcode != dns.RcodeServerFailure {
		t.Errorf("answer older than 24h served: %v", r)
	}
}

func TestExitNXDOMAIN(t *testing.T) {
	m, fx := newTestManager(t, fakeUpstream(t, "203.0.113.5"))
	fx.rcode, fx.addrs = dns.RcodeNameError, nil
	if r := query(m, "nope.stream.example", dns.TypeA); r.Rcode != dns.RcodeNameError {
		t.Errorf("%v", r)
	}
}

func TestSelfExitResolvesLocally(t *testing.T) {
	m, fx := newTestManager(t, fakeUpstream(t, "203.0.113.7"))
	r := query(m, "www.local.test", dns.TypeA)
	if strings.Join(aRecords(r), ",") != "10.100.1.1" {
		t.Fatalf("%v", r)
	}
	if fx.resolves != 0 {
		t.Error("self exit asked a remote node")
	}
	if !strings.Contains(m.recent.list(1)[0].Result, "203.0.113.7") {
		t.Errorf("result %q", m.recent.list(1)[0].Result)
	}
}

func TestClientsMustBePrivate(t *testing.T) {
	m, _ := newTestManager(t, fakeUpstream(t, "203.0.113.5"))
	q := new(dns.Msg)
	q.SetQuestion("tv.stream.example.", dns.TypeA)
	r := m.answer(transit, &net.UDPAddr{IP: net.ParseIP("8.8.8.8"), Port: 1}, q)
	if r.Rcode != dns.RcodeRefused {
		t.Errorf("public client: %v", r)
	}
}

func TestDNSOverRealSockets(t *testing.T) {
	m, _ := newTestManager(t, fakeUpstream(t, "203.0.113.5"))
	for _, network := range []string{"udp", "tcp"} {
		c, err := m.listenDNS(network, "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		c.Close()
	}
	pc, _ := net.ListenPacket("udp4", "127.0.0.1:0")
	addr := pc.LocalAddr().String()
	pc.Close()
	c, err := m.listenDNS("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	time.Sleep(50 * time.Millisecond)
	q := new(dns.Msg)
	q.SetQuestion("tv.stream.example.", dns.TypeA)
	r, _, err := (&dns.Client{Timeout: 2 * time.Second}).Exchange(q, addr)
	if err != nil {
		t.Fatal(err)
	}
	// The answer is the address the query arrived on.
	if strings.Join(aRecords(r), ",") != "127.0.0.1" {
		t.Errorf("answer %v", r)
	}
}

func TestRelayToRemoteExit(t *testing.T) {
	m, fx := newTestManager(t, fakeUpstream(t, "203.0.113.5"))
	var gotReq ConnectRequest
	fx.connect = func(req ConnectRequest) (net.Conn, error) {
		gotReq = req
		a, b := net.Pipe()
		go func() { // the "CDN": echo the request line back
			defer b.Close()
			line, _ := bufio.NewReader(b).ReadString('\n')
			io.WriteString(b, "echo "+line)
		}()
		return a, nil
	}
	c, err := m.listenRelay("127.0.0.1:0", false)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	addr := c.(net.Listener).Addr().String()

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.WriteString(conn, "GET /x HTTP/1.1\r\nHost: tv.stream.example\r\n\r\n")
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	b, _ := io.ReadAll(conn)
	conn.Close()
	if string(b) != "echo GET /x HTTP/1.1\r\n" {
		t.Fatalf("got %q", b)
	}
	if gotReq.Exit != "nl" || gotReq.Port != 80 || gotReq.Host != "tv.stream.example" || len(gotReq.Addrs) != 2 {
		t.Errorf("connect request %+v", gotReq)
	}
	time.Sleep(50 * time.Millisecond)
	u := m.TakeServiceUsage()
	if len(u) != 1 || u[0].Service != "streamtv" || u[0].Conns != 1 || u[0].Bytes < int64(len(b)) {
		t.Errorf("usage %+v", u)
	}
	if u := m.TakeServiceUsage(); len(u) != 0 {
		t.Errorf("second delta %+v", u)
	}

	// Non-service hostnames are refused (not an open proxy).
	conn, _ = net.Dial("tcp", addr)
	_, _ = io.WriteString(conn, "GET / HTTP/1.1\r\nHost: www.bbc.co.uk\r\n\r\n")
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	b, _ = io.ReadAll(conn)
	conn.Close()
	if len(b) != 0 || m.refused.Load() != 1 {
		t.Errorf("non-service relayed: %q refused=%d", b, m.refused.Load())
	}

	// Exit down: closed, nothing relayed.
	fx.up = false
	conn, _ = net.Dial("tcp", addr)
	_, _ = io.WriteString(conn, "GET / HTTP/1.1\r\nHost: api.stream.example\r\n\r\n")
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	b, _ = io.ReadAll(conn)
	conn.Close()
	if len(b) != 0 {
		t.Errorf("relayed with exit down: %q", b)
	}
}

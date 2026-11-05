// SPDX-License-Identifier: Apache-2.0

package smartdns

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/ingressd/ingressd/pkg/config"
)

// realmsConfig puts two realms with their own Smart DNS on one node: both
// route stream.example, each through its own remote exit, only tq7k2m
// routes only-a.example, and each realm has an exit on this node.
const realmsConfig = `version: 1
edge: { public_ipv4: 203.0.113.10, acme: { ca: internal } }
security: { tunnel_input: restricted }
mesh:
  address: 10.255.0.1/16
  peers:
    nod_nl: { public_key: "eEvqkSJVw/7cGUEcJXmeHiNFDLBGOz8GpScshecvNHU=", endpoint: "198.51.100.6:51900", address: 10.255.0.2/32 }
realms:
  tq7k2m:
    smartdns:
      enabled: true
      upstream: [UPSTREAM]
      exits:
        tq7k2m.nl: { node: nod_nl, country: NL }
        tq7k2m.home: { node: self, country: GB }
      services:
        tq7k2m.tv: { domains: [stream.example, only-a.example], exit: tq7k2m.nl }
  tb4x9p:
    smartdns:
      enabled: true
      upstream: [UPSTREAM]
      exits:
        tb4x9p.nl: { node: nod_nl, country: NL }
        tb4x9p.home: { node: self, country: GB }
      services:
        tb4x9p.tv: { domains: [stream.example], exit: tb4x9p.nl }
tunnels:
  tq7k2m01: { realm: tq7k2m, table: 1201, site: router, listen_port: 51820, transit: 10.100.1.0/30, subnets: [192.168.1.0/24], virtual_prefix: 10.0.4.0/24 }
  tb4x9p01: { realm: tb4x9p, table: 1202, site: router, listen_port: 51821, transit: 10.100.2.0/30, subnets: [192.168.1.0/24], virtual_prefix: 10.0.5.0/24 }
`

func newRealmsManager(t *testing.T) (*Manager, *fakeExits) {
	t.Helper()
	cfg, err := config.Parse([]byte(strings.ReplaceAll(realmsConfig, "UPSTREAM", `"`+fakeUpstream(t, "203.0.113.5")+`"`)))
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	m := New(Options{})
	fx := &fakeExits{up: true, exitAddrs: map[string][]netip.Addr{
		"tq7k2m.nl": addrs("192.0.2.1"),
		"tb4x9p.nl": addrs("192.0.2.2"),
	}}
	m.remote = fx
	m.dnsPort, m.tlsPort, m.httpPort = 0, 0, 0
	m.Reconfigure(cfg, func(string) (string, error) { return "", errors.New("no secrets") })
	m.listeners.closeAll()
	t.Cleanup(m.listeners.closeAll)
	return m, fx
}

func queryAt(m *Manager, local, name string) *dns.Msg {
	q := new(dns.Msg)
	q.SetQuestion(dns.Fqdn(name), dns.TypeA)
	return m.answer(&net.UDPAddr{IP: net.ParseIP(local), Port: 53}, tv, q)
}

// Each realm's resolver answers only on its own transit address, with its
// own services and exits.
func TestRealmResolversAreSeparate(t *testing.T) {
	m, fx := newRealmsManager(t)
	if got := m.state().listen; len(got) != 2 || got[0].String() != "10.100.1.1" || got[1].String() != "10.100.2.1" {
		t.Fatalf("listen %v", got)
	}

	if a := aRecords(queryAt(m, "10.100.1.1", "tv.stream.example")); !slices.Equal(a, []string{"10.100.1.1"}) {
		t.Errorf("realm A answer %v", a)
	}
	if a := aRecords(queryAt(m, "10.100.2.1", "tv.stream.example")); !slices.Equal(a, []string{"10.100.2.1"}) {
		t.Errorf("realm B answer %v", a)
	}
	fx.mu.Lock()
	resolved, realms := slices.Clone(fx.resolved), slices.Clone(fx.realms)
	fx.mu.Unlock()
	if !slices.Equal(resolved, []string{"tq7k2m.nl", "tb4x9p.nl"}) || !slices.Equal(realms, []string{"tq7k2m", "tb4x9p"}) {
		t.Errorf("resolved at %v for realms %v, want each realm's own exit", resolved, realms)
	}

	// Realm B does not route realm A's service: the name goes upstream.
	if a := aRecords(queryAt(m, "10.100.1.1", "only-a.example")); !slices.Equal(a, []string{"10.100.1.1"}) {
		t.Errorf("realm A only-a answer %v", a)
	}
	if a := aRecords(queryAt(m, "10.100.2.1", "only-a.example")); !slices.Equal(a, []string{"203.0.113.5"}) {
		t.Errorf("realm B sees realm A's route: %v", a)
	}
	// No block answers on an address it does not listen on.
	if r := queryAt(m, "10.9.9.9", "tv.stream.example"); r.Rcode != dns.RcodeRefused {
		t.Errorf("unknown listen address: %s", dns.RcodeToString[r.Rcode])
	}

	names := []string{}
	for _, s := range m.Services() {
		names = append(names, s.Name+"="+s.Active)
	}
	if !slices.Equal(names, []string{"tb4x9p.tv=tb4x9p.nl", "tq7k2m.tv=tq7k2m.nl"}) {
		t.Errorf("services %v", names)
	}
}

// The relay picks the realm by the address the home connected to.
func TestRealmRelayUsesItsOwnRoutes(t *testing.T) {
	m, fx := newRealmsManager(t)
	got := make(chan ConnectRequest, 2)
	fx.connect = func(req ConnectRequest) (net.Conn, error) {
		got <- req
		return nil, errors.New("test: no exit")
	}
	relay := func(local, host string) {
		ln, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()
		go func() {
			c, err := ln.Accept()
			if err == nil {
				m.handleRelay(&localConn{Conn: c, local: &net.TCPAddr{IP: net.ParseIP(local), Port: 51080}}, false)
			}
		}()
		c, err := net.Dial("tcp4", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		c.Write([]byte("GET / HTTP/1.1\r\nHost: " + host + "\r\n\r\n"))
		c.SetReadDeadline(time.Now().Add(3 * time.Second))
		c.Read(make([]byte, 1))
		c.Close()
	}
	relay("10.100.2.1", "tv.stream.example")
	select {
	case req := <-got:
		if req.Exit != "tb4x9p.nl" || req.Realm != "tb4x9p" {
			t.Errorf("realm B relayed via %q for realm %q", req.Exit, req.Realm)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("realm B did not relay")
	}
	before := m.refused.Load()
	relay("10.100.2.1", "only-a.example")
	if m.refused.Load() != before+1 {
		t.Error("realm B relayed realm A's hostname")
	}
	select {
	case req := <-got:
		t.Errorf("realm B relayed only-a.example via %q", req.Exit)
	default:
	}
}

type localConn struct {
	net.Conn
	local net.Addr
}

func (c *localConn) LocalAddr() net.Addr { return c.local }

// The exit API refuses an exit of another realm (or a realm exit to a
// request naming none) in resolve, health and relay.
func TestExitAPIRefusesOtherRealms(t *testing.T) {
	m, _ := newRealmsManager(t)
	ctx := context.Background()
	for _, tc := range []struct{ realm, exit, want string }{
		{"tb4x9p", "tq7k2m.home", `exit "tq7k2m.home" is not hosted on this node for realm "tb4x9p"`},
		{"", "tq7k2m.home", "belongs to a realm; the request names none"},
		{"tq7k2m", "tq7k2m.nl", "is not hosted on this node"},
	} {
		if r := m.resolveLocal(ctx, tc.realm, tc.exit, "tv.stream.example"); !strings.Contains(r.Error, tc.want) || r.ExitUp {
			t.Errorf("resolve %s for %q: %+v, want %q", tc.exit, tc.realm, r, tc.want)
		}
	}

	body, _ := json.Marshal(resolveRequest{Exit: "tq7k2m.home", Name: "tv.stream.example", Realm: "tb4x9p"})
	w := httptest.NewRecorder()
	m.resolveHandler().ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/v1/resolve", bytes.NewReader(body)))
	if !strings.Contains(w.Body.String(), "not hosted on this node for realm") {
		t.Errorf("POST /v1/resolve across realms: %s", w.Body.String())
	}

	for realm, want := range map[string][]string{"tq7k2m": {"tq7k2m.home"}, "tb4x9p": {"tb4x9p.home"}, "": {}} {
		w := httptest.NewRecorder()
		m.exitsHandler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/v1/exits?realm="+realm, nil))
		var out exitsResponse
		json.NewDecoder(w.Body).Decode(&out)
		var got []string
		for name := range out.Exits {
			got = append(got, name)
		}
		slices.Sort(got)
		if !slices.Equal(got, want) && !(len(got) == 0 && len(want) == 0) {
			t.Errorf("GET /v1/exits?realm=%s lists %v, want %v", realm, got, want)
		}
	}

	cfg := *m.state().cfg
	mc := *cfg.Mesh
	mc.Peers = map[string]config.MeshPeer{"nod_nl": {PublicKey: "eEvqkSJVw/7cGUEcJXmeHiNFDLBGOz8GpScshecvNHU=", Address: "127.0.0.1/32"}}
	cfg.Mesh = &mc
	m.mesh.Reconfigure(&cfg)
	defer m.mesh.Reconfigure(nil)
	c, err := m.listenExitRelay("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	for _, req := range []ConnectRequest{
		{Exit: "tq7k2m.home", Realm: "tb4x9p", Host: "tv.stream.example", Port: 443, Addrs: addrs("192.0.2.20")},
		{Exit: "tq7k2m.home", Host: "tv.stream.example", Port: 443, Addrs: addrs("192.0.2.20")},
	} {
		conn, err := net.Dial("tcp", c.(net.Listener).Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		conn.SetDeadline(time.Now().Add(3 * time.Second))
		WriteConnectRequest(conn, req)
		resp, err := ReadConnectResponse(conn)
		conn.Close()
		if err != nil || resp.OK || resp.ExitDown || !strings.Contains(resp.Error, "tq7k2m.home") {
			t.Errorf("relay %+v: %+v, %v", req, resp, err)
		}
	}
}

// SPDX-License-Identifier: Apache-2.0

package smartdns

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"

	"github.com/miekg/dns"

	"github.com/ingressd/ingressd/pkg/config"
)

func TestLocalExitResolvesThroughDial(t *testing.T) {
	upstream := fakeUpstream(t, "203.0.113.8")
	var mu sync.Mutex
	var dials []string
	// Stands in for the VPN device: the resolver address only exists
	// inside the tunnel.
	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		mu.Lock()
		dials = append(dials, network+" "+addr)
		mu.Unlock()
		var d net.Dialer
		return d.DialContext(ctx, network, upstream)
	}
	m := New(Options{})
	m.Reconfigure(Plan{
		Site:     "home",
		Exits:    map[string]PlanExit{"vpn-nl": {Country: "NL", Egress: &EgressOptions{DNS: []string{"10.2.0.1"}, Dial: dial, VPN: true}}},
		Services: map[string]config.SmartDNSSiteService{"tv": {Domains: []string{"stream.example"}, Exits: []string{"vpn-nl"}}},
	})
	t.Cleanup(m.listeners.closeAll)
	r := query(m, "tv.stream.example", dns.TypeA)
	if r.Rcode != dns.RcodeSuccess || strings.Join(aRecords(r), ",") != "10.100.1.1" {
		t.Fatalf("answer %v", r)
	}
	if res := m.recent.list(1)[0].Result; !strings.Contains(res, "exit vpn-nl") || !strings.Contains(res, "203.0.113.8") {
		t.Errorf("result %q", res)
	}
	mu.Lock()
	defer mu.Unlock()
	if strings.Join(dials, ",") != "udp4 10.2.0.1:53" {
		t.Errorf("dials %v", dials)
	}
	if ex := m.Exits(); len(ex) != 1 || ex[0].Name != "vpn-nl" || !ex[0].Up || !ex[0].VPN {
		t.Errorf("exits %+v", ex)
	}
}

func TestBindErrors(t *testing.T) {
	m := New(Options{
		DNSPort: 5300, TLSPort: 4430, HTTPPort: 8000,
		Listen: func(network, addr string) (net.Listener, error) {
			if strings.HasSuffix(addr, ":4430") {
				return nil, errors.New("bind: address already in use")
			}
			return net.Listen(network, "127.0.0.1:0")
		},
		ListenPacket: func(network, _ string) (net.PacketConn, error) { return net.ListenPacket(network, "127.0.0.1:0") },
	})
	t.Cleanup(m.listeners.closeAll)
	m.Reconfigure(Plan{Listen: []netip.Addr{netip.MustParseAddr("127.0.0.1")}})
	be := m.BindErrors()
	if len(be) != 1 || be["relay-tls"] != "bind: address already in use" {
		t.Errorf("bind errors %v", be)
	}
	if got := strings.Join(m.listeners.names(), ","); got != "dns-tcp 127.0.0.1:5300,dns-udp 127.0.0.1:5300,relay-http 127.0.0.1:8000" {
		t.Errorf("running %s", got)
	}
	if s := m.Snapshot(); s.BindErrors["relay-tls"] == "" || strings.Join(s.Listen, ",") != "127.0.0.1" {
		t.Errorf("snapshot %+v", s)
	}
	// Dropping the address drops its failure too.
	m.Reconfigure(Plan{})
	if be := m.BindErrors(); len(be) != 0 {
		t.Errorf("bind errors after removal %v", be)
	}
}

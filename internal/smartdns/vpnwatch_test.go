// SPDX-License-Identifier: Apache-2.0

package smartdns

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestParseTrace(t *testing.T) {
	ip, cc, err := parseTrace(strings.NewReader("fl=29f\nh=1.1.1.1\nip=203.0.113.7\nts=1.2\nloc=gb\ncolo=LHR\n"))
	if err != nil || ip != "203.0.113.7" || cc != "GB" {
		t.Errorf("%q %q %v", ip, cc, err)
	}
	if _, cc, _ := parseTrace(strings.NewReader("ip=203.0.113.7\nloc=XX\n")); cc != "" {
		t.Errorf("XX is unknown, got %q", cc)
	}
	if _, _, err := parseTrace(strings.NewReader("<html>captive portal</html>")); err == nil {
		t.Error("no ip accepted")
	}
}

func TestExitHealth(t *testing.T) {
	e := &egress{country: "NL", public: "198.51.100.6"}
	if ip, msg := exitHealth(e, "", "", "timeout", true); ip != "198.51.100.6" || !strings.Contains(msg, "egress check failed") {
		t.Errorf("%q %q", ip, msg)
	}
	if ip, msg := exitHealth(e, "203.0.113.9", "DE", "", true); ip != "203.0.113.9" || msg != "egress 203.0.113.9 geolocates to DE, expected NL" {
		t.Errorf("%q %q", ip, msg)
	}
	if _, msg := exitHealth(e, "203.0.113.9", "NL", "", true); msg != "" {
		t.Errorf("match: %q", msg)
	}
	if _, msg := exitHealth(e, "203.0.113.9", "DE", "", false); msg != "" {
		t.Errorf("down exits report the tunnel, not the trace: %q", msg)
	}
}

func TestTraceThroughEgress(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, _ := net.SplitHostPort(r.RemoteAddr)
		fmt.Fprintf(w, "ip=%s\nloc=NL\n", host) //nolint:gosec // G705: plain-text trace stub for the test
	}))
	defer srv.Close()
	ip, cc, err := trace(context.Background(), &egress{}, srv.URL)
	if err != nil || ip != "127.0.0.1" || cc != "NL" {
		t.Errorf("%q %q %v", ip, cc, err)
	}
}

// fakeWG is a WireGuard device with one peer whose endpoint can change.
type fakeWG struct {
	mu        sync.Mutex
	peer      wgtypes.Key
	endpoint  *net.UDPAddr
	handshake time.Time
	sets      []string
}

func (f *fakeWG) device(string) (*wgtypes.Device, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return &wgtypes.Device{Peers: []wgtypes.Peer{{PublicKey: f.peer, Endpoint: f.endpoint, LastHandshakeTime: f.handshake}}}, nil
}

func (f *fakeWG) configure(_ string, c wgtypes.Config) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, p := range c.Peers {
		if p.PublicKey == f.peer && p.Endpoint != nil {
			f.endpoint = p.Endpoint
			f.sets = append(f.sets, p.Endpoint.String())
		}
	}
	return nil
}

func TestRefreshEndpointFollowsDNS(t *testing.T) {
	k, _ := wgtypes.GeneratePrivateKey()
	wg := &fakeWG{peer: k.PublicKey(), handshake: time.Now()}
	addrs := []netip.Addr{netip.MustParseAddr("203.0.113.10")}
	var mu sync.Mutex
	m := New(Options{
		Device:    wg.device,
		Configure: wg.configure,
		TraceURL:  "http://127.0.0.1:1/",
		Lookup: func(context.Context, string) ([]netip.Addr, error) {
			mu.Lock()
			defer mu.Unlock()
			return addrs, nil
		},
	})
	e := &egress{exit: "proton-nl", ifname: "ix-x-proton-nl", endpoint: "nl-12.vpn.example.net:51820", peerKey: k.PublicKey().String(), device: wg.device}

	// No endpoint yet (the name did not resolve at apply time).
	m.refreshEndpoint(e)
	if len(wg.sets) != 1 || wg.sets[0] != "203.0.113.10:51820" {
		t.Fatalf("sets %v", wg.sets)
	}
	if got := e.endpointNow(); got != "203.0.113.10:51820" {
		t.Errorf("endpointNow %q", got)
	}
	// Unchanged DNS: no reconfigure.
	m.refreshEndpoint(e)
	if len(wg.sets) != 1 {
		t.Fatalf("reconfigured without a change: %v", wg.sets)
	}
	// The provider moves the server; IPv4 is preferred over IPv6.
	mu.Lock()
	addrs = []netip.Addr{netip.MustParseAddr("2001:db8::10"), netip.MustParseAddr("203.0.113.20")}
	mu.Unlock()
	m.refreshEndpoint(e)
	if len(wg.sets) != 2 || wg.sets[1] != "203.0.113.20:51820" {
		t.Fatalf("sets %v", wg.sets)
	}
	// Still listed among several addresses: kept (no flapping).
	mu.Lock()
	addrs = []netip.Addr{netip.MustParseAddr("203.0.113.30"), netip.MustParseAddr("203.0.113.20")}
	mu.Unlock()
	m.refreshEndpoint(e)
	if len(wg.sets) != 2 {
		t.Fatalf("switched although the current address is still listed: %v", wg.sets)
	}
	// IP endpoints are set when missing and never re-resolved.
	wg.endpoint = nil
	e.endpoint = "198.51.100.14:51820"
	m.refreshEndpoint(e)
	if wg.sets[len(wg.sets)-1] != "198.51.100.14:51820" {
		t.Errorf("sets %v", wg.sets)
	}
}

func TestWatchEgressTracesAndReports(t *testing.T) {
	var hits int
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits++
		mu.Unlock()
		fmt.Fprint(w, "ip=203.0.113.99\nloc=DE\n")
	}))
	defer srv.Close()
	k, _ := wgtypes.GeneratePrivateKey()
	wg := &fakeWG{peer: k.PublicKey(), handshake: time.Now(), endpoint: &net.UDPAddr{IP: net.IPv4(203, 0, 113, 10), Port: 51820}}
	m := New(Options{Device: wg.device, Configure: wg.configure, TraceURL: srv.URL})
	// A direct exit (no interface) so the trace can reach the test server.
	e := &egress{exit: "nl", country: "NL", public: "198.51.100.6", device: wg.device}
	m.st.Store(&state{egress: map[string]*egress{"nl": e}, exits: map[string]exitInfo{"nl": {}}, byAddr: map[netip.Addr]*scope{}, site: map[netip.Addr]string{}})
	m.watchEgress(time.Now())
	deadline := time.Now().Add(3 * time.Second)
	for {
		ex := m.Exits()
		if len(ex) == 1 && ex[0].Egress == "203.0.113.99" {
			if ex[0].Country != "DE" || !strings.Contains(ex[0].Message, "geolocates to DE, expected NL") {
				t.Errorf("%+v", ex[0])
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("no trace result: %+v", ex)
		}
		time.Sleep(20 * time.Millisecond)
	}
	// Not due again right away.
	m.watchEgress(time.Now())
	time.Sleep(50 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	if hits != 1 {
		t.Errorf("trace hits %d", hits)
	}
}

// SPDX-License-Identifier: Apache-2.0

package smartdns

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/ingressd/ingressd/pkg/config"
)

var (
	siteEdge = netip.MustParseAddr("10.100.1.1") // the node's end of tunnel site1
	siteAddr = netip.MustParseAddr("10.100.1.2") // the connector's end
)

// newTestExitServer serves site1 (allowed) but not other. Its listeners
// cannot bind the transit addresses here, so tests call the handlers.
func newTestExitServer(t *testing.T, upstream string) *ExitServer {
	t.Helper()
	s := NewExitServer(ExitServerOptions{TraceURL: "http://127.0.0.1:1/"})
	s.Reconfigure(&config.Config{
		Edge:    config.Edge{PublicIPv4: "198.51.100.7"},
		Tunnels: map[string]config.Tunnel{"site1": {Transit: "10.100.1.0/30"}, "other": {Transit: "10.100.2.0/30"}},
		SmartDNS: &config.SmartDNS{Exit: &config.SmartDNSNodeExit{
			Country: "NL", Sites: []string{"site1", "missing"}, Upstream: []string{upstream},
		}},
	})
	t.Cleanup(s.listeners.closeAll)
	return s
}

// setTrace records what a trace of the node's egress found.
func setTrace(s *ExitServer, ip, country string) {
	p := s.probes.probe(s.state().egress)
	p.mu.Lock()
	defer p.mu.Unlock()
	p.ip, p.country, p.at = ip, country, time.Now()
}

func TestExitServerAllowsOnlyTheSiteAddress(t *testing.T) {
	s := newTestExitServer(t, "127.0.0.1:9")
	for _, tc := range []struct {
		local, remote string
		ok            bool
	}{
		{"10.100.1.1", "10.100.1.2", true},
		{"10.100.1.1", "10.100.1.3", false}, // another address in the tunnel
		{"10.100.1.1", "192.168.1.10", false},
		{"10.100.1.2", "10.100.1.1", false},
		{"10.100.2.1", "10.100.2.2", false}, // a tunnel not listed in sites
	} {
		site, ok := s.allowed(netip.MustParseAddr(tc.local), netip.MustParseAddr(tc.remote))
		if ok != tc.ok || (ok && site != "site1") {
			t.Errorf("%s <- %s: %q %v", tc.local, tc.remote, site, ok)
		}
	}
	if got := strings.Join(s.Snapshot().Sites, ","); got != "site1" {
		t.Errorf("sites %s", got)
	}

	// With no exit configured nothing is allowed.
	s.Reconfigure(&config.Config{Tunnels: map[string]config.Tunnel{"site1": {Transit: "10.100.1.0/30"}}})
	if _, ok := s.allowed(siteEdge, siteAddr); ok {
		t.Error("allowed without an exit")
	}
}

func exitAPI(s *ExitServer, method, path, body string, remote netip.Addr) *httptest.ResponseRecorder {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/resolve", s.resolveHandler)
	mux.HandleFunc("GET /v1/exit", s.exitHandler)
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req = req.WithContext(context.WithValue(req.Context(), connAddrsKey{}, [2]netip.Addr{siteEdge, remote}))
	w := httptest.NewRecorder()
	s.guard(mux).ServeHTTP(w, req)
	return w
}

func TestExitServerAPI(t *testing.T) {
	s := newTestExitServer(t, fakeUpstream(t, "203.0.113.5"))
	w := exitAPI(s, "POST", "/v1/resolve", `{"name":"TV.stream.example."}`, siteAddr)
	var resp resolveResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); w.Code != 200 || err != nil {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	if !resp.ExitUp || resp.Rcode != 0 || len(resp.Addrs) != 1 || resp.Addrs[0].String() != "203.0.113.5" || resp.TTL != 120 {
		t.Errorf("resolve %+v", resp)
	}
	w = exitAPI(s, "GET", "/v1/exit", "", siteAddr)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"up":true`) || !strings.Contains(w.Body.String(), `"egress":"198.51.100.7"`) {
		t.Errorf("/v1/exit %d %s", w.Code, w.Body)
	}

	// Any other source is refused before the handlers run.
	for _, remote := range []string{"10.100.1.3", "10.100.2.2", "127.0.0.1"} {
		w := exitAPI(s, "POST", "/v1/resolve", `{"name":"tv.stream.example"}`, netip.MustParseAddr(remote))
		if w.Code != http.StatusForbidden {
			t.Errorf("from %s: %d %s", remote, w.Code, w.Body)
		}
	}
	if s.refused.Load() != 3 {
		t.Errorf("refused %d", s.refused.Load())
	}
}

func TestExitServerCountry(t *testing.T) {
	s := newTestExitServer(t, fakeUpstream(t, "203.0.113.5"))
	e := s.state().egress
	if up, msg := s.countryOK(e); !up || msg != "" {
		t.Errorf("not traced yet: %v %q", up, msg)
	}
	setTrace(s, "198.51.100.7", "NL")
	if up, msg := s.countryOK(e); !up || msg != "" {
		t.Errorf("NL: %v %q", up, msg)
	}
	setTrace(s, "198.51.100.7", "DE")
	if up, msg := s.countryOK(e); up || msg != "egress 198.51.100.7 geolocates to DE, expected NL" {
		t.Errorf("DE: %v %q", up, msg)
	}
	// An unknown country after a trace does not fail the exit.
	setTrace(s, "198.51.100.7", "")
	if up, _ := s.countryOK(e); !up {
		t.Error("unknown country: down")
	}

	// The API reports the mismatch so the connector moves on.
	setTrace(s, "198.51.100.7", "DE")
	w := exitAPI(s, "POST", "/v1/resolve", `{"name":"tv.stream.example"}`, siteAddr)
	if !strings.Contains(w.Body.String(), `"exit_up":false`) || !strings.Contains(w.Body.String(), "geolocates to DE, expected NL") {
		t.Errorf("resolve %s", w.Body)
	}
	w = exitAPI(s, "GET", "/v1/exit", "", siteAddr)
	if !strings.Contains(w.Body.String(), `"up":false`) || !strings.Contains(w.Body.String(), "geolocates to DE, expected NL") {
		t.Errorf("/v1/exit %s", w.Body)
	}
}

// addrConn gives a pipe the tunnel addresses handleRelay checks.
type addrConn struct {
	net.Conn
	local, remote net.Addr
}

func (c addrConn) LocalAddr() net.Addr  { return c.local }
func (c addrConn) RemoteAddr() net.Addr { return c.remote }

func relayVia(t *testing.T, s *ExitServer, remote netip.Addr, req ConnectRequest) (ConnectResponse, error) {
	t.Helper()
	a, b := net.Pipe()
	defer a.Close()
	local := net.TCPAddrFromAddrPort(netip.AddrPortFrom(siteEdge, 51902))
	go s.handleRelay(addrConn{b, local, net.TCPAddrFromAddrPort(netip.AddrPortFrom(remote, 40000))})
	a.SetDeadline(time.Now().Add(3 * time.Second))
	if err := WriteConnectRequest(a, req); err != nil {
		return ConnectResponse{}, err
	}
	return ReadConnectResponse(a)
}

func TestExitServerRelayRefusals(t *testing.T) {
	s := newTestExitServer(t, "127.0.0.1:9")
	for _, tc := range []struct {
		req  ConnectRequest
		want string
	}{
		{ConnectRequest{Exit: "nl", Host: "tv.stream.example", Port: 443, Addrs: addrs("192.168.1.1")}, "not a public address"},
		{ConnectRequest{Exit: "nl", Host: "tv.stream.example", Port: 443, Addrs: addrs("127.0.0.1")}, "not a public address"},
		{ConnectRequest{Exit: "nl", Host: "tv.stream.example", Port: 22, Addrs: addrs("192.0.2.20")}, "port 22"},
	} {
		resp, err := relayVia(t, s, siteAddr, tc.req)
		if err != nil || resp.OK || resp.ExitDown || !strings.Contains(resp.Error, tc.want) {
			t.Errorf("%+v: %+v, %v (want %q, not exit down)", tc.req, resp, err, tc.want)
		}
	}

	// The exit geolocating elsewhere is an exit-down refusal (retried
	// through the service's next exit).
	setTrace(s, "198.51.100.7", "DE")
	resp, err := relayVia(t, s, siteAddr, ConnectRequest{Exit: "nl", Host: "tv.stream.example", Port: 443, Addrs: addrs("192.0.2.20")})
	if err != nil || resp.OK || !resp.ExitDown || !strings.Contains(resp.Error, "geolocates to DE, expected NL") {
		t.Errorf("DE: %+v, %v", resp, err)
	}

	// Other sources get the connection closed without an answer.
	other := ConnectRequest{Exit: "nl", Host: "tv.stream.example", Port: 443, Addrs: addrs("192.0.2.20")}
	if resp, err := relayVia(t, s, netip.MustParseAddr("10.100.1.3"), other); err == nil {
		t.Errorf("other source answered %+v", resp)
	}
	if s.refused.Load() != 1 {
		t.Errorf("refused %d", s.refused.Load())
	}
}

// SPDX-License-Identifier: Apache-2.0

package client

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ingressd/ingressd/internal/connector/proto"
)

func pfx(s string) netip.Prefix { return netip.MustParsePrefix(s) }

func fakeIfaces(ifs ...Iface) func() ([]Iface, error) {
	return func() ([]Iface, error) { return ifs, nil }
}

func TestDiscoverySubnets(t *testing.T) {
	sc := &Scanner{
		Interfaces: fakeIfaces(
			Iface{Name: "lo", Up: true, Loopback: true, Prefixes: []netip.Prefix{pfx("127.0.0.1/8")}},
			Iface{Name: "eth0", Up: true, Prefixes: []netip.Prefix{pfx("192.168.1.10/24"), pfx("203.0.113.5/24")}},
			Iface{Name: "eth1", Up: true, Prefixes: []netip.Prefix{pfx("10.1.2.3/16")}},       // capped to /22
			Iface{Name: "eth2", Up: false, Prefixes: []netip.Prefix{pfx("172.16.5.1/24")}},    // down
			Iface{Name: "ingressd0", Up: true, Prefixes: []netip.Prefix{pfx("10.9.0.2/24")}},  // tunnel device
			Iface{Name: "wg-other", Up: true, Prefixes: []netip.Prefix{pfx("10.100.1.2/24")}}, // transit network
			Iface{Name: "br0", Up: true, Prefixes: []netip.Prefix{pfx("192.168.1.11/24"), pfx("172.20.0.1/32")}},
			Iface{Name: "p2p", Up: true, Prefixes: []netip.Prefix{pfx("172.31.0.0/31")}},
		),
		ExcludeIfaces:   []string{"ingressd0"},
		ExcludePrefixes: []netip.Prefix{pfx("10.100.1.0/24")},
	}
	got, err := sc.Subnets()
	if err != nil {
		t.Fatal(err)
	}
	want := []netip.Prefix{pfx("192.168.1.0/24"), pfx("10.1.0.0/22"), pfx("172.31.0.0/31")}
	if !slices.Equal(got, want) {
		t.Errorf("subnets = %v, want %v", got, want)
	}
}

func TestRequestedDiscoveryStaysInsideTheAllowlist(t *testing.T) {
	ifaces := fakeIfaces(
		Iface{Name: "eth0", Up: true, Prefixes: []netip.Prefix{pfx("192.168.1.10/24")}},
		Iface{Name: "eth1", Up: true, Prefixes: []netip.Prefix{pfx("10.1.2.3/24")}},
		Iface{Name: "eth2", Up: true, Prefixes: []netip.Prefix{pfx("172.16.5.1/24")}},
		Iface{Name: "eth3", Up: true, Prefixes: []netip.Prefix{pfx("100.64.0.6/24")}},
	)
	for _, tc := range []struct {
		reach *localReach
		want  []netip.Prefix
	}{
		{reachOf("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"), []netip.Prefix{pfx("192.168.1.0/24"), pfx("10.1.2.0/24"), pfx("172.16.5.0/24")}},
		{reachOf("192.168.1.0/25", "192.168.1.7/32", "10.1.2.9/32"), []netip.Prefix{pfx("192.168.1.0/25"), pfx("10.1.2.9/32")}},
		{reachOf("198.51.100.0/24"), []netip.Prefix{}},
		{reachOf(), []netip.Prefix{}},
		{nil, []netip.Prefix{}},
	} {
		e := &edge{s: &session{st: &State{reach: tc.reach}, mode: ModeNetstack}}
		sc := e.scanner()
		sc.Interfaces = ifaces
		sc.Eligible = IsPrivateV4
		got, err := sc.Subnets()
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(got, tc.want) {
			t.Errorf("list %+v: scans %v, want %v", tc.reach, got, tc.want)
		}
	}
}

func TestDiscoveryHosts(t *testing.T) {
	self := netip.MustParseAddr("192.168.0.2")
	if got := hosts(pfx("192.168.0.0/30"), self); len(got) != 1 || got[0].String() != "192.168.0.1" {
		t.Errorf("/30 hosts = %v", got)
	}
	if got := hosts(pfx("10.0.0.0/31"), netip.MustParseAddr("10.0.0.0")); len(got) != 1 || got[0].String() != "10.0.0.1" {
		t.Errorf("/31 hosts = %v", got)
	}
	if got := hosts(pfx("192.168.0.0/24"), self); len(got) != 253 {
		t.Errorf("/24 has %d hosts, want 253", len(got))
	}
	if got := hosts(pfx("10.0.0.0/22"), netip.MustParseAddr("10.0.1.1")); len(got) != 1021 {
		t.Errorf("/22 has %d hosts, want 1021", len(got))
	}
}

func port(t *testing.T, rawURL string) int {
	t.Helper()
	_, p, err := net.SplitHostPort(strings.TrimPrefix(strings.TrimPrefix(rawURL, "https://"), "http://"))
	if err != nil {
		t.Fatal(err)
	}
	n, _ := strconv.Atoi(p)
	return n
}

// TestDiscoveryScan scans fake "LAN" services on loopback: a plain HTTP app
// that redirects to its login page, an HTTPS app with a self-signed
// certificate, a TCP service that is not HTTP, and a closed port.
func TestDiscoveryScan(t *testing.T) {
	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "TestApp/1.0")
		if r.URL.Path == "/" {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		fmt.Fprint(w, "<html><head><TITLE>\n  Home &amp; Garden\n</TITLE></head></html>")
	}))
	defer app.Close()
	secure := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "pve-api-daemon/3.0")
		fmt.Fprint(w, "<title>Proxmox Virtual Environment</title>")
	}))
	defer secure.Close()
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = raw.Close() }()
	go func() {
		for {
			c, err := raw.Accept()
			if err != nil {
				return
			}
			_, _ = c.Write([]byte("SSH-2.0-OpenSSH_9.6\r\n"))
			_ = c.Close()
		}
	}()
	closed, _ := net.Listen("tcp", "127.0.0.1:0")
	closedPort := closed.Addr().(*net.TCPAddr).Port
	_ = closed.Close()

	appPort, securePort, rawPort := port(t, app.URL), port(t, secure.URL), raw.Addr().(*net.TCPAddr).Port
	sc := &Scanner{
		// 127.0.0.0/30: hosts 127.0.0.1 (the services) and 127.0.0.2 (self).
		Interfaces: fakeIfaces(Iface{Name: "lan0", Up: true, Prefixes: []netip.Prefix{pfx("127.0.0.2/30")}}),
		Eligible:   func(netip.Addr) bool { return true },
		Ports:      []int{appPort, securePort, rawPort, closedPort},
		Rate:       1000,
		Timeout:    20 * time.Second,
	}
	subnets, svcs, err := sc.Scan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(subnets) != 1 || subnets[0] != pfx("127.0.0.0/30") {
		t.Errorf("subnets = %v", subnets)
	}
	want := []proto.DiscoveredService{
		{Address: "127.0.0.1", Port: appPort, Scheme: "http", Title: "Home & Garden", Server: "TestApp/1.0"},
		{Address: "127.0.0.1", Port: securePort, Scheme: "https", Title: "Proxmox Virtual Environment", Server: "pve-api-daemon/3.0"},
	}
	slices.SortFunc(want, func(a, b proto.DiscoveredService) int { return a.Port - b.Port })
	if !slices.Equal(svcs, want) {
		got, _ := json.MarshalIndent(svcs, "", " ")
		t.Errorf("services:\n%s\nwant %+v", got, want)
	}
}

func TestDiscoveryNoSubnets(t *testing.T) {
	sc := &Scanner{Interfaces: fakeIfaces(Iface{Name: "eth0", Up: true, Prefixes: []netip.Prefix{pfx("203.0.113.5/24")}})}
	if _, _, err := sc.Scan(context.Background()); err == nil {
		t.Error("scan without private subnets succeeded")
	}
}

// TestEnrollJoinPinsCA enrols with a join string that carries the edge's CA:
// the connector trusts that CA (and only it) for the edge.
func TestEnrollJoinPinsCA(t *testing.T) {
	edge := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != proto.EnrollPath {
			http.NotFound(w, r)
			return
		}
		var req proto.EnrollRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.Token != "tok123" {
			http.Error(w, "bad token", http.StatusForbidden)
			return
		}
		_ = json.NewEncoder(w).Encode(proto.EnrollResponse{Credential: "cred", Config: proto.TunnelConfig{Tunnel: "home", Address: "10.100.1.2/24", Revision: "r1"}})
	}))
	defer edge.Close()
	caPEM := func(s *httptest.Server) string {
		return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.Certificate().Raw}))
	}
	// httptest certificates are valid for example.com; dial the server's
	// loopback address instead of resolving the name.
	edgeURL := "https://example.com:" + strconv.Itoa(port(t, edge.URL))

	enrollWith := func(ca string) (*State, error) {
		js, err := proto.EncodeJoin(proto.Join{URL: edgeURL, Token: "tok123", CA: ca})
		if err != nil {
			t.Fatal(err)
		}
		o := EnrollOptions{Mode: ModeNetstack, EdgeAddr: "127.0.0.1"}
		if err := o.ApplyJoin(js); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return Enroll(ctx, filepath.Join(t.TempDir(), "connector.json"), o)
	}
	st, err := enrollWith(caPEM(edge))
	if err != nil {
		t.Fatalf("enrol with the edge's CA: %v", err)
	}
	if p := st.Primary(); len(st.Edges) != 1 || p.URL != edgeURL || p.CAPEM != caPEM(edge) || p.Credential != "cred" || st.Tunnel() != "home" {
		t.Errorf("state = %+v", st)
	}
	if _, err := tlsConfig("example.com", "", st.Primary().CAPEM, false); err != nil {
		t.Errorf("stored CA does not load: %v", err)
	}
	if _, err := enrollWith(otherCA(t)); err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Errorf("enrol with a different CA: err = %v, want a certificate error", err)
	}
	if _, err := enrollWith(""); err == nil {
		t.Error("enrol without a CA trusted the self-signed edge")
	}
}

// otherCA returns a freshly generated self-signed CA certificate (httptest
// servers all share one built-in certificate).
func otherCA(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(42),
		Subject:               pkix.Name{CommonName: "other test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// TestEnrollAlternateEdgeToken falls back to the second edge of a join string
// and enrols there with that edge's own token.
func TestEnrollAlternateEdgeToken(t *testing.T) {
	edge := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req proto.EnrollRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.Token != "tok-b" {
			http.Error(w, "bad token", http.StatusForbidden)
			return
		}
		_ = json.NewEncoder(w).Encode(proto.EnrollResponse{Credential: "cred-b", Config: proto.TunnelConfig{Tunnel: "home", Address: "10.100.1.2/24", Revision: "r1"}})
	}))
	defer edge.Close()
	ca := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: edge.Certificate().Raw}))
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	deadURL := "https://example.com:" + strconv.Itoa(l.Addr().(*net.TCPAddr).Port)
	_ = l.Close()

	enroll := func(tokB string) (*State, error) {
		js, err := proto.EncodeJoin(proto.Join{Token: "tok-top", Edges: []proto.JoinEdge{
			{URL: deadURL, CA: ca, T: "tok-a"},
			{URL: edge.URL, CA: ca, T: tokB},
		}})
		if err != nil {
			t.Fatal(err)
		}
		o := EnrollOptions{Mode: ModeNetstack, EdgeAddr: "127.0.0.1"}
		if err := o.ApplyJoin(js); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return Enroll(ctx, filepath.Join(t.TempDir(), "connector.json"), o)
	}
	st, err := enroll("tok-b")
	if err != nil {
		t.Fatalf("enrol via the second edge: %v", err)
	}
	if p := st.Primary(); len(st.Edges) != 1 || p.URL != edge.URL || p.Credential != "cred-b" {
		t.Errorf("state = %+v", st)
	}
	if _, err := enroll(""); err == nil || !strings.Contains(err.Error(), "bad token") {
		t.Errorf("enrol with the top-level token: err = %v, want bad token", err)
	}
}

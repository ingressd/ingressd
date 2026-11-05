// SPDX-License-Identifier: Apache-2.0

package smartdns

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"sync/atomic"
	"testing"

	"github.com/ingressd/ingressd/pkg/config"
)

var testCheck = config.SmartDNSCheck{Domains: []string{"stream.example"}, Host: "tv.stream.example", Path: "/v1/location", Field: "countryCode", CacheBuster: "cb"}

func addrs(ss ...string) []netip.Addr {
	out := make([]netip.Addr, len(ss))
	for i, s := range ss {
		out[i] = netip.MustParseAddr(s)
	}
	return out
}

func TestEdgeOrder(t *testing.T) {
	seen := map[string]string{"18.0.0.5": "NL", "18.0.0.2": "UA", "18.0.0.9": "", "18.0.0.1": "NL", "18.0.0.7": "GB"}
	var probes atomic.Int32
	c := newEdgeChecker()
	c.setChecks([]config.SmartDNSCheck{testCheck})
	c.probe = func(_ context.Context, _ *egress, ip netip.Addr, ck config.SmartDNSCheck) string {
		probes.Add(1)
		if ck.Field != "countryCode" {
			t.Errorf("wrong check %+v", ck)
		}
		return seen[ip.String()]
	}
	e := &egress{exit: "nl", country: "NL"}
	in := addrs("18.0.0.2", "18.0.0.9", "18.0.0.5", "18.0.0.7", "18.0.0.1")
	got := c.order(context.Background(), e, "tv.stream.example", in)
	want := addrs("18.0.0.1", "18.0.0.5", "18.0.0.9", "18.0.0.2", "18.0.0.7")
	if !slices.Equal(got, want) {
		t.Fatalf("order = %v, want %v (good sorted, unknown, bad)", got, want)
	}
	if probes.Load() != 5 {
		t.Errorf("probes = %d, want 5", probes.Load())
	}
	// Results are cached: same order, no new probes.
	if got := c.order(context.Background(), e, "cdn.stream.example", in); !slices.Equal(got, want) {
		t.Errorf("second order = %v", got)
	}
	if probes.Load() != 5 {
		t.Errorf("results not cached: %d probes", probes.Load())
	}
	// Hosts without a check keep the resolver's order.
	if got := c.order(context.Background(), e, "other.example", in); !slices.Equal(got, in) {
		t.Errorf("unchecked host reordered: %v", got)
	}
	country, msg := c.summary("nl")
	if country != "NL" || msg == "" {
		t.Errorf("summary = %q, %q", country, msg)
	}
	if len(c.snapshot()) != 5 {
		t.Errorf("snapshot has %d results", len(c.snapshot()))
	}
}

func TestProbeEdge(t *testing.T) {
	var gotPath, gotHost string
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotHost = r.URL.RequestURI(), r.Host
		fmt.Fprint(w, `{"userLocation":[{"countryCode" : "NL","x":1}]}`)
	}))
	srv.TLS = &tls.Config{}
	srv.StartTLS()
	defer srv.Close()
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())

	// Point the probe at the test server: the check host is example.com
	// (in the test certificate) and the edge IP is 127.0.0.1.
	_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	ck := testCheck
	ck.Host = "example.com"
	orig := probeTLSConfig
	probeTLSConfig = func(host string) *tls.Config { return &tls.Config{ServerName: host, RootCAs: pool} }
	defer func() { probeTLSConfig = orig }()
	origPort := probePort
	probePort = port
	defer func() { probePort = origPort }()

	got := probeEdge(context.Background(), &egress{exit: "nl"}, netip.MustParseAddr("127.0.0.1"), ck)
	if got != "NL" {
		t.Fatalf("probe = %q", got)
	}
	if gotHost != "example.com" || len(gotPath) < len(ck.Path)+4 || gotPath[:len(ck.Path)+4] != ck.Path+"?cb=" {
		t.Errorf("request %s %s lacks the cache-buster", gotHost, gotPath)
	}
	// TLS failures count as unknown.
	probeTLSConfig = func(host string) *tls.Config { return &tls.Config{ServerName: host} }
	if got := probeEdge(context.Background(), &egress{exit: "nl"}, netip.MustParseAddr("127.0.0.1"), ck); got != "" {
		t.Errorf("untrusted edge = %q", got)
	}
}

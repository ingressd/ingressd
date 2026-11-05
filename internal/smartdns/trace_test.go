// SPDX-License-Identifier: Apache-2.0

package smartdns

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
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
	ip, cc, err := trace(context.Background(), newEgress(EgressOptions{}), srv.URL)
	if err != nil || ip != "127.0.0.1" || cc != "NL" {
		t.Errorf("%q %q %v", ip, cc, err)
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
	m := New(Options{TraceURL: srv.URL})
	// A direct exit (no VPN) so the trace can reach the test server.
	m.Reconfigure(Plan{Exits: map[string]PlanExit{"nl": {Country: "NL", Egress: &EgressOptions{Public: "198.51.100.6"}}}})
	m.probes.watch(m.state().egress, time.Now())
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
	m.probes.watch(m.state().egress, time.Now())
	time.Sleep(50 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	if hits != 1 {
		t.Errorf("trace hits %d", hits)
	}
}

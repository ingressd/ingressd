// SPDX-License-Identifier: Apache-2.0

package portcatalog

import (
	"slices"
	"testing"
)

func TestCatalogIsClean(t *testing.T) {
	type key struct {
		port  int
		proto string
	}
	risks := []string{"normal", "low", "medium", "high"}
	probes := []string{ProbeHTTP, ProbeTLS, ProbeTCP, ProbeUDP, ProbeDNS}
	seen := map[key]bool{}
	apps := map[string]int{}
	last := key{}
	for _, e := range All() {
		k := key{e.Port, e.Proto}
		if seen[k] {
			t.Errorf("%d/%s listed twice", e.Port, e.Proto)
		}
		seen[k] = true
		if e.Port < last.port || (e.Port == last.port && e.Proto < last.proto) {
			t.Errorf("%d/%s is out of order", e.Port, e.Proto)
		}
		last = k
		if e.Port < 1 || e.Port > 65535 || (e.Proto != "tcp" && e.Proto != "udp") {
			t.Errorf("bad port %d/%s", e.Port, e.Proto)
		}
		if !slices.Contains(risks, e.Risk) || !slices.Contains(probes, e.Probe) {
			t.Errorf("%d/%s: risk %q, probe %q", e.Port, e.Proto, e.Risk, e.Probe)
		}
		if len(e.Apps) == 0 {
			t.Errorf("%d/%s has no apps", e.Port, e.Proto)
		}
		for _, a := range e.Apps {
			if a.Name == "" || a.Preset == "" || a.Category == "" {
				t.Errorf("%d/%s: incomplete app %+v", e.Port, e.Proto, a)
			}
			if p, dup := apps[a.Preset]; dup {
				t.Errorf("preset %s is on ports %d and %d", a.Preset, p, e.Port)
			}
			apps[a.Preset] = e.Port
		}
	}
}

func TestLANPorts(t *testing.T) {
	ports := LANPorts()
	// The ports scanned before the catalogue existed.
	for _, p := range []int{80, 443, 3000, 5000, 5001, 8000, 8006, 8080, 8081, 8123, 8443, 8888, 9000, 9090, 32400} {
		if !slices.Contains(ports, p) {
			t.Errorf("port %d is no longer scanned", p)
		}
	}
	for _, p := range []int{53, 22, 5432, 25565} {
		if slices.Contains(ports, p) {
			t.Errorf("port %d must not be scanned across the LAN", p)
		}
	}
}

func TestTLSPorts(t *testing.T) {
	tls := TLSPorts()
	for _, p := range []int{443, 5001, 8006, 8443, 9443} {
		if !tls[p] {
			t.Errorf("port %d lost HTTPS first", p)
		}
	}
	if tls[80] {
		t.Error("port 80 tried with HTTPS first")
	}
}

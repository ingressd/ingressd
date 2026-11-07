// SPDX-License-Identifier: Apache-2.0

// Package portcatalog lists the ports well-known self-hosted apps and game
// servers use. The connector's LAN scan probes the entries marked lan_scan.
package portcatalog

import (
	_ "embed"
	"encoding/json"
	"fmt"
)

// Probe says how a service is recognised.
const (
	ProbeHTTP = "http"
	ProbeTLS  = "tls"
	ProbeTCP  = "tcp"
	ProbeUDP  = "udp"
	ProbeDNS  = "dns"
)

// App is one app known to use a port.
type App struct {
	Name     string `json:"name"`
	Preset   string `json:"preset"`
	Category string `json:"category"`
}

// Entry is one port. Apps sharing a port share an entry, which takes the
// highest risk of them.
type Entry struct {
	Port    int    `json:"port"`
	Proto   string `json:"proto"`
	Probe   string `json:"probe"`
	LANScan bool   `json:"lan_scan"`
	Risk    string `json:"risk"`
	Apps    []App  `json:"apps"`
}

//go:embed catalog.json
var catalogJSON []byte

var entries = mustParse(catalogJSON)

func mustParse(b []byte) []Entry {
	var out []Entry
	if err := json.Unmarshal(b, &out); err != nil {
		panic(fmt.Sprintf("portcatalog: %v", err))
	}
	return out
}

// All returns every entry, by port and then protocol.
func All() []Entry {
	return append([]Entry(nil), entries...)
}

// LANPorts returns the TCP ports the LAN scan probes. The scan recognises
// web services only, so entries with other probes are left out.
func LANPorts() []int {
	var out []int
	for _, e := range entries {
		if e.LANScan && e.Proto == "tcp" && (e.Probe == ProbeHTTP || e.Probe == ProbeTLS) {
			out = append(out, e.Port)
		}
	}
	return out
}

// TLSPorts returns the TCP ports to try with HTTPS first.
func TLSPorts() map[int]bool {
	out := map[int]bool{}
	for _, e := range entries {
		if e.Proto == "tcp" && e.Probe == ProbeTLS {
			out[e.Port] = true
		}
	}
	return out
}

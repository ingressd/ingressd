// SPDX-License-Identifier: Apache-2.0

package proto

import "time"

// LAN service discovery (rev1). Additive to the phase 5 protocol:
//
//  1. A connector that supports discovery (and was not started with
//     --no-discovery) adds "discover=<last handled request id>" to every poll
//     (DiscoverParam; empty before its first scan). The parameter's presence
//     is the capability flag: edges never send discovery requests to
//     connectors that omit it, so old connectors never see them.
//  2. To request a scan the edge answers the poll at once with 200 and the
//     current TunnelConfig with DiscoverID set to a new request id, even when
//     the revision is unchanged. DiscoverID is not part of the revision and
//     never causes a link restart.
//  3. The connector scans its directly connected private IPv4 subnets and
//     posts a DiscoveryReport (same ID) to DiscoveryPath. The edge stores it
//     and clears the pending request; in managed mode the node agent forwards
//     it to the panel as nodeproto.Discovery.
const (
	DiscoveryPath = "/.ingressd/connector/discovery"
	DiscoverParam = "discover"
)

// DiscoveryReport is posted by the connector after a scan.
type DiscoveryReport struct {
	// ID echoes TunnelConfig.DiscoverID.
	ID       string    `json:"id"`
	Started  time.Time `json:"started"`
	Finished time.Time `json:"finished"`
	// Subnets are the prefixes that were scanned (after the /22 cap).
	Subnets  []string            `json:"subnets,omitempty"`
	Services []DiscoveredService `json:"services"`
	// Error is set when the scan could not run (e.g. no private subnets).
	Error string `json:"error,omitempty"`
}

// DiscoveredService is one web service found on the LAN. It mirrors
// nodeproto.DiscoveredService (this package stays dependency-free).
type DiscoveredService struct {
	Address string `json:"address"` // IPv4
	Port    int    `json:"port"`
	Scheme  string `json:"scheme"`           // http | https
	Title   string `json:"title,omitempty"`  // HTML <title>
	Server  string `json:"server,omitempty"` // Server header
}

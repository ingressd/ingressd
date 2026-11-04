// SPDX-License-Identifier: Apache-2.0

// Package proto holds the wire types shared by the edge's connector endpoints
// (internal/connector) and ingressd-connector (internal/connector/client).
// It has no dependencies so the connector binary stays small and portable.
package proto

import (
	"net/http"
	"strings"
	"time"
)

// Paths on the edge's admin hostname.
const (
	EnrollPath = "/.ingressd/connector/enroll"
	PollPath   = "/.ingressd/connector/poll"
	ReportPath = "/.ingressd/connector/report"
	// TunnelPathPrefix + <tunnel> is the WireGuard-over-WebSocket bridge.
	TunnelPathPrefix = "/.ingressd/tunnel/"

	// MachinePrefix holds every machine endpoint on a node's hostnames.
	MachinePrefix = "/.ingressd/"
	// LegacyMachinePrefix is still served (rewritten to MachinePrefix) for
	// connectors and edges that predate the rename.
	LegacyMachinePrefix = "/.homeedge/" // legacy homeedge name, remove after 2027-01
)

// ServeLegacyPrefix rewrites a request under LegacyMachinePrefix to the same
// path under MachinePrefix and hands it to h (normally the mux it is
// registered on), so old clients keep working.
func ServeLegacyPrefix(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rest, ok := strings.CutPrefix(r.URL.Path, LegacyMachinePrefix)
		if !ok {
			http.NotFound(w, r)
			return
		}
		r2 := r.Clone(r.Context())
		r2.URL.Path = MachinePrefix + rest
		r2.URL.RawPath = ""
		r2.RequestURI = r2.URL.RequestURI()
		h.ServeHTTP(w, r2)
	})
}

// PollWait is how long the edge holds a poll open without changes.
const PollWait = 25 * time.Second

// EnrollRequest is posted by the connector with a one-time token.
type EnrollRequest struct {
	Token     string `json:"token"`
	PublicKey string `json:"public_key"`
	Hostname  string `json:"hostname,omitempty"`
	Version   string `json:"version,omitempty"`
}

// EnrollResponse carries the connector's credential and its tunnel config.
type EnrollResponse struct {
	// Credential authenticates later requests: "Authorization: Bearer
	// <tunnel>.<credential>". The edge stores only its hash.
	Credential string       `json:"credential"`
	Config     TunnelConfig `json:"config"`
}

// TunnelConfig is everything the connector needs to bring up its side.
type TunnelConfig struct {
	Tunnel        string `json:"tunnel"`
	EdgePublicKey string `json:"edge_public_key"`
	// Endpoint is the edge's WireGuard UDP listener, host:port.
	Endpoint string `json:"endpoint"`
	// Address is the site's transit address with prefix, e.g. 10.100.1.2/24.
	Address string `json:"address"`
	// EdgeAddress is the edge's transit address, e.g. 10.100.1.1. The control
	// channel prefers it (over the tunnel) to the public address.
	EdgeAddress string   `json:"edge_address"`
	Subnets     []string `json:"subnets"`
	Keepalive   int      `json:"keepalive"`
	MTU         int      `json:"mtu"`
	// FallbackWS allows WireGuard over WebSocket at WSURL when UDP is blocked.
	FallbackWS bool   `json:"fallback_ws"`
	WSURL      string `json:"ws_url,omitempty"`
	// Transparent lists "tcp/192.168.0.17:25565"-style sources whose replies
	// must leave via the tunnel (transparent L4); TUN mode installs policy
	// routes for them.
	Transparent []string `json:"transparent,omitempty"`
	// Targets are origin host:port pairs the connector tests for reachability.
	Targets []string `json:"targets,omitempty"`
	// Siblings are the site's other edges (multi-PoP). The connector adds
	// each as a WireGuard peer and refreshes the list from any edge.
	Siblings []Sibling `json:"siblings,omitempty"`
	// KeyAuth is the newest IngressdKey header version this edge accepts
	// (KeyAuthV2; 0 = v1 only, an edge from before v2).
	KeyAuth int `json:"key_auth,omitempty"`
	// Revision changes whenever any field above changes.
	Revision string `json:"revision"`
	// DiscoverID, when set in a poll response, asks the connector to scan its
	// LAN and post a DiscoveryReport with this ID (see discovery.go). It is
	// not covered by Revision and is never persisted by the connector.
	DiscoverID string `json:"discover_id,omitempty"`
	// Update, when set in a poll response, offers a release (update.go).
	// Not covered by Revision and never persisted with the config.
	Update *UpdateNotice `json:"update,omitempty"`
}

// Transports a connector can use.
const (
	TransportUDP       = "udp"
	TransportWebSocket = "websocket"
)

// Health is what a connector reports about itself.
type Health struct {
	Time          time.Time `json:"time"`
	Version       string    `json:"version,omitempty"`
	Hostname      string    `json:"hostname,omitempty"`
	Mode          string    `json:"mode"`      // tun | netstack
	Transport     string    `json:"transport"` // udp | websocket
	MTU           int       `json:"mtu"`
	LastHandshake time.Time `json:"last_handshake"`
	RxBytes       int64     `json:"rx_bytes"`
	TxBytes       int64     `json:"tx_bytes"`
	Reachability  []Reach   `json:"reachability,omitempty"`
	// Discovery is true when the connector accepts discovery requests.
	Discovery bool `json:"discovery,omitempty"`
	// OS, Arch and Install (systemd|launchd|windows-service|docker|manual)
	// describe the installation; Update is the state of the last update
	// notice (update.go). Additive.
	OS      string       `json:"os,omitempty"`
	Arch    string       `json:"arch,omitempty"`
	Install string       `json:"install,omitempty"`
	Update  *UpdateState `json:"update,omitempty"`
}

// Reach is the result of one reachability test from the site.
type Reach struct {
	Target  string        `json:"target"`
	OK      bool          `json:"ok"`
	Latency time.Duration `json:"latency,omitempty"`
	Error   string        `json:"error,omitempty"`
}

// Bearer formats the Authorization header value for a credential.
func Bearer(tunnel, credential string) string { return "Bearer " + tunnel + "." + credential }

// ParseBearer splits an Authorization header into tunnel and credential.
func ParseBearer(h string) (tunnel, credential string, ok bool) {
	v, found := strings.CutPrefix(h, "Bearer ")
	if !found {
		return "", "", false
	}
	return strings.Cut(v, ".")
}

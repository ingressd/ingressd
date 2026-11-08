// SPDX-License-Identifier: Apache-2.0

package config

// Smart DNS (docs/rev1/CONNECTOR-SMARTDNS.md). The resolver, relay and VPN
// exits run on the connector; a node only lets its own connector sites
// leave from its public IP (SmartDNS.Exit) and passes each connector site's
// signed Smart DNS config through (Tunnel.SmartDNS).

// SmartDNS is the node's part of Smart DNS.
type SmartDNS struct {
	// Exit, when set, lets the listed connector sites egress from this
	// node's own route (its public IP) for their Smart DNS services.
	Exit *SmartDNSNodeExit `yaml:"exit,omitempty"`
}

// SmartDNSNodeExit is a node exit: no VPN, no routing changes, just the
// node's default route.
type SmartDNSNodeExit struct {
	// Country is the ISO 3166-1 alpha-2 country the node's IP is expected
	// to geolocate to; the exit reports itself down when it does not.
	Country string `yaml:"country"`
	// Sites are the connector tunnels allowed to use the exit.
	Sites []string `yaml:"sites"`
	// Upstream resolves service names from the node's location (default
	// 1.1.1.1, 9.9.9.9).
	Upstream []string `yaml:"upstream,omitempty"`
	// Checks are edge location checks for services on CDNs whose edges
	// geolocate viewers themselves; the panel fills them in from its
	// catalog.
	Checks []SmartDNSCheck `yaml:"checks,omitempty"`
}

// SmartDNSCheck asks a CDN edge which country it places an exit in: an
// HTTPS GET of Path on Host, sent to one edge IP through the exit, whose
// JSON response holds the ISO country code in Field.
type SmartDNSCheck struct {
	// Domains are the service domain suffixes whose upstream IPs are checked.
	Domains []string `yaml:"domains" json:"domains"`
	Host    string   `yaml:"host" json:"host"`
	Path    string   `yaml:"path" json:"path"`
	Field   string   `yaml:"field" json:"field"`
	// CacheBuster, if set, is a query parameter given a random value so
	// CDN-cached endpoints answer for this request.
	CacheBuster string `yaml:"cache_buster,omitempty" json:"cache_buster,omitempty"`
}

// Exit locations of a connector site's exits (SmartDNSSiteExit.At).
const (
	// ExitAtConnector egresses through a VPN config on the connector.
	ExitAtConnector = "connector"
	// ExitAtNode egresses from one of the site's own nodes' public IP.
	ExitAtNode = "node"
	// ExitAtOperator is reserved for exits run by the network operator;
	// it is refused.
	ExitAtOperator = "operator"
)

// SmartDNSSite is a connector site's Smart DNS config. The panel signs it
// (nodeproto.SignedSmartDNS) and nodes hand it to the connector unchanged.
type SmartDNSSite struct {
	// Listen is the connector host's LAN IPv4 address the resolver (53)
	// and relay (80, 443) bind; empty: the address of the interface
	// holding the default route.
	Listen string `json:"listen,omitempty"`
	// Upstream answers every name no service routes (default 1.1.1.1,
	// 9.9.9.9), so the connector can be a home's only DNS server.
	Upstream []string `json:"upstream,omitempty"`
	// FailbackAfter is how long a service's preferred exit must stay
	// healthy before connections move back to it (Go duration, default
	// 5m, at most 1h).
	FailbackAfter string                         `json:"failback_after,omitempty"`
	Services      map[string]SmartDNSSiteService `json:"services"`
	Exits         map[string]SmartDNSSiteExit    `json:"exits"`
	Checks        []SmartDNSCheck                `json:"checks,omitempty"`
}

// SmartDNSSiteService routes its domains (suffix match) through its exits,
// in order of preference. A direct service has no exits: its domains are
// answered by the upstream resolvers and leave through the home connection,
// which carves a subdomain out of a broader service.
type SmartDNSSiteService struct {
	Domains []string `json:"domains"`
	Exits   []string `json:"exits"`
	Direct  bool     `json:"direct,omitempty"`
	Enabled *bool    `json:"enabled,omitempty"` // default true
	Catalog string   `json:"catalog,omitempty"` // informational
}

// SmartDNSSiteExit is one egress point of a connector site.
type SmartDNSSiteExit struct {
	At      string `json:"at"`             // ExitAtConnector or ExitAtNode
	Node    string `json:"node,omitempty"` // at node: the node id (one of the site's edges)
	Country string `json:"country"`
	// VPN is the WireGuard .conf of a connector exit, age-encrypted to the
	// connector's recipient (ASCII armor), so no node can read it.
	VPN string `json:"vpn,omitempty"`
}

// IsEnabled reports whether a service is enabled (default true).
func (s SmartDNSSiteService) IsEnabled() bool { return s.Enabled == nil || *s.Enabled }

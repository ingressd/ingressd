// SPDX-License-Identifier: Apache-2.0

package config

// Smart DNS and node mesh configuration (docs/rev1/ARCHITECTURE.md §7).
// The panel compiles these sections into each node's config; the smartdns
// work stream owns their validation (validateSmartDNS / validateMesh).

// SmartDNS runs the resolver and SNI relay on this node for its sites.
type SmartDNS struct {
	Enabled bool `yaml:"enabled"`
	// Listen are the addresses the resolver (:53) and relay (:80/:443)
	// bind; default: every tunnel's edge transit address, so they are only
	// reachable from the homes, never from the internet.
	Listen []string `yaml:"listen"`
	// Upstream resolvers for names that are not routed (default 1.1.1.1, 9.9.9.9).
	Upstream []string `yaml:"upstream"`
	// Services route their domains through an exit, keyed by service name.
	Services map[string]SmartDNSService `yaml:"services"`
	// Exits are egress points, keyed by exit name.
	Exits map[string]SmartDNSExit `yaml:"exits"`
	// Checks are edge location checks for services on CDNs whose edges
	// geolocate viewers themselves (see internal/smartdns/edgecheck.go).
	// The panel fills them in from its service catalog.
	Checks []SmartDNSCheck `yaml:"checks"`
	// FailbackAfter is how long a service's preferred exit must stay
	// healthy before connections move back to it from a fallback exit
	// (default 5m, 0 = at once, at most 1h).
	FailbackAfter *Duration `yaml:"failback_after,omitempty"`
}

// SmartDNSCheck asks a CDN edge which country it places an exit in: an
// HTTPS GET of Path on Host, sent to one edge IP through the exit, whose
// JSON response holds the ISO country code in Field.
type SmartDNSCheck struct {
	// Domains are the service domain suffixes whose upstream IPs are checked.
	Domains []string `yaml:"domains"`
	Host    string   `yaml:"host"`
	Path    string   `yaml:"path"`
	Field   string   `yaml:"field"`
	// CacheBuster, if set, is a query parameter given a random value so
	// CDN-cached endpoints answer for this request.
	CacheBuster string `yaml:"cache_buster,omitempty"`
}

type SmartDNSService struct {
	Domains []string `yaml:"domains"` // suffix match: "example.com" covers "tv.example.com"
	// Exit is the single-exit form of Exits, kept for older panels; it is
	// normalised into Exits when the config is loaded.
	Exit string `yaml:"exit,omitempty"`
	// Exits are the service's exits in order of preference (1 to 4, all in
	// the same country): new connections use the first healthy one.
	Exits   []string `yaml:"exits,omitempty"`
	Enabled *bool    `yaml:"enabled"` // default true
	Catalog string   `yaml:"catalog"` // catalog entry id the domains came from, informational
}

type SmartDNSExit struct {
	// Node is the mesh peer (node id) that egresses, or "self".
	Node    string `yaml:"node"`
	Country string `yaml:"country"` // ISO 3166-1 alpha-2, expected egress country
	// VPN optionally names a secret (secret://name) holding a WireGuard
	// .conf; the exit node egresses through that tunnel instead of its own
	// IP. Only used on the exit node itself.
	VPN string `yaml:"vpn"`
}

// Mesh connects the nodes of one org over WireGuard.
type Mesh struct {
	// Address is this node's mesh address with prefix, e.g. 10.255.0.1/16.
	Address    string              `yaml:"address"`
	ListenPort int                 `yaml:"listen_port"` // default 51900
	Peers      map[string]MeshPeer `yaml:"peers"`       // keyed by node id
}

type MeshPeer struct {
	PublicKey string `yaml:"public_key"`
	Endpoint  string `yaml:"endpoint"` // host:port of the peer's mesh listener
	Address   string `yaml:"address"`  // peer's mesh address (/32)
	Name      string `yaml:"name"`     // human name, informational
}

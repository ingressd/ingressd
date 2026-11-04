// SPDX-License-Identifier: Apache-2.0

// Package config defines config.yaml, the single source of truth for an edge.
//
// Sections that later phases own (access, WAF, L4, alerts, ...) are kept as
// raw yaml.Node values for now so the full example config parses with strict
// field checking; they become typed as each phase lands.
package config

import (
	"fmt"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	TunnelWireGuard = "wireguard"

	SiteRouter    = "router"
	SiteConnector = "connector"

	ExposurePublic      = "public"
	ExposureTunnelOnly  = "tunnel_only"
	ExposureIPAllowlist = "ip_allowlist"

	FailbackAuto   = "auto"
	FailbackManual = "manual"

	OriginActive   = "active"
	OriginDraining = "draining"
	OriginDisabled = "disabled"

	HealthHTTP = "http"
	HealthTCP  = "tcp"

	// MaxTunnelNameLen keeps interface names within Linux's 15-byte limit.
	MaxTunnelNameLen = 12
)

// InterfaceName is the edge's WireGuard interface for a tunnel.
func InterfaceName(tunnel string) string { return "ix-" + tunnel }

// Config is the root of config.yaml.
type Config struct {
	Version       int                     `yaml:"version"`
	Edge          Edge                    `yaml:"edge"`
	Email         Email                   `yaml:"email"`
	Access        *Access                 `yaml:"access"`
	Certificates  Certificates            `yaml:"certificates"`
	Tunnels       map[string]Tunnel       `yaml:"tunnels"`
	Groups        map[string]Group        `yaml:"groups"`
	ServiceTokens map[string]ServiceToken `yaml:"service_tokens"`
	Policies      map[string]Policy       `yaml:"policies"`
	Pools         map[string]Pool         `yaml:"pools"`
	Apps          map[string]App          `yaml:"apps"`
	L4            L4Services              `yaml:"l4"`
	Admins        []AdminUser             `yaml:"admins"`
	Alerts        Alerts                  `yaml:"alerts"`
	Security      Security                `yaml:"security"`
	Logging       Logging                 `yaml:"logging"`
	Backups       Backups                 `yaml:"backups"`
	SmartDNS      *SmartDNS               `yaml:"smartdns"`
	Mesh          *Mesh                   `yaml:"mesh"`
}

type Edge struct {
	Name       string `yaml:"name"`
	PublicIPv4 string `yaml:"public_ipv4"`
	PublicIPv6 string `yaml:"public_ipv6"`
	// SSHPort is always allowed through the managed firewall. Default 22.
	SSHPort int `yaml:"ssh_port"`
	// ManageFirewall lets ingressd own the host's nftables input/forward
	// policy. Default true; set false to manage the firewall yourself.
	ManageFirewall *bool     `yaml:"manage_firewall"`
	Admin          Admin     `yaml:"admin"`
	ACME           ACME      `yaml:"acme"`
	GeoIP          *GeoIP    `yaml:"geoip"`
	CrowdSec       *CrowdSec `yaml:"crowdsec"`
}

// FirewallManaged reports whether ingressd owns the host firewall.
func (e Edge) FirewallManaged() bool { return e.ManageFirewall == nil || *e.ManageFirewall }

// Admin controls how the control panel itself is exposed.
type Admin struct {
	Hostname    string   `yaml:"hostname"`
	Exposure    string   `yaml:"exposure"`
	IPAllowlist []string `yaml:"ip_allowlist"`
}

type ACME struct {
	Email       string       `yaml:"email"`
	CA          string       `yaml:"ca"`
	DNSProvider *DNSProvider `yaml:"dns_provider"`
}

type Certificates struct {
	// Wildcards are issued up front via DNS-01 and used for matching hosts.
	Wildcards []string `yaml:"wildcards"`
	OriginCA  OriginCA `yaml:"origin_ca"`
}

type DNSProvider struct {
	Type     string `yaml:"type"`
	APIToken string `yaml:"api_token"`
}

// Tunnel is a WireGuard link to one site. The site always initiates.
type Tunnel struct {
	Type       string   `yaml:"type"`
	Site       string   `yaml:"site"`
	Vendor     string   `yaml:"vendor"`
	ListenPort int      `yaml:"listen_port"`
	Transit    string   `yaml:"transit"`
	Subnets    []string `yaml:"subnets"`
	// VirtualPrefix remaps Subnets to a unique range on the edge, for sites
	// whose LANs overlap. Empty means no remapping.
	VirtualPrefix string `yaml:"virtual_prefix"`
	Keepalive     int    `yaml:"keepalive"`
	PublicKey     string `yaml:"public_key"`
	FallbackWS    bool   `yaml:"fallback_ws"`
	// SiteDNS goes in the generated site config's DNS line. ingressd does not
	// use it (only edge traffic enters the tunnel), but some importers such
	// as UniFi's require one. Default 1.1.1.1.
	SiteDNS string `yaml:"site_dns"`
	// Siblings are the same site's tunnels to other nodes (multi-PoP). A
	// connector learns them from this node and links to every edge; this
	// node never dials them.
	Siblings []TunnelSibling `yaml:"siblings"`
}

// TunnelSibling is one other node the tunnel's site is attached to.
type TunnelSibling struct {
	Node string `yaml:"node"`
	// Endpoint is that node's WireGuard listener for the site, host:port.
	Endpoint      string `yaml:"endpoint"`
	EdgePublicKey string `yaml:"edge_public_key"`
	// Transit is that attachment's network (edge .1, site .2).
	Transit string `yaml:"transit"`
	// WSURL is that node's WireGuard-over-WebSocket URL (connector sites).
	WSURL string `yaml:"ws_url"`
}

// DefaultSiteDNS is written to site configs when site_dns is unset.
const DefaultSiteDNS = "1.1.1.1"

type Pool struct {
	Steering     string       `yaml:"steering"`
	Sticky       *Sticky      `yaml:"sticky"`
	Failback     string       `yaml:"failback"`
	FailbackHold Duration     `yaml:"failback_hold"`
	Health       *HealthCheck `yaml:"health"`
	Origins      []Origin     `yaml:"origins"`
	Fallback     string       `yaml:"fallback"`
}

type Sticky struct {
	Cookie string   `yaml:"cookie"`
	TTL    Duration `yaml:"ttl"`
}

type HealthCheck struct {
	Type           string   `yaml:"type"`
	Path           string   `yaml:"path"`
	Method         string   `yaml:"method"` // GET (default) or HEAD
	Host           string   `yaml:"host"`
	Interval       Duration `yaml:"interval"`
	Timeout        Duration `yaml:"timeout"`
	ExpectStatus   []int    `yaml:"expect_status"`
	ExpectBody     string   `yaml:"expect_body"`
	UnhealthyAfter int      `yaml:"unhealthy_after"`
	HealthyAfter   int      `yaml:"healthy_after"`
}

// Origin is one upstream in a pool. An empty Tunnel means a direct origin.
type Origin struct {
	Name     string `yaml:"name"`
	Tunnel   string `yaml:"tunnel"`
	Address  string `yaml:"address"`
	Weight   int    `yaml:"weight"`
	Priority int    `yaml:"priority"`
	State    string `yaml:"state"`
}

// App is a published HTTP application. It uses either Pool, or the
// Origin+Tunnel shorthand for a single-origin pool.
type App struct {
	Hosts  []string `yaml:"hosts"`
	Pool   string   `yaml:"pool"`
	Origin string   `yaml:"origin"`
	Tunnel string   `yaml:"tunnel"`

	Headers   *Headers   `yaml:"headers"`
	Proxy     *Proxy     `yaml:"proxy"`
	Redirects []Redirect `yaml:"redirects"`

	// Access lists policy names; the first matching policy wins. Paths
	// override it for matching request paths.
	Access []string   `yaml:"access"`
	Paths  []PathRule `yaml:"paths"`
	// LoginMethods are the sign-in methods the portal offers for this app:
	// email (the emailed one-time code) and any of access.providers.
	// Default: [email].
	LoginMethods []string `yaml:"login_methods,omitempty"`

	TLS          *AppTLS         `yaml:"tls"`
	WAF          *WAF            `yaml:"waf"`
	RateLimit    []RateLimitRule `yaml:"rate_limit"`
	BotChallenge *BotChallenge   `yaml:"bot_challenge"`
	Security     *Security       `yaml:"security"`
	Cache        *Cache          `yaml:"cache"`
	AlwaysOnline *AlwaysOnline   `yaml:"always_online"`
}

type Headers struct {
	// Preset adds standard security response headers: none, basic or strict.
	Preset   string     `yaml:"preset"`
	Request  *HeaderOps `yaml:"request"`
	Response *HeaderOps `yaml:"response"`
}

type HeaderOps struct {
	Set    map[string]string `yaml:"set"`
	Delete []string          `yaml:"delete"`
}

type Proxy struct {
	Websockets *bool    `yaml:"websockets"` // informational; Caddy always proxies upgrades
	MaxBody    string   `yaml:"max_body"`   // e.g. 512MB
	Timeout    Duration `yaml:"timeout"`
}

// Redirect sends every request for From (one of the app's hosts) to To,
// keeping the path and query.
type Redirect struct {
	From string `yaml:"from"`
	To   string `yaml:"to"`
	Code int    `yaml:"code"`
}

// Duration is a time.Duration written as a Go duration string ("10s", "2m").
type Duration time.Duration

func (d *Duration) UnmarshalYAML(n *yaml.Node) error {
	var s string
	if err := n.Decode(&s); err != nil {
		return err
	}
	v, err := ParseDuration(s)
	if err != nil {
		return fmt.Errorf("line %d: invalid duration %q", n.Line, s)
	}
	*d = Duration(v)
	return nil
}

func (d Duration) MarshalYAML() (any, error) {
	return time.Duration(d).String(), nil
}

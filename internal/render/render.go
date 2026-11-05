// SPDX-License-Identifier: Apache-2.0

// Package render turns a validated config into the concrete state each
// backend needs: Caddy JSON, an nftables ruleset and kernel network state.
// It is pure (no I/O), so its output can be diffed and golden-tested.
package render

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"maps"
	"net/netip"
	"slices"

	"github.com/ingressd/ingressd/pkg/config"
)

// Resolver resolves secret://name references.
type Resolver interface {
	Resolve(v string) (string, error)
}

// Keys supplies WireGuard keys (base64) for each tunnel.
type Keys interface {
	EdgePrivate(tunnel string) (string, error)
	SitePublic(tunnel string) (string, error)
}

type Options struct {
	// AdminListen is Caddy's admin address, e.g. unix//run/ingressd/caddy-admin.sock.
	AdminListen string
	// StorageDir holds Caddy's certificates and ACME accounts.
	StorageDir string
	// StorageSocket, when set (managed mode), selects the shared storage
	// module caddy.storage.ingressd instead of file_system: certificates live
	// in the panel, shared by the org's nodes, reached through serve's
	// storage relay on this unix socket. StorageDir becomes the module's
	// local cache (and keeps the node-local internal CA under pki/).
	StorageSocket string
	// StateDir is the control plane state directory (cache store, snapshots).
	StateDir string
	// ControlSocket is the control plane's HTTP unix socket (see ControlHosts).
	ControlSocket string
	// AccessLogSocket receives Caddy's JSON access logs (see observe.go).
	AccessLogSocket string
	// HTTPPort and HTTPSPort override 80/443 (tests only).
	HTTPPort, HTTPSPort int
	// ExtraInputTCP and ExtraInputUDP are host-local ports the managed
	// firewall also accepts (INGRESSD_FIREWALL_ALLOW_TCP/_UDP), e.g. a panel
	// and its edge DNS sharing the host.
	ExtraInputTCP, ExtraInputUDP []int
	// MachineHost is the node's own hostname or public IP (managed mode,
	// rev1): it serves the /.ingressd/ machine endpoints like the admin
	// hostname. A bare IP gets a certificate from Caddy's internal CA.
	MachineHost string
	// Security describes GeoIP databases and the state dir (see security.go).
	Security SecurityOptions
}

// Plan is everything needed to bring the edge to the configured state.
type Plan struct {
	Caddy   json.RawMessage `json:"caddy"`
	NFT     string          `json:"nft"`
	Network Network         `json:"network"`
}

type Network struct {
	Interfaces []Interface `json:"interfaces"`
	Routes     []Route     `json:"routes"`
	Rules      []Rule      `json:"rules"`
	// NoRPFilter lists interfaces whose replies come from addresses that are
	// not in the main routing table (remapped tunnels), so reverse-path
	// filtering must be off for them.
	NoRPFilter []string `json:"no_rp_filter,omitempty"`
	// IPForward enables net.ipv4.ip_forward (kernel-forwarded L4 services).
	// It is never switched off again, since other software may rely on it.
	IPForward bool `json:"ip_forward,omitempty"`
	// Shapes are the realms' bandwidth caps (shape.go).
	Shapes []Shape `json:"shapes,omitempty"`
}

type Interface struct {
	Name       string `json:"name"`
	Address    string `json:"address"`
	ListenPort int    `json:"listen_port"`
	MTU        int    `json:"mtu"`
	PrivateKey string `json:"private_key"`
	Peers      []Peer `json:"peers"`
}

type Peer struct {
	PublicKey  string   `json:"public_key"`
	AllowedIPs []string `json:"allowed_ips"`
	// Endpoint, Keepalive and PresharedKey are used by mesh and VPN peers
	// (tunnel peers always dial the edge).
	Endpoint     string `json:"endpoint,omitempty"`
	Keepalive    int    `json:"keepalive,omitempty"`
	PresharedKey string `json:"preshared_key,omitempty"`
}

// Route is a device route; Table 0 means the main table.
type Route struct {
	Dst   string `json:"dst"`
	Dev   string `json:"dev"`
	Table int    `json:"table,omitempty"`
}

type Rule struct {
	Priority int `json:"priority"`
	Mark     int `json:"mark"`
	Table    int `json:"table"`
}

const (
	// Policy-routing rules in this priority range belong to ingressd.
	RulePriorityBase = 10000
	RulePriorityMax  = 10999
	// TableBase is the first routing table (and fwmark) used for remapped
	// tunnels (see config.Config.TunnelTable).
	TableBase  = config.TunnelTableMin
	DefaultMTU = 1420
)

// TunnelRulePriority is the policy-routing rule priority of a remapped
// tunnel's table. It follows from the table number alone, so explicit tables
// keep their rules stable too, below the VPN exits' range.
func TunnelRulePriority(table int) int { return RulePriorityBase + table - TableBase }

// Render produces the plan for cfg, which must already be valid.
func Render(cfg *config.Config, res Resolver, keys Keys, opts Options) (*Plan, error) {
	// An app may otherwise take over the machine host (see controlHosts),
	// and with realms that would hand one tenant the node's own endpoints.
	if m := machineHost(cfg, opts); len(cfg.Realms) > 0 && m != "" && appHost(cfg, m) {
		return nil, fmt.Errorf("an app claims the node's machine host %s, which realms may not", m)
	}
	net, err := renderNetwork(cfg, keys)
	if err != nil {
		return nil, err
	}
	if err := renderSmartDNSNetwork(cfg, res, &net); err != nil {
		return nil, err
	}
	caddy, err := renderCaddy(cfg, res, opts)
	if err != nil {
		return nil, err
	}
	return &Plan{Caddy: caddy, NFT: renderNFT(cfg, opts.ExtraInputTCP, opts.ExtraInputUDP), Network: net}, nil
}

// EdgeAddr is the edge's address in a transit network (first host).
func EdgeAddr(transit netip.Prefix) netip.Addr { return transit.Masked().Addr().Next() }

// SiteAddr is the site's address in a transit network (second host).
func SiteAddr(transit netip.Prefix) netip.Addr { return EdgeAddr(transit).Next() }

// Virtual maps a real site address to the address the edge uses for it,
// which differs only for tunnels with a virtual_prefix.
func Virtual(t config.Tunnel, a netip.Addr) netip.Addr {
	if t.VirtualPrefix == "" || len(t.Subnets) != 1 {
		return a
	}
	sub, err1 := netip.ParsePrefix(t.Subnets[0])
	vp, err2 := netip.ParsePrefix(t.VirtualPrefix)
	if err1 != nil || err2 != nil || !a.Is4() || !sub.Contains(a) {
		return a
	}
	off := u32(a) - u32(sub.Masked().Addr())
	return fromU32(u32(vp.Masked().Addr()) + off)
}

func u32(a netip.Addr) uint32 {
	b := a.As4()
	return binary.BigEndian.Uint32(b[:])
}

func fromU32(v uint32) netip.Addr {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	return netip.AddrFrom4(b)
}

func sortedKeys[V any](m map[string]V) []string { return slices.Sorted(maps.Keys(m)) }

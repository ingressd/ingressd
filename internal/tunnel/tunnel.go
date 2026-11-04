// SPDX-License-Identifier: Apache-2.0

// Package tunnel manages WireGuard keys and produces site configurations.
package tunnel

import (
	"cmp"
	"fmt"
	"maps"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/ingressd/ingressd/internal/render"
	"github.com/ingressd/ingressd/internal/secrets"
	"github.com/ingressd/ingressd/pkg/config"
)

// EdgeKeyName and SiteKeyName are the secret names holding private keys.
func EdgeKeyName(tunnel string) string { return "wg-" + tunnel + "-edge" }
func SiteKeyName(tunnel string) string { return "wg-" + tunnel + "-site" }

// EnsureKeys generates any missing private keys: always the edge's, and the
// site's when the config does not pin a site public key. It reports whether
// the store changed (and so needs saving).
func EnsureKeys(cfg *config.Config, st *secrets.Store) (bool, error) {
	changed := false
	gen := func(name string) error {
		if _, ok := st.Get(name); ok {
			return nil
		}
		k, err := wgtypes.GeneratePrivateKey()
		if err != nil {
			return err
		}
		changed = true
		return st.Set(name, k.String())
	}
	for name, t := range cfg.Tunnels {
		if err := gen(EdgeKeyName(name)); err != nil {
			return changed, err
		}
		if t.PublicKey == "" {
			if err := gen(SiteKeyName(name)); err != nil {
				return changed, err
			}
		}
	}
	return changed, nil
}

// Keys implements render.Keys from the secrets store.
type Keys struct {
	Cfg   *config.Config
	Store *secrets.Store
	// SiteKey, if set, returns a site public key recorded outside config
	// (connector enrollment), or "". Config public_key takes precedence.
	SiteKey func(tunnel string) string
}

func (k Keys) private(name string) (wgtypes.Key, error) {
	v, ok := k.Store.Get(name)
	if !ok {
		return wgtypes.Key{}, fmt.Errorf("WireGuard key %s is missing (run ingressd apply to generate it)", name)
	}
	return wgtypes.ParseKey(v)
}

func (k Keys) EdgePrivate(tunnel string) (string, error) {
	key, err := k.private(EdgeKeyName(tunnel))
	return key.String(), err
}

func (k Keys) EdgePublic(tunnel string) (string, error) {
	key, err := k.private(EdgeKeyName(tunnel))
	return key.PublicKey().String(), err
}

func (k Keys) SitePublic(tunnel string) (string, error) {
	if pk := k.Cfg.Tunnels[tunnel].PublicKey; pk != "" {
		key, err := wgtypes.ParseKey(pk)
		if err != nil {
			return "", fmt.Errorf("tunnels.%s.public_key: %w", tunnel, err)
		}
		return key.String(), nil
	}
	if k.SiteKey != nil {
		if pk := k.SiteKey(tunnel); pk != "" {
			return pk, nil
		}
	}
	key, err := k.private(SiteKeyName(tunnel))
	return key.PublicKey().String(), err
}

// Format of a generated site config.
const (
	FormatWGQuick = "wg-quick" // [Interface] includes Address/MTU; importable by routers
	FormatWG      = "wg"       // plain `wg setconf` format
)

type SiteOptions struct {
	// Endpoint is the host the site dials; defaults to edge.admin.hostname,
	// then edge.public_ipv4.
	Endpoint string
	Format   string
}

// SiteConfig renders the WireGuard config a site imports.
func SiteConfig(cfg *config.Config, keys Keys, name string, opts SiteOptions) (string, error) {
	t, ok := cfg.Tunnels[name]
	if !ok {
		return "", fmt.Errorf("unknown tunnel %q", name)
	}
	host := cmp.Or(opts.Endpoint, cfg.Edge.Admin.Hostname, cfg.Edge.PublicIPv4)
	if host == "" {
		return "", fmt.Errorf("no endpoint: set edge.admin.hostname or edge.public_ipv4, or pass --endpoint")
	}
	transit, err := netip.ParsePrefix(t.Transit)
	if err != nil {
		return "", err
	}
	edgePub, err := keys.EdgePublic(name)
	if err != nil {
		return "", err
	}
	sitePriv := "<site private key — generated on the site>"
	if t.PublicKey == "" {
		k, err := keys.private(SiteKeyName(name))
		if err != nil {
			return "", err
		}
		sitePriv = k.String()
	}

	var b strings.Builder
	fmt.Fprintf(&b, "# ingressd tunnel %q — import on the site (%s)\n", name, cmp.Or(t.Vendor, t.Site))
	b.WriteString("[Interface]\n")
	fmt.Fprintf(&b, "PrivateKey = %s\n", sitePriv)
	if opts.Format != FormatWG {
		fmt.Fprintf(&b, "Address = %s\n", netip.PrefixFrom(render.SiteAddr(transit), transit.Bits()))
		// Unused by ingressd, but UniFi's importer rejects configs without it.
		fmt.Fprintf(&b, "DNS = %s\n", cmp.Or(t.SiteDNS, config.DefaultSiteDNS))
		fmt.Fprintf(&b, "MTU = %d\n", render.DefaultMTU)
	}
	b.WriteString("\n[Peer]\n")
	fmt.Fprintf(&b, "PublicKey = %s\n", edgePub)
	fmt.Fprintf(&b, "Endpoint = %s\n", net.JoinHostPort(host, strconv.Itoa(t.ListenPort)))
	fmt.Fprintf(&b, "AllowedIPs = %s\n", transit.Masked())
	fmt.Fprintf(&b, "PersistentKeepalive = %d\n", t.Keepalive)
	return b.String(), nil
}

// Status is the live state of one tunnel on the edge.
type Status struct {
	Tunnel        string
	Interface     string
	Up            bool
	Endpoint      string
	LastHandshake time.Time
	RxBytes       int64
	TxBytes       int64
}

// HandshakeTimeout is how old a handshake may be before a tunnel counts as down.
const HandshakeTimeout = 180 * time.Second

// Healthy reports whether the tunnel has had a recent handshake.
func (s Status) Healthy(now time.Time) bool {
	return s.Up && !s.LastHandshake.IsZero() && now.Sub(s.LastHandshake) < HandshakeTimeout
}

// ReadStatus queries the kernel for every configured tunnel.
func ReadStatus(cfg *config.Config) ([]Status, error) {
	c, err := wgctrl.New()
	if err != nil {
		return nil, err
	}
	defer c.Close()
	var out []Status
	for _, name := range sortedNames(cfg) {
		s := Status{Tunnel: name, Interface: config.InterfaceName(name)}
		dev, err := c.Device(s.Interface)
		if err == nil {
			s.Up = true
			for _, p := range dev.Peers {
				if p.Endpoint != nil {
					s.Endpoint = p.Endpoint.String()
				}
				s.LastHandshake = p.LastHandshakeTime
				s.RxBytes, s.TxBytes = p.ReceiveBytes, p.TransmitBytes
			}
		}
		out = append(out, s)
	}
	return out, nil
}

func sortedNames(cfg *config.Config) []string { return slices.Sorted(maps.Keys(cfg.Tunnels)) }

// SPDX-License-Identifier: Apache-2.0

// Package wgconf parses WireGuard .conf files as VPN providers hand them out
// (wg-quick format: [Interface] with Address/DNS/MTU, one [Peer]).
//
// A Smart DNS exit only needs a subset: the interface key and IPv4 address,
// the tunnel's DNS servers and MTU, and the one peer. wg-quick-only keys
// (Table, PostUp, SaveConfig...) are ignored: the node never runs wg-quick and
// never changes its own default route or resolver for a VPN exit. The same
// rules are implemented in the panel's browser-side parser; keep them in
// step.
package wgconf

import (
	"bufio"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

// DefaultKeepalive is applied when a config has no PersistentKeepalive: VPN
// providers drop idle NAT mappings, and an exit is idle most of the time.
const DefaultKeepalive = 25

// Config is the subset of a wg-quick file a VPN exit needs.
type Config struct {
	PrivateKey string
	Address    netip.Prefix   // first IPv4 address (used)
	Address6   netip.Prefix   // first IPv6 address (informational: exits egress over IPv4)
	DNS        []netip.Addr   // IPv4 DNS servers inside the tunnel
	DNS6       []netip.Addr   // IPv6 DNS servers (informational)
	MTU        int            // 0 = default
	AllowedIPs []netip.Prefix // as written; the node routes only marked traffic anyway
	Peer       Peer
}

type Peer struct {
	PublicKey    string
	PresharedKey string
	Endpoint     string // host:port as written (host may be a name)
	Keepalive    int    // 0 when the file has none; see EffectiveKeepalive
}

// FullTunnel reports whether AllowedIPs covers all of IPv4 (0.0.0.0/0 or
// the 0.0.0.0/1 + 128.0.0.0/1 pair). Exits always route every destination
// through the tunnel, so a split-tunnel config is still usable, but its
// provider may drop traffic outside AllowedIPs.
func (c *Config) FullTunnel() bool {
	half := 0
	for _, p := range c.AllowedIPs {
		switch p.String() {
		case "0.0.0.0/0":
			return true
		case "0.0.0.0/1", "128.0.0.0/1":
			half++
		}
	}
	return half == 2
}

// EffectiveKeepalive is the keepalive the node applies.
func (p Peer) EffectiveKeepalive() int {
	if p.Keepalive > 0 {
		return p.Keepalive
	}
	return DefaultKeepalive
}

// EndpointHost returns the endpoint's host and port.
func (p Peer) EndpointHost() (host, port string) {
	h, pt, _ := net.SplitHostPort(p.Endpoint)
	return h, pt
}

// Parse reads a wg-quick .conf.
func Parse(text string) (*Config, error) {
	text = strings.TrimPrefix(text, "\ufeff")
	if looksLikeOpenVPN(text) {
		return nil, errors.New("this is an OpenVPN file, not a WireGuard config; download the WireGuard version from your VPN provider")
	}
	c := &Config{}
	section := ""
	peers, ifaces := 0, 0
	sc := bufio.NewScanner(strings.NewReader(text))
	sc.Buffer(make([]byte, 64<<10), 64<<10)
	for n := 1; sc.Scan(); n++ {
		line := sc.Text()
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "[") {
			section = strings.ToLower(strings.Trim(line, "[] "))
			switch section {
			case "peer":
				peers++
			case "interface":
				ifaces++
			default:
				return nil, fmt.Errorf("line %d: unknown section [%s]", n, section)
			}
			continue
		}
		k, val, ok := strings.Cut(line, "=")
		if !ok {
			return nil, fmt.Errorf("line %d: expected key = value", n)
		}
		if section == "" {
			return nil, fmt.Errorf("line %d: %q outside a section; a WireGuard config starts with [Interface]", n, strings.TrimSpace(k))
		}
		k, val = strings.ToLower(strings.TrimSpace(k)), strings.TrimSpace(val)
		switch section + "." + k {
		case "interface.privatekey":
			c.PrivateKey = val
		case "interface.address":
			for _, a := range splitList(val) {
				p, err := netip.ParsePrefix(a)
				if err != nil {
					ad, err2 := netip.ParseAddr(a)
					if err2 != nil {
						return nil, fmt.Errorf("line %d: bad Address %q", n, a)
					}
					p = netip.PrefixFrom(ad, ad.BitLen())
				}
				switch {
				case p.Addr().Is4() && !c.Address.IsValid():
					c.Address = p
				case p.Addr().Is6() && !c.Address6.IsValid():
					c.Address6 = p
				}
			}
		case "interface.dns":
			for _, a := range splitList(val) {
				if ad, err := netip.ParseAddr(a); err == nil {
					if ad.Is4() {
						c.DNS = append(c.DNS, ad)
					} else {
						c.DNS6 = append(c.DNS6, ad)
					}
				} // search domains are ignored
			}
		case "interface.mtu":
			m, err := strconv.Atoi(val)
			if err != nil || m < 576 || m > 9000 {
				return nil, fmt.Errorf("line %d: bad MTU %q (expected 576-9000)", n, val)
			}
			c.MTU = m
		case "peer.publickey":
			c.Peer.PublicKey = val
		case "peer.presharedkey":
			c.Peer.PresharedKey = val
		case "peer.endpoint":
			c.Peer.Endpoint = val
		case "peer.allowedips":
			for _, a := range splitList(val) {
				p, err := netip.ParsePrefix(a)
				if err != nil {
					return nil, fmt.Errorf("line %d: bad AllowedIPs entry %q", n, a)
				}
				c.AllowedIPs = append(c.AllowedIPs, p)
			}
		case "peer.persistentkeepalive":
			if strings.EqualFold(val, "off") {
				continue
			}
			ka, err := strconv.Atoi(val)
			if err != nil || ka < 0 || ka > 65535 {
				return nil, fmt.Errorf("line %d: bad PersistentKeepalive %q", n, val)
			}
			c.Peer.Keepalive = ka
		}
	}
	switch {
	case ifaces == 0:
		return nil, errors.New("no [Interface] section; this does not look like a WireGuard config")
	case ifaces > 1:
		return nil, fmt.Errorf("expected one [Interface], found %d", ifaces)
	case c.PrivateKey == "":
		return nil, errors.New("missing [Interface] PrivateKey; download the config again with its key included")
	case !validKey(c.PrivateKey):
		return nil, errors.New("invalid [Interface] PrivateKey (expected 44 base64 characters)")
	case !c.Address.IsValid() && c.Address6.IsValid():
		return nil, errors.New("[Interface] Address has only IPv6; Smart DNS exits egress over IPv4, so choose a config with an IPv4 address")
	case !c.Address.IsValid():
		return nil, errors.New("missing [Interface] Address")
	case peers == 0:
		return nil, errors.New("missing [Peer] section")
	case peers != 1:
		return nil, fmt.Errorf("expected exactly one [Peer], found %d", peers)
	case !validKey(c.Peer.PublicKey):
		return nil, errors.New("missing or invalid [Peer] PublicKey")
	case c.Peer.PresharedKey != "" && !validKey(c.Peer.PresharedKey):
		return nil, errors.New("invalid [Peer] PresharedKey")
	case c.Peer.Endpoint == "":
		return nil, errors.New("missing [Peer] Endpoint (host:port of the VPN server)")
	}
	host, port, err := net.SplitHostPort(c.Peer.Endpoint)
	if err != nil || host == "" {
		return nil, fmt.Errorf("invalid [Peer] Endpoint %q (expected host:port)", c.Peer.Endpoint)
	}
	if p, err := strconv.Atoi(port); err != nil || p < 1 || p > 65535 {
		return nil, fmt.Errorf("invalid [Peer] Endpoint port %q", port)
	}
	return c, nil
}

// looksLikeOpenVPN spots .ovpn files, the most common wrong download.
func looksLikeOpenVPN(text string) bool {
	if strings.Contains(strings.ToLower(text), "[interface]") {
		return false
	}
	for _, l := range strings.Split(text, "\n") {
		l = strings.TrimSpace(l)
		if l == "client" || l == "<ca>" || strings.HasPrefix(l, "remote ") || strings.HasPrefix(l, "dev tun") || strings.HasPrefix(l, "auth-user-pass") {
			return true
		}
	}
	return false
}

func splitList(s string) []string {
	var out []string
	for _, f := range strings.Split(s, ",") {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	return out
}

func validKey(s string) bool {
	b, err := base64.StdEncoding.DecodeString(s)
	return err == nil && len(b) == 32
}

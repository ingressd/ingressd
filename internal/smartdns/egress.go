// SPDX-License-Identifier: Apache-2.0

package smartdns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/miekg/dns"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const (
	dialTimeout      = 6 * time.Second
	dnsTimeout       = 2 * time.Second
	handshakeMaxAge  = 3 * time.Minute
	defaultAnswerTTL = 60 * time.Second
)

// egress is how a self exit reaches the internet: through the node's own
// route, or through its VPN interface (SO_MARK + SO_BINDTODEVICE).
type egress struct {
	exit    string
	country string
	ifname  string // "" = the node's own route
	mark    int
	dns     []string // resolvers, host:port (inside the VPN when ifname is set)
	public  string   // the node's public IPv4, when egressing directly
	// device reads WireGuard state for the VPN health check.
	device func(name string) (*wgtypes.Device, error)
	// endpoint and peerKey come from the VPN config (endpoint refresh).
	endpoint, peerKey string

	refreshMu sync.Mutex
	refreshed time.Time
}

func (e *egress) dialer() *net.Dialer {
	return &net.Dialer{Timeout: dialTimeout, Control: egressControl(e.ifname, e.mark)}
}

// up reports whether egress works: always without a VPN; with one, the VPN
// peer must have completed a handshake recently.
func (e *egress) up() (bool, string) {
	if e.ifname == "" {
		return true, ""
	}
	if e.device == nil {
		return false, "no WireGuard access"
	}
	dev, err := e.device(e.ifname)
	if err != nil {
		return false, fmt.Sprintf("VPN interface %s: %v", e.ifname, err)
	}
	for _, p := range dev.Peers {
		if !p.LastHandshakeTime.IsZero() && time.Since(p.LastHandshakeTime) < handshakeMaxAge {
			return true, ""
		}
	}
	return false, fmt.Sprintf("VPN tunnel %s has no recent handshake", e.ifname)
}

// resolve looks up name's A records from the exit's location. It returns
// the DNS rcode (NOERROR or NXDOMAIN) or an error when no resolver gave a
// usable answer.
func (e *egress) resolve(ctx context.Context, name string) (int, answer, error) {
	q := new(dns.Msg)
	q.SetQuestion(dns.Fqdn(name), dns.TypeA)
	r, err := exchange(ctx, e.dns, e.dialer(), q)
	if err != nil {
		return 0, answer{}, err
	}
	return r.Rcode, answerOf(r), nil
}

// exchange asks each server in turn (UDP, then TCP if truncated) and
// returns the first NOERROR/NXDOMAIN response.
func exchange(ctx context.Context, servers []string, d *net.Dialer, q *dns.Msg) (*dns.Msg, error) {
	if len(servers) == 0 {
		return nil, errors.New("no resolvers configured")
	}
	var last error
	for _, s := range servers {
		c := &dns.Client{Net: "udp", Dialer: d, Timeout: dnsTimeout}
		r, _, err := c.ExchangeContext(ctx, q, s)
		if err == nil && r.Truncated {
			c.Net = "tcp"
			r, _, err = c.ExchangeContext(ctx, q, s)
		}
		if err != nil {
			last = fmt.Errorf("%s: %w", s, err)
			continue
		}
		if r.Rcode != dns.RcodeSuccess && r.Rcode != dns.RcodeNameError {
			last = fmt.Errorf("%s: %s", s, dns.RcodeToString[r.Rcode])
			continue
		}
		return r, nil
	}
	return nil, last
}

// answerOf collects the A records (following any CNAME chain the server
// included) and the smallest TTL.
func answerOf(r *dns.Msg) answer {
	var a answer
	minTTL := uint32(0)
	for _, rr := range r.Answer {
		ttl := rr.Header().Ttl
		if minTTL == 0 || ttl < minTTL {
			minTTL = ttl
		}
		if v, ok := rr.(*dns.A); ok {
			if ip, ok := netip.AddrFromSlice(v.A.To4()); ok {
				a.Addrs = append(a.Addrs, ip)
			}
		}
	}
	a.TTL = time.Duration(minTTL) * time.Second
	if a.TTL == 0 {
		a.TTL = defaultAnswerTTL
	}
	return a
}

// dial connects to the first reachable address, in the given order.
func (e *egress) dial(ctx context.Context, addrs []netip.Addr, port int) (net.Conn, netip.Addr, error) {
	d := e.dialer()
	var last error
	for _, a := range addrs {
		c, err := d.DialContext(ctx, "tcp4", net.JoinHostPort(a.String(), strconv.Itoa(port)))
		if err == nil {
			return c, a, nil
		}
		last = err
	}
	if last == nil {
		last = errors.New("no upstream addresses")
	}
	via := "direct"
	if e.ifname != "" {
		via = "via " + e.ifname
	}
	return nil, netip.Addr{}, fmt.Errorf("connect %s failed: %w", via, last)
}

// hostPort adds :53 to a bare resolver address.
func hostPort(s string) string {
	if _, err := netip.ParseAddr(s); err == nil {
		return net.JoinHostPort(s, "53")
	}
	return s
}

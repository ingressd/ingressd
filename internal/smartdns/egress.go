// SPDX-License-Identifier: Apache-2.0

package smartdns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"time"

	"github.com/miekg/dns"
)

const (
	dialTimeout      = 6 * time.Second
	dnsTimeout       = 2 * time.Second
	defaultAnswerTTL = 60 * time.Second
)

// DialFunc opens a connection ("tcp4" or "udp4") from an egress.
type DialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// EgressOptions describe how one exit reaches the internet.
type EgressOptions struct {
	Name    string
	Country string // expected ISO country
	// DNS are the resolvers (host:port) asked from the egress.
	DNS []string
	// Dial connects through the egress; nil means the host's own route.
	Dial DialFunc
	// Health reports whether the egress can be used (a VPN's handshake);
	// nil means always.
	Health func() (bool, string)
	// Endpoint reports the VPN server in use, for status.
	Endpoint func() string
	// VPN marks an egress through a VPN tunnel (status only).
	VPN bool
	// Public is the egress IP when known in advance (status only).
	Public string
	// Sig changes when the egress changes (new VPN config); traces are
	// redone then.
	Sig string
}

// egress is how a local exit reaches the internet: the host's route (a
// node exit) or a VPN tunnel (a connector exit).
type egress struct {
	exit, country string
	dns           []string
	public        string
	vpn           bool
	sigStr        string
	dialFn        DialFunc
	health        func() (bool, string)
	endpoint      func() string
	// alwaysTrace keeps tracing while the egress reports itself down (a
	// node exit is down because of what the trace found).
	alwaysTrace bool
}

func newEgress(o EgressOptions) *egress {
	e := &egress{exit: o.Name, country: o.Country, public: o.Public, vpn: o.VPN, sigStr: o.Sig, dialFn: o.Dial, health: o.Health, endpoint: o.Endpoint}
	for _, d := range o.DNS {
		e.dns = append(e.dns, hostPort(d))
	}
	if e.dialFn == nil {
		d := &net.Dialer{Timeout: dialTimeout}
		e.dialFn = d.DialContext
	}
	return e
}

func (e *egress) dialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()
	return e.dialFn(ctx, network, addr)
}

// up reports whether the egress can be used.
func (e *egress) up() (bool, string) {
	if e.health == nil {
		return true, ""
	}
	return e.health()
}

func (e *egress) endpointNow() string {
	if e.endpoint == nil {
		return ""
	}
	return e.endpoint()
}

func (e *egress) sig() string { return e.sigStr }

// resolve looks up name's A records from the exit's location. It returns
// the DNS rcode (NOERROR or NXDOMAIN) or an error when no resolver gave a
// usable answer.
func (e *egress) resolve(ctx context.Context, name string) (int, answer, error) {
	q := new(dns.Msg)
	q.SetQuestion(dns.Fqdn(name), dns.TypeA)
	r, err := exchange(ctx, e.dns, e.dialContext, q)
	if err != nil {
		return 0, answer{}, err
	}
	return r.Rcode, answerOf(r), nil
}

func hostDial(ctx context.Context, network, addr string) (net.Conn, error) {
	d := &net.Dialer{Timeout: dnsTimeout}
	return d.DialContext(ctx, network, addr)
}

// exchange asks each server in turn (UDP, then TCP if truncated) and
// returns the first NOERROR/NXDOMAIN response.
func exchange(ctx context.Context, servers []string, dial DialFunc, q *dns.Msg) (*dns.Msg, error) {
	if len(servers) == 0 {
		return nil, errors.New("no resolvers configured")
	}
	var last error
	for _, s := range servers {
		r, err := exchangeOne(ctx, dial, "udp4", s, q)
		if err == nil && r.Truncated {
			r, err = exchangeOne(ctx, dial, "tcp4", s, q)
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

func exchangeOne(ctx context.Context, dial DialFunc, network, server string, q *dns.Msg) (*dns.Msg, error) {
	ctx, cancel := context.WithTimeout(ctx, dnsTimeout)
	defer cancel()
	c, err := dial(ctx, network, server)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	if dl, ok := ctx.Deadline(); ok {
		c.SetDeadline(dl)
	}
	cl := &dns.Client{Net: "tcp", Timeout: dnsTimeout}
	if network == "udp4" {
		cl.Net = "udp"
	}
	r, _, err := cl.ExchangeWithConnContext(ctx, q, &dns.Conn{Conn: c})
	return r, err
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
	var last error
	for _, a := range addrs {
		c, err := e.dialContext(ctx, "tcp4", net.JoinHostPort(a.String(), strconv.Itoa(port)))
		if err == nil {
			return c, a, nil
		}
		last = err
	}
	if last == nil {
		last = errors.New("no upstream addresses")
	}
	via := "direct"
	if e.vpn {
		via = "through the VPN"
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

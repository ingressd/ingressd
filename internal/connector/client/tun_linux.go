// SPDX-License-Identifier: Apache-2.0

package client

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// DefaultInterface is the TUN-mode interface name.
const DefaultInterface = "ingressd0"

// Policy routing for transparent L4 sources: replies from these host:port
// pairs are looked up in transparentTable, whose default route is the tunnel.
const (
	transparentTable    = 5182
	transparentPriority = 5182
)

// kernelLink is kernel WireGuard configured through wgctrl.
type kernelLink struct {
	name string
	c    *wgctrl.Client
	mtu  int
	// cleanup undoes routes, rules and nftables state.
	cleanup func()
}

func (l *kernelLink) SetPeer(p peerConfig, reset bool) error {
	if reset {
		if err := l.c.ConfigureDevice(l.name, wgtypes.Config{Peers: []wgtypes.PeerConfig{{PublicKey: p.PublicKey, Remove: true}}}); err != nil {
			return err
		}
	}
	ka := time.Duration(p.Keepalive) * time.Second
	pc := wgtypes.PeerConfig{PublicKey: p.PublicKey, PersistentKeepaliveInterval: &ka, ReplaceAllowedIPs: true}
	if p.Endpoint.IsValid() {
		pc.Endpoint = net.UDPAddrFromAddrPort(p.Endpoint)
	}
	for _, a := range p.AllowedIPs {
		pc.AllowedIPs = append(pc.AllowedIPs, net.IPNet{IP: a.Addr().AsSlice(), Mask: net.CIDRMask(a.Bits(), a.Addr().BitLen())})
	}
	return l.c.ConfigureDevice(l.name, wgtypes.Config{Peers: []wgtypes.PeerConfig{pc}})
}

func (l *kernelLink) RemovePeer(key wgtypes.Key) error {
	return l.c.ConfigureDevice(l.name, wgtypes.Config{Peers: []wgtypes.PeerConfig{{PublicKey: key, Remove: true}}})
}

func (l *kernelLink) Stats() (map[wgtypes.Key]peerStats, error) {
	d, err := l.c.Device(l.name)
	if err != nil {
		return nil, err
	}
	out := map[wgtypes.Key]peerStats{}
	for _, p := range d.Peers {
		out[p.PublicKey] = peerStats{LastHandshake: p.LastHandshakeTime, RxBytes: p.ReceiveBytes, TxBytes: p.TransmitBytes}
	}
	return out, nil
}

func (l *kernelLink) AddAddress(p netip.Prefix) error    { return setAddress(l.name, p, true) }
func (l *kernelLink) RemoveAddress(p netip.Prefix) error { return setAddress(l.name, p, false) }

// setAddress adds or removes a transit address on the interface.
func setAddress(name string, p netip.Prefix, add bool) error {
	lk, err := netlink.LinkByName(name)
	if err != nil {
		return err
	}
	a, err := netlink.ParseAddr(p.String())
	if err != nil {
		return err
	}
	if add {
		return netlink.AddrReplace(lk, a)
	}
	if err := netlink.AddrDel(lk, a); err != nil && !errors.Is(err, unix.EADDRNOTAVAIL) {
		return err
	}
	return nil
}

func (l *kernelLink) SetMTU(mtu int) error {
	if err := setLinkMTU(l.name, mtu); err != nil {
		return err
	}
	l.mtu = mtu
	return nil
}

func (l *kernelLink) MTU() int     { return l.mtu }
func (l *kernelLink) Kind() string { return "kernel" }

func (l *kernelLink) DialTunnel(ctx context.Context, addr string) (net.Conn, error) {
	return dialViaRoute(ctx, addr)
}

func (l *kernelLink) Close() error {
	if l.cleanup != nil {
		l.cleanup()
	}
	if lk, err := netlink.LinkByName(l.name); err == nil {
		_ = netlink.LinkDel(lk)
	}
	return l.c.Close()
}

func dialViaRoute(ctx context.Context, addr string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, "tcp", addr)
}

func setLinkMTU(name string, mtu int) error {
	lk, err := netlink.LinkByName(name)
	if err != nil {
		return err
	}
	return netlink.LinkSetMTU(lk, mtu)
}

// openTUN brings up a routed interface: kernel WireGuard when the module is
// available, otherwise wireguard-go on a TUN device.
func openTUN(st *State, priv wgtypes.Key, log *slog.Logger) (link, error) {
	if os.Geteuid() != 0 {
		return nil, errors.New("tun mode needs root (or CAP_NET_ADMIN); use --mode netstack otherwise")
	}
	name := cmp.Or(st.Interface, DefaultInterface)
	mtu := st.MTU()
	if old, err := netlink.LinkByName(name); err == nil { // left over from a crash
		_ = netlink.LinkDel(old)
	}

	var l link
	err := netlink.LinkAdd(&netlink.Wireguard{LinkAttrs: netlink.LinkAttrs{Name: name, MTU: mtu}})
	if err == nil {
		c, err := wgctrl.New()
		if err != nil {
			return nil, err
		}
		if err := c.ConfigureDevice(name, wgtypes.Config{PrivateKey: &priv}); err != nil {
			c.Close()
			deleteLink(name)
			return nil, err
		}
		l = &kernelLink{name: name, c: c, mtu: mtu}
	} else {
		log.Info("kernel WireGuard unavailable, using wireguard-go", "err", err)
		tdev, err := tun.CreateTUN(name, mtu)
		if err != nil {
			return nil, fmt.Errorf("create TUN %s: %w", name, err)
		}
		dev, err := newUserDevice(tdev, priv, log)
		if err != nil {
			return nil, err
		}
		l = &userLink{dev: dev, kind: "wireguard-go/tun", mtu: mtu, dial: dialViaRoute,
			setMTU: func(m int) error { return setLinkMTU(name, m) },
			addr:   func(p netip.Prefix, add bool) error { return setAddress(name, p, add) }}
	}

	cleanup, err := configureInterface(name, st, log)
	if err != nil {
		l.Close()
		deleteLink(name)
		return nil, err
	}
	switch v := l.(type) {
	case *kernelLink:
		v.cleanup = cleanup
	case *userLink:
		v.cleanup = cleanup
	}
	return l, nil
}

func deleteLink(name string) {
	if lk, err := netlink.LinkByName(name); err == nil {
		_ = netlink.LinkDel(lk)
	}
}

// configureInterface assigns the transit addresses, enables forwarding,
// installs transparent-mode policy routes and the nftables helpers. It
// returns a function undoing the routes, rules and nftables table.
func configureInterface(name string, st *State, log *slog.Logger) (func(), error) {
	lk, err := netlink.LinkByName(name)
	if err != nil {
		return nil, err
	}
	for _, p := range st.Addresses() {
		if err := setAddress(name, p, true); err != nil {
			return nil, fmt.Errorf("address %s: %w", p, err)
		}
	}
	if err := netlink.LinkSetUp(lk); err != nil {
		return nil, err
	}
	// The edge's traffic to the site subnets is forwarded by this host.
	if err := os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1"), 0o644); err != nil {
		log.Warn("could not enable IP forwarding", "err", err)
	}

	var rules []*netlink.Rule
	srcs, err := parseTransparent(st.Transparent())
	if err != nil {
		return nil, err
	}
	if len(srcs) > 0 {
		if err := netlink.RouteReplace(&netlink.Route{LinkIndex: lk.Attrs().Index, Dst: &net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)}, Table: transparentTable}); err != nil {
			return nil, fmt.Errorf("transparent route table: %w", err)
		}
	}
	for i, s := range srcs {
		r := netlink.NewRule()
		r.Priority = transparentPriority + i
		r.Table = transparentTable
		r.Src = &net.IPNet{IP: s.addr.Addr().AsSlice(), Mask: net.CIDRMask(32, 32)}
		r.IPProto = s.proto
		r.Sport = netlink.NewRulePortRange(s.addr.Port(), s.addr.Port())
		if err := netlink.RuleAdd(r); err != nil && !errors.Is(err, unix.EEXIST) {
			return nil, fmt.Errorf("policy rule for %s: %w", s.raw, err)
		}
		rules = append(rules, r)
	}

	nftOK := applyNFT(nftScript(name, st, st.MTU()), log)
	return func() {
		for _, r := range rules {
			_ = netlink.RuleDel(r)
		}
		if nftOK {
			_ = runNFT("add table ip ingressd_connector\ndelete table ip ingressd_connector\n")
		}
	}, nil
}

type transparentSrc struct {
	raw   string
	proto int
	addr  netip.AddrPort
}

// parseTransparent parses "tcp/192.168.0.17:25565" entries.
func parseTransparent(in []string) ([]transparentSrc, error) {
	var out []transparentSrc
	for _, s := range in {
		p, a, ok := strings.Cut(s, "/")
		ap, err := netip.ParseAddrPort(a)
		if !ok || err != nil || !ap.Addr().Is4() {
			return nil, fmt.Errorf("transparent source %q: want tcp/IPv4:port or udp/IPv4:port", s)
		}
		t := transparentSrc{raw: s, addr: ap}
		switch p {
		case "tcp":
			t.proto = unix.IPPROTO_TCP
		case "udp":
			t.proto = unix.IPPROTO_UDP
		default:
			return nil, fmt.Errorf("transparent source %q: protocol must be tcp or udp", s)
		}
		out = append(out, t)
	}
	return out, nil
}

// dropLegacyTable removes the table a pre-rename connector left behind.
const dropLegacyTable = "add table ip homeedge_connector # legacy homeedge name, remove after 2027-01\n" + // legacy homeedge name, remove after 2027-01
	"delete table ip homeedge_connector # legacy homeedge name, remove after 2027-01\n" // legacy homeedge name, remove after 2027-01

// nftScript clamps TCP MSS to the tunnel MTU in both directions (the edge
// and the LAN hosts both assume larger MTUs) and optionally masquerades
// tunnel traffic so LAN hosts reply to this host when it is not their router.
func nftScript(ifname string, st *State, mtu int) string {
	mss := strconv.Itoa(mtu - 40)
	var b strings.Builder
	b.WriteString(dropLegacyTable)
	b.WriteString("add table ip ingressd_connector\ndelete table ip ingressd_connector\n")
	fmt.Fprintf(&b, "table ip ingressd_connector {\n\tchain forward {\n\t\ttype filter hook forward priority mangle; policy accept;\n")
	fmt.Fprintf(&b, "\t\tiifname %q tcp flags syn tcp option maxseg size > %s tcp option maxseg size set %s\n", ifname, mss, mss)
	fmt.Fprintf(&b, "\t\toifname %q tcp flags syn tcp option maxseg size > %s tcp option maxseg size set %s\n", ifname, mss, mss)
	b.WriteString("\t}\n")
	if st.Masquerade {
		var nets []string
		for _, p := range st.Addresses() {
			nets = append(nets, p.Masked().String())
		}
		if len(nets) > 0 {
			fmt.Fprintf(&b, "\tchain postrouting {\n\t\ttype nat hook postrouting priority srcnat; policy accept;\n\t\tip saddr { %s } oifname != %q masquerade\n\t}\n", strings.Join(nets, ", "), ifname)
		}
	}
	b.WriteString("}\n")
	return b.String()
}

func runNFT(script string) error {
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(script)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("nft: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func applyNFT(script string, log *slog.Logger) bool {
	if _, err := exec.LookPath("nft"); err != nil {
		log.Warn("nft not installed: skipping MSS clamping and masquerade")
		return false
	}
	if err := runNFT(script); err != nil {
		log.Warn("nftables setup failed", "err", err)
		return false
	}
	return true
}

// reapplyNFT refreshes the MSS clamp after an MTU change.
func reapplyNFT(st *State, mtu int, log *slog.Logger) {
	if _, err := exec.LookPath("nft"); err == nil {
		applyNFT(nftScript(cmp.Or(st.Interface, DefaultInterface), st, mtu), log)
	}
}

// probeMTU picks the largest of 1420/1380 that passes a don't-fragment ping
// to the edge's transit address, falling back to 1280.
func probeMTU(l link, edge netip.Addr, log *slog.Logger) int {
	for _, mtu := range []int{1420, 1380} {
		if err := l.SetMTU(mtu); err != nil {
			log.Warn("set MTU", "mtu", mtu, "err", err)
			continue
		}
		for range 3 {
			if err := pingDF(edge, mtu-28, time.Second); err == nil {
				return mtu
			}
		}
	}
	_ = l.SetMTU(1280)
	return 1280
}

// pingDF sends one ICMP echo of the given payload size with DF set and
// waits for the reply.
func pingDF(dst netip.Addr, size int, timeout time.Duration) error {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.IPPROTO_ICMP)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	if err := unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_MTU_DISCOVER, unix.IP_PMTUDISC_PROBE); err != nil {
		return err
	}
	tv := unix.NsecToTimeval(timeout.Nanoseconds())
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
		return err
	}
	id := uint16(os.Getpid())
	seq := uint16(time.Now().UnixNano())
	pkt := icmpEcho(id, seq, size-8)
	if err := unix.Sendto(fd, pkt, 0, &unix.SockaddrInet4{Addr: dst.As4()}); err != nil {
		return err
	}
	deadline := time.Now().Add(timeout)
	buf := make([]byte, 2048)
	for time.Now().Before(deadline) {
		n, from, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			return err
		}
		sa, ok := from.(*unix.SockaddrInet4)
		if !ok || netip.AddrFrom4(sa.Addr) != dst || n < 20 {
			continue
		}
		ihl := int(buf[0]&0x0f) * 4
		if n < ihl+8 {
			continue
		}
		icmp := buf[ihl:n]
		if icmp[0] == 0 && uint16(icmp[4])<<8|uint16(icmp[5]) == id && uint16(icmp[6])<<8|uint16(icmp[7]) == seq {
			return nil
		}
	}
	return errors.New("timeout")
}

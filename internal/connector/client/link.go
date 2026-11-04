// SPDX-License-Identifier: Apache-2.0

package client

import (
	"bufio"
	"context"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// peerConfig is one edge peer as the site configures it.
type peerConfig struct {
	PublicKey  wgtypes.Key
	Endpoint   netip.AddrPort
	AllowedIPs []netip.Prefix
	Keepalive  int
}

type peerStats struct {
	LastHandshake time.Time
	RxBytes       int64
	TxBytes       int64
}

// link is the site's WireGuard device: kernel, wireguard-go on a TUN, or
// wireguard-go on a gVisor netstack. It has one peer per edge.
type link interface {
	// SetPeer configures an edge peer. reset removes it first, dropping the
	// session so a new handshake starts at once (used when switching
	// transports, to learn quickly whether the new path works).
	SetPeer(p peerConfig, reset bool) error
	RemovePeer(key wgtypes.Key) error
	// Stats returns the counters of every peer.
	Stats() (map[wgtypes.Key]peerStats, error)
	// AddAddress and RemoveAddress manage the site's transit addresses
	// (one per edge).
	AddAddress(p netip.Prefix) error
	RemoveAddress(p netip.Prefix) error
	// SetMTU changes the tunnel MTU where the mode supports it.
	SetMTU(mtu int) error
	MTU() int
	// DialTunnel opens a TCP connection to addr through the tunnel.
	DialTunnel(ctx context.Context, addr string) (net.Conn, error)
	Kind() string
	Close() error
}

// userLink is wireguard-go configured through its UAPI.
type userLink struct {
	dev     *device.Device
	kind    string
	mtu     int
	setMTU  func(int) error
	dial    func(ctx context.Context, addr string) (net.Conn, error)
	addr    func(p netip.Prefix, add bool) error
	cleanup func()
}

func newUserDevice(tdev tun.Device, priv wgtypes.Key, log *slog.Logger) (*device.Device, error) {
	logger := &device.Logger{
		Verbosef: func(f string, a ...any) { log.Debug("wireguard: " + fmt.Sprintf(f, a...)) },
		Errorf:   func(f string, a ...any) { log.Warn("wireguard: " + fmt.Sprintf(f, a...)) },
	}
	dev := device.NewDevice(tdev, conn.NewDefaultBind(), logger)
	if err := dev.IpcSet("private_key=" + hex.EncodeToString(priv[:]) + "\n"); err != nil {
		dev.Close()
		return nil, err
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return nil, err
	}
	return dev, nil
}

func (l *userLink) SetPeer(p peerConfig, reset bool) error {
	var b strings.Builder
	pk := hex.EncodeToString(p.PublicKey[:])
	if reset {
		fmt.Fprintf(&b, "public_key=%s\nremove=true\n", pk)
	}
	fmt.Fprintf(&b, "public_key=%s\n", pk)
	if p.Endpoint.IsValid() {
		fmt.Fprintf(&b, "endpoint=%s\n", p.Endpoint)
	}
	fmt.Fprintf(&b, "persistent_keepalive_interval=%d\nreplace_allowed_ips=true\n", p.Keepalive)
	for _, a := range p.AllowedIPs {
		fmt.Fprintf(&b, "allowed_ip=%s\n", a)
	}
	return l.dev.IpcSet(b.String())
}

func (l *userLink) RemovePeer(key wgtypes.Key) error {
	return l.dev.IpcSet("public_key=" + hex.EncodeToString(key[:]) + "\nremove=true\n")
}

func (l *userLink) Stats() (map[wgtypes.Key]peerStats, error) {
	s, err := l.dev.IpcGet()
	if err != nil {
		return nil, err
	}
	return parseUAPIStats(s), nil
}

func (l *userLink) AddAddress(p netip.Prefix) error {
	if l.addr == nil {
		return nil
	}
	return l.addr(p, true)
}

func (l *userLink) RemoveAddress(p netip.Prefix) error {
	if l.addr == nil {
		return nil
	}
	return l.addr(p, false)
}

// parseUAPIStats reads every peer's counters from a UAPI dump.
func parseUAPIStats(s string) map[wgtypes.Key]peerStats {
	out := map[wgtypes.Key]peerStats{}
	var key wgtypes.Key
	var st peerStats
	var sec, nsec int64
	have := false
	flush := func() {
		if !have {
			return
		}
		if sec != 0 || nsec != 0 {
			st.LastHandshake = time.Unix(sec, nsec)
		}
		out[key] = st
	}
	sc := bufio.NewScanner(strings.NewReader(s))
	for sc.Scan() {
		k, v, _ := strings.Cut(sc.Text(), "=")
		n, _ := strconv.ParseInt(v, 10, 64)
		switch k {
		case "public_key":
			flush()
			key, st, sec, nsec, have = wgtypes.Key{}, peerStats{}, 0, 0, true
			if b, err := hex.DecodeString(v); err == nil && len(b) == len(key) {
				copy(key[:], b)
			}
		case "last_handshake_time_sec":
			sec = n
		case "last_handshake_time_nsec":
			nsec = n
		case "rx_bytes":
			st.RxBytes = n
		case "tx_bytes":
			st.TxBytes = n
		}
	}
	flush()
	return out
}

func (l *userLink) SetMTU(mtu int) error {
	if l.setMTU == nil {
		return nil
	}
	if err := l.setMTU(mtu); err != nil {
		return err
	}
	l.mtu = mtu
	return nil
}

func (l *userLink) MTU() int     { return l.mtu }
func (l *userLink) Kind() string { return l.kind }

func (l *userLink) DialTunnel(ctx context.Context, addr string) (net.Conn, error) {
	return l.dial(ctx, addr)
}

func (l *userLink) Close() error {
	l.dev.Close()
	if l.cleanup != nil {
		l.cleanup()
	}
	return nil
}

// openNetstack brings up wireguard-go on a gVisor netstack (no root).
func openNetstack(st *State, priv wgtypes.Key, log *slog.Logger) (link, error) {
	var allowed []netip.Prefix
	for _, s := range st.Subnets() {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return nil, fmt.Errorf("config subnet %q: %w", s, err)
		}
		allowed = append(allowed, p)
	}
	addrs := st.Addresses()
	if len(addrs) == 0 {
		return nil, fmt.Errorf("no site transit address in the tunnel config")
	}
	mtu := st.MTU()
	ns, err := newNetstack(addrs[0], mtu, allowed, log)
	if err != nil {
		return nil, err
	}
	for _, a := range addrs[1:] {
		if err := ns.AddAddress(a); err != nil {
			_ = ns.Close()
			return nil, err
		}
	}
	dev, err := newUserDevice(ns, priv, log)
	if err != nil {
		ns.Close()
		return nil, err
	}
	return &userLink{dev: dev, kind: "wireguard-go/netstack", mtu: mtu, dial: ns.DialTCP, addr: func(p netip.Prefix, add bool) error {
		if add {
			return ns.AddAddress(p)
		}
		return ns.RemoveAddress(p)
	}}, nil
}

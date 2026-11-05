// SPDX-License-Identifier: Apache-2.0

package client

import (
	"cmp"
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"

	"github.com/ingressd/ingressd/internal/smartdns/wgconf"
	"github.com/ingressd/ingressd/pkg/envcompat"
)

// A connector VPN exit: the provider's WireGuard config on its own
// wireguard-go device over a gVisor netstack. It has no host interface or
// route, so it can only ever carry the relay's own connections, and needs
// no root on any OS.

const (
	vpnHandshakeMaxAge = 3 * time.Minute
	vpnProbeEvery      = 20 * time.Second
	vpnProbeFails      = 3
	vpnEndpointRefresh = 30 * time.Second
	vpnDefaultMTU      = 1420
	vpnDefaultKeepalv  = 25
)

// vpnProbeTarget is dialled through the tunnel to tell a dead provider
// from an idle one before the handshake ages out
// ( overrides it, for test networks).
var vpnProbeTarget = cmp.Or(strings.TrimSpace(envcompat.Get("INGRESSD_SMARTDNS_PROBE_ADDR")), "1.1.1.1:443")

type vpnExit struct {
	name     string
	log      *slog.Logger
	dev      *device.Device
	net      *netstack.Net
	cfg      *wgconf.Config
	peerHex  string
	dns      []string
	lookup   func(ctx context.Context, host string) ([]netip.Addr, error)
	cancel   context.CancelFunc
	sig      string
	mu       sync.Mutex
	fails    int
	lastOK   time.Time
	endpoint string // ip:port in use
}

func keyHex(b64 string) (string, error) {
	b, err := base64.StdEncoding.DecodeString(b64)
	if err != nil || len(b) != 32 {
		return "", fmt.Errorf("invalid WireGuard key")
	}
	return hex.EncodeToString(b), nil
}

// startVPNExit brings the tunnel up and starts its probe and endpoint
// refresh loops.
func startVPNExit(ctx context.Context, name, text string, log *slog.Logger) (*vpnExit, error) {
	wc, err := wgconf.Parse(text)
	if err != nil {
		return nil, err
	}
	mtu := wc.MTU
	if mtu == 0 {
		mtu = vpnDefaultMTU
	}
	var dnsAddrs []netip.Addr
	dnsAddrs = append(dnsAddrs, wc.DNS...)
	tdev, tnet, err := netstack.CreateNetTUN([]netip.Addr{wc.Address.Addr()}, dnsAddrs, mtu)
	if err != nil {
		return nil, err
	}
	logger := &device.Logger{
		Verbosef: func(f string, a ...any) { log.Debug("vpn exit " + name + ": " + fmt.Sprintf(f, a...)) },
		Errorf:   func(f string, a ...any) { log.Warn("vpn exit " + name + ": " + fmt.Sprintf(f, a...)) },
	}
	dev := device.NewDevice(tdev, conn.NewDefaultBind(), logger)
	v := &vpnExit{name: name, log: log, dev: dev, net: tnet, cfg: wc, sig: text,
		lookup: func(ctx context.Context, host string) ([]netip.Addr, error) {
			return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		}}
	for _, d := range wc.DNS {
		v.dns = append(v.dns, d.String())
	}
	priv, err := keyHex(wc.PrivateKey)
	if err != nil {
		dev.Close()
		return nil, err
	}
	if v.peerHex, err = keyHex(wc.Peer.PublicKey); err != nil {
		dev.Close()
		return nil, err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "private_key=%s\nreplace_peers=true\npublic_key=%s\n", priv, v.peerHex)
	if wc.Peer.PresharedKey != "" {
		psk, err := keyHex(wc.Peer.PresharedKey)
		if err != nil {
			dev.Close()
			return nil, err
		}
		fmt.Fprintf(&b, "preshared_key=%s\n", psk)
	}
	ka := wc.Peer.EffectiveKeepalive()
	if ka == 0 {
		ka = vpnDefaultKeepalv
	}
	fmt.Fprintf(&b, "persistent_keepalive_interval=%d\nreplace_allowed_ips=true\nallowed_ip=0.0.0.0/0\n", ka)
	if ep, err := v.resolveEndpoint(ctx); err == nil {
		fmt.Fprintf(&b, "endpoint=%s\n", ep)
		v.endpoint = ep
	} else {
		log.Warn("VPN endpoint does not resolve yet; retrying", "exit", name, "endpoint", wc.Peer.Endpoint, "err", err)
	}
	if err := dev.IpcSet(b.String()); err != nil {
		dev.Close()
		return nil, fmt.Errorf("configure VPN device: %w", err)
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return nil, err
	}
	ctx, v.cancel = context.WithCancel(ctx)
	go v.loop(ctx)
	return v, nil
}

func (v *vpnExit) close() {
	v.cancel()
	v.dev.Close()
}

// resolveEndpoint returns the endpoint as ip:port, IPv4 first.
func (v *vpnExit) resolveEndpoint(ctx context.Context) (string, error) {
	host, port, err := net.SplitHostPort(v.cfg.Peer.Endpoint)
	if err != nil {
		return "", err
	}
	if _, err := strconv.Atoi(port); err != nil {
		return "", err
	}
	if a, err := netip.ParseAddr(host); err == nil {
		return net.JoinHostPort(a.String(), port), nil
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	addrs, err := v.lookup(ctx, host)
	if err != nil {
		return "", err
	}
	if len(addrs) == 0 {
		return "", fmt.Errorf("%s has no addresses", host)
	}
	slices.SortStableFunc(addrs, func(a, b netip.Addr) int {
		switch {
		case a.Is4() == b.Is4():
			return 0
		case a.Is4():
			return -1
		}
		return 1
	})
	return net.JoinHostPort(addrs[0].Unmap().String(), port), nil
}

func (v *vpnExit) loop(ctx context.Context) {
	probe := time.NewTicker(vpnProbeEvery)
	refresh := time.NewTicker(vpnEndpointRefresh)
	defer probe.Stop()
	defer refresh.Stop()
	v.probe(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-probe.C:
			v.probe(ctx)
		case <-refresh.C:
			v.refreshEndpoint(ctx)
		}
	}
}

// probe connects through the tunnel; vpnProbeFails failures in a row mark
// the exit down until one succeeds.
func (v *vpnExit) probe(ctx context.Context) {
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	c, err := v.net.DialContext(ctx, "tcp4", vpnProbeTarget)
	v.mu.Lock()
	defer v.mu.Unlock()
	if err != nil {
		v.fails++
		return
	}
	c.Close()
	v.fails, v.lastOK = 0, time.Now()
}

// refreshEndpoint follows the provider moving its server to another
// address (and picks up a name that did not resolve at start).
func (v *vpnExit) refreshEndpoint(ctx context.Context) {
	ep, err := v.resolveEndpoint(ctx)
	if err != nil {
		return
	}
	v.mu.Lock()
	cur := v.endpoint
	v.mu.Unlock()
	if ep == cur || (cur != "" && v.stillListed(ctx, cur)) {
		return
	}
	if err := v.dev.IpcSet(fmt.Sprintf("public_key=%s\nupdate_only=true\nendpoint=%s\n", v.peerHex, ep)); err != nil {
		v.log.Warn("cannot update VPN endpoint", "exit", v.name, "err", err)
		return
	}
	v.log.Info("VPN endpoint updated", "exit", v.name, "from", cur, "to", ep)
	v.mu.Lock()
	v.endpoint = ep
	v.mu.Unlock()
}

// stillListed reports whether the endpoint in use is still one of the
// name's addresses (providers often answer several).
func (v *vpnExit) stillListed(ctx context.Context, cur string) bool {
	host, _, err := net.SplitHostPort(v.cfg.Peer.Endpoint)
	if err != nil {
		return false
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return false
	}
	curHost, _, _ := net.SplitHostPort(cur)
	ca, err := netip.ParseAddr(curHost)
	if err != nil {
		return false
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	addrs, err := v.lookup(ctx, host)
	return err == nil && slices.Contains(addrs, ca)
}

func (v *vpnExit) lastHandshake() time.Time {
	s, err := v.dev.IpcGet()
	if err != nil {
		return time.Time{}
	}
	var sec, nsec int64
	for _, line := range strings.Split(s, "\n") {
		k, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch k {
		case "last_handshake_time_sec":
			sec, _ = strconv.ParseInt(val, 10, 64)
		case "last_handshake_time_nsec":
			nsec, _ = strconv.ParseInt(val, 10, 64)
		}
	}
	if sec == 0 && nsec == 0 {
		return time.Time{}
	}
	return time.Unix(sec, nsec)
}

// health: up while the handshake is fresh and the probe has not failed
// vpnProbeFails times in a row.
func (v *vpnExit) health() (bool, string) {
	hs := v.lastHandshake()
	v.mu.Lock()
	fails := v.fails
	v.mu.Unlock()
	switch {
	case hs.IsZero():
		return false, "VPN tunnel has not completed a handshake"
	case time.Since(hs) > vpnHandshakeMaxAge:
		return false, "VPN tunnel has no recent handshake"
	case fails >= vpnProbeFails:
		return false, fmt.Sprintf("VPN tunnel carries no traffic (%d failed probes)", fails)
	}
	return true, ""
}

func (v *vpnExit) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	return v.net.DialContext(ctx, network, addr)
}

func (v *vpnExit) endpointNow() string {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.endpoint
}

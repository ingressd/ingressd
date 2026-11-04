// SPDX-License-Identifier: Apache-2.0 AND MIT

package client

// The TUN device below follows wireguard-go's tun/netstack, extended with
// TCP/UDP forwarders: in netstack mode the connector terminates connections
// to the site subnets in userspace and dials the real targets from the host,
// so it needs neither root nor a kernel WireGuard module.
//
// The portions adapted from wireguard-go (golang.zx2c4.com/wireguard,
// tun/netstack/tun.go) are under the following license:
//
// SPDX-License-Identifier: MIT
//
// Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of
// this software and associated documentation files (the "Software"), to deal in
// the Software without restriction, including without limitation the rights to
// use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
// of the Software, and to permit persons to whom the Software is furnished to do
// so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"strconv"
	"sync"
	"syscall"
	"time"

	"golang.zx2c4.com/wireguard/tun"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

const nicID = 1

// netstackTUN is a tun.Device backed by a gVisor network stack.
type netstackTUN struct {
	ep       *channel.Endpoint
	stack    *stack.Stack
	events   chan tun.Event
	notify   *channel.NotificationHandle
	incoming chan *buffer.View
	mtu      int
	closeOne sync.Once

	allowed []netip.Prefix
	log     *slog.Logger
	dial    func(ctx context.Context, network, addr string) (net.Conn, error)

	addrMu sync.Mutex
	addrs  []netip.Prefix // the site's transit addresses, one per edge
}

// newNetstack creates the userspace stack with the site's transit address.
// Connections to addresses inside allowed are forwarded to the real network.
func newNetstack(addr netip.Prefix, mtu int, allowed []netip.Prefix, log *slog.Logger) (*netstackTUN, error) {
	t := &netstackTUN{
		ep: channel.New(1024, uint32(mtu), ""),
		stack: stack.New(stack.Options{
			NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
			TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol, icmp.NewProtocol4, icmp.NewProtocol6},
			// HandleLocal would treat every source as local in promiscuous
			// mode and drop inbound packets as spoofed.
			HandleLocal: false,
		}),
		events:   make(chan tun.Event, 10),
		incoming: make(chan *buffer.View),
		mtu:      mtu,
		allowed:  allowed,
		log:      log,
		dial:     (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
	}
	sack := tcpip.TCPSACKEnabled(true)
	if err := t.stack.SetTransportProtocolOption(tcp.ProtocolNumber, &sack); err != nil {
		return nil, fmt.Errorf("netstack: enable SACK: %v", err)
	}
	t.notify = t.ep.AddNotify(t)
	if err := t.stack.CreateNIC(nicID, t.ep); err != nil {
		return nil, fmt.Errorf("netstack: create NIC: %v", err)
	}
	if err := t.AddAddress(addr); err != nil {
		return nil, err
	}
	t.stack.AddRoute(tcpip.Route{Destination: header.IPv4EmptySubnet, NIC: nicID})
	t.stack.AddRoute(tcpip.Route{Destination: header.IPv6EmptySubnet, NIC: nicID})
	// Accept packets for any destination (the site subnets) and reply
	// from those addresses.
	if err := t.stack.SetPromiscuousMode(nicID, true); err != nil {
		return nil, fmt.Errorf("netstack: promiscuous: %v", err)
	}
	if err := t.stack.SetSpoofing(nicID, true); err != nil {
		return nil, fmt.Errorf("netstack: spoofing: %v", err)
	}
	t.stack.SetTransportProtocolHandler(tcp.ProtocolNumber, tcp.NewForwarder(t.stack, 0, 1024, t.forwardTCP).HandlePacket)
	t.stack.SetTransportProtocolHandler(udp.ProtocolNumber, udp.NewForwarder(t.stack, t.forwardUDP).HandlePacket)
	t.events <- tun.EventUp
	return t, nil
}

func (t *netstackTUN) Name() (string, error)    { return "netstack", nil }
func (t *netstackTUN) File() *os.File           { return nil }
func (t *netstackTUN) Events() <-chan tun.Event { return t.events }
func (t *netstackTUN) MTU() (int, error)        { return t.mtu, nil }
func (t *netstackTUN) BatchSize() int           { return 1 }

func (t *netstackTUN) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	view, ok := <-t.incoming
	if !ok {
		return 0, os.ErrClosed
	}
	n, err := view.Read(bufs[0][offset:])
	if err != nil {
		return 0, err
	}
	sizes[0] = n
	return 1, nil
}

func (t *netstackTUN) Write(bufs [][]byte, offset int) (int, error) {
	for _, b := range bufs {
		pkt := b[offset:]
		if len(pkt) == 0 {
			continue
		}
		pkb := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(pkt)})
		switch pkt[0] >> 4 {
		case 4:
			t.ep.InjectInbound(header.IPv4ProtocolNumber, pkb)
		case 6:
			t.ep.InjectInbound(header.IPv6ProtocolNumber, pkb)
		default:
			pkb.DecRef()
			return 0, syscall.EAFNOSUPPORT
		}
	}
	return len(bufs), nil
}

// WriteNotify is called by the channel endpoint when the stack sends.
func (t *netstackTUN) WriteNotify() {
	pkt := t.ep.Read()
	if pkt == nil {
		return
	}
	view := pkt.ToView()
	pkt.DecRef()
	t.incoming <- view
}

func (t *netstackTUN) Close() error {
	t.closeOne.Do(func() {
		t.stack.RemoveNIC(nicID)
		t.stack.Close()
		t.ep.RemoveNotify(t.notify)
		t.ep.Close()
		close(t.events)
		close(t.incoming)
	})
	return nil
}

func netProto(a netip.Addr) tcpip.NetworkProtocolNumber {
	if a.Is6() {
		return ipv6.ProtocolNumber
	}
	return ipv4.ProtocolNumber
}

// AddAddress adds a site transit address (one per edge).
func (t *netstackTUN) AddAddress(p netip.Prefix) error {
	t.addrMu.Lock()
	defer t.addrMu.Unlock()
	for _, a := range t.addrs {
		if a.Addr() == p.Addr() {
			return nil
		}
	}
	if err := t.stack.AddProtocolAddress(nicID, tcpip.ProtocolAddress{
		Protocol:          netProto(p.Addr()),
		AddressWithPrefix: tcpip.AddrFromSlice(p.Addr().AsSlice()).WithPrefix(),
	}, stack.AddressProperties{}); err != nil {
		return fmt.Errorf("netstack: add address %s: %v", p, err)
	}
	t.addrs = append(t.addrs, p)
	return nil
}

// RemoveAddress removes a site transit address.
func (t *netstackTUN) RemoveAddress(p netip.Prefix) error {
	t.addrMu.Lock()
	defer t.addrMu.Unlock()
	for i, a := range t.addrs {
		if a.Addr() == p.Addr() {
			t.addrs = append(t.addrs[:i], t.addrs[i+1:]...)
			if err := t.stack.RemoveAddress(nicID, tcpip.AddrFromSlice(p.Addr().AsSlice())); err != nil {
				return fmt.Errorf("netstack: remove address %s: %v", p, err)
			}
			return nil
		}
	}
	return nil
}

// source picks the transit address on the same network as dst, so each
// edge sees requests from its own site address.
func (t *netstackTUN) source(dst netip.Addr) (netip.Addr, bool) {
	t.addrMu.Lock()
	defer t.addrMu.Unlock()
	for _, a := range t.addrs {
		if a.Contains(dst) {
			return a.Addr(), true
		}
	}
	return netip.Addr{}, false
}

// DialTCP connects to addr through the tunnel (used by the control channel).
func (t *netstackTUN) DialTCP(ctx context.Context, addr string) (net.Conn, error) {
	ap, err := netip.ParseAddrPort(addr)
	if err != nil {
		return nil, err
	}
	remote := tcpip.FullAddress{NIC: nicID, Addr: tcpip.AddrFromSlice(ap.Addr().AsSlice()), Port: ap.Port()}
	if src, ok := t.source(ap.Addr()); ok {
		return gonet.DialTCPWithBind(ctx, t.stack, tcpip.FullAddress{NIC: nicID, Addr: tcpip.AddrFromSlice(src.AsSlice())}, remote, netProto(ap.Addr()))
	}
	return gonet.DialContextTCP(ctx, t.stack, remote, netProto(ap.Addr()))
}

// target returns the real address a forwarded flow is for, if allowed.
func (t *netstackTUN) target(id stack.TransportEndpointID) (string, bool) {
	a, ok := netip.AddrFromSlice(id.LocalAddress.AsSlice())
	if !ok {
		return "", false
	}
	a = a.Unmap()
	for _, p := range t.allowed {
		if p.Contains(a) {
			return net.JoinHostPort(a.String(), strconv.Itoa(int(id.LocalPort))), true
		}
	}
	return "", false
}

func (t *netstackTUN) forwardTCP(r *tcp.ForwarderRequest) {
	dst, ok := t.target(r.ID())
	if !ok {
		r.Complete(true)
		return
	}
	// Dial first so a closed port is reported to the edge as a reset.
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		out, err := t.dial(ctx, "tcp", dst)
		cancel()
		if err != nil {
			t.log.Debug("netstack: dial failed", "target", dst, "err", err)
			r.Complete(true)
			return
		}
		var wq waiter.Queue
		ep, terr := r.CreateEndpoint(&wq)
		if terr != nil {
			r.Complete(true)
			out.Close()
			return
		}
		r.Complete(false)
		in := gonet.NewTCPConn(&wq, ep)
		splice(in, out)
	}()
}

// splice copies both ways and closes both connections when done.
func splice(a, b net.Conn) {
	done := make(chan struct{}, 2)
	cp := func(dst, src net.Conn) {
		_, _ = io.Copy(dst, src)
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
		done <- struct{}{}
	}
	go cp(a, b)
	go cp(b, a)
	<-done
	// Give the other direction a moment to drain after a half-close.
	select {
	case <-done:
	case <-time.After(30 * time.Second):
	}
	a.Close()
	b.Close()
}

// udpIdle closes forwarded UDP flows after this long without traffic.
const udpIdle = 2 * time.Minute

func (t *netstackTUN) forwardUDP(r *udp.ForwarderRequest) {
	dst, ok := t.target(r.ID())
	if !ok {
		return
	}
	var wq waiter.Queue
	ep, terr := r.CreateEndpoint(&wq)
	if terr != nil {
		return
	}
	in := gonet.NewUDPConn(&wq, ep)
	out, err := net.Dial("udp", dst)
	if err != nil {
		in.Close()
		return
	}
	go func() {
		defer in.Close()
		defer out.Close()
		cp := func(dst, src net.Conn) {
			buf := make([]byte, 65535)
			for {
				_ = src.SetReadDeadline(time.Now().Add(udpIdle))
				n, err := src.Read(buf)
				if err != nil {
					break
				}
				if _, err := dst.Write(buf[:n]); err != nil {
					break
				}
			}
			in.Close()
			out.Close()
		}
		go cp(out, in)
		cp(in, out)
	}()
}

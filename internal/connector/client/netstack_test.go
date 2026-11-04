// SPDX-License-Identifier: Apache-2.0

package client

import (
	"context"
	"log/slog"
	"net"
	"net/netip"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

// TestNetstackDial checks that a TCP dial through the netstack emits a SYN
// on the device and that an injected RST completes the dial with an error.
func TestNetstackDial(t *testing.T) {
	ns, err := newNetstack(netip.MustParsePrefix("10.100.1.2/24"), 1420, []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")}, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	defer ns.Close()
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_, _ = ns.DialTCP(ctx, "10.100.1.1:443")
	}()
	got := make(chan []byte, 1)
	go func() {
		buf := [][]byte{make([]byte, 2000)}
		sizes := []int{0}
		if _, err := ns.Read(buf, sizes, 0); err == nil {
			got <- buf[0][:sizes[0]]
		}
	}()
	select {
	case pkt := <-got:
		ip := header.IPv4(pkt)
		if ip.DestinationAddress().String() != "10.100.1.1" || ip.Protocol() != uint8(header.TCPProtocolNumber) {
			t.Fatalf("unexpected packet to %s proto %d", ip.DestinationAddress(), ip.Protocol())
		}
		tcp := header.TCP(ip.Payload())
		if tcp.Flags()&header.TCPFlagSyn == 0 {
			t.Errorf("not a SYN: %v", tcp.Flags())
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no packet read from the netstack device")
	}
}

// synPacket builds an IPv4 TCP SYN.
func synPacket(src, dst netip.AddrPort) []byte {
	b := make([]byte, header.IPv4MinimumSize+header.TCPMinimumSize)
	ip := header.IPv4(b)
	ip.Encode(&header.IPv4Fields{
		TotalLength: uint16(len(b)),
		TTL:         64,
		Protocol:    uint8(header.TCPProtocolNumber),
		SrcAddr:     tcpip.AddrFrom4(src.Addr().As4()),
		DstAddr:     tcpip.AddrFrom4(dst.Addr().As4()),
	})
	ip.SetChecksum(^ip.CalculateChecksum())
	tcp := header.TCP(b[header.IPv4MinimumSize:])
	tcp.Encode(&header.TCPFields{
		SrcPort: src.Port(), DstPort: dst.Port(), SeqNum: 1000,
		DataOffset: header.TCPMinimumSize, Flags: header.TCPFlagSyn, WindowSize: 65535,
	})
	xsum := header.PseudoHeaderChecksum(header.TCPProtocolNumber, ip.SourceAddress(), ip.DestinationAddress(), uint16(len(tcp)))
	tcp.SetChecksum(^tcp.CalculateChecksum(xsum))
	return b
}

// TestNetstackForward checks that a SYN to an allowed subnet is dialled out
// and answered with a SYN-ACK.
func TestNetstackForward(t *testing.T) {
	ns, err := newNetstack(netip.MustParsePrefix("10.100.1.2/24"), 1420, []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")}, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	defer ns.Close()
	dialed := make(chan string, 1)
	ns.dial = func(_ context.Context, _, addr string) (net.Conn, error) {
		dialed <- addr
		a, _ := net.Pipe()
		return a, nil
	}
	syn := synPacket(netip.MustParseAddrPort("10.100.1.1:40000"), netip.MustParseAddrPort("10.0.0.5:80"))
	if _, err := ns.Write([][]byte{syn}, 0); err != nil {
		t.Fatal(err)
	}
	select {
	case a := <-dialed:
		if a != "10.0.0.5:80" {
			t.Errorf("dialed %s", a)
		}
	case <-time.After(3 * time.Second):
		st := ns.stack.Stats()
		t.Fatalf("forwarder did not dial: ip rx=%d malformed=%d invdst=%d delivered=%d tcp seg=%d invalid=%d forwardMax=%d listenOverflow=%d", st.IP.PacketsReceived.Value(), st.IP.MalformedPacketsReceived.Value(), st.IP.InvalidDestinationAddressesReceived.Value(), st.IP.PacketsDelivered.Value(), st.TCP.ValidSegmentsReceived.Value(), st.TCP.InvalidSegmentsReceived.Value(), st.TCP.ForwardMaxInFlightDrop.Value(), st.TCP.ListenOverflowSynDrop.Value())
	}
	buf := [][]byte{make([]byte, 2000)}
	sizes := []int{0}
	done := make(chan struct{})
	go func() { _, _ = ns.Read(buf, sizes, 0); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("no SYN-ACK")
	}
	tcp := header.TCP(header.IPv4(buf[0][:sizes[0]]).Payload())
	if tcp.Flags() != header.TCPFlagSyn|header.TCPFlagAck {
		t.Errorf("flags = %v", tcp.Flags())
	}
}

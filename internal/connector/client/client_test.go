// SPDX-License-Identifier: Apache-2.0

package client

import (
	"context"
	"encoding/hex"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/ingressd/ingressd/internal/connector"
	"github.com/ingressd/ingressd/internal/connector/proto"
)

func TestParseUAPIStats(t *testing.T) {
	k1, _ := wgtypes.GeneratePrivateKey()
	k2, _ := wgtypes.GeneratePrivateKey()
	p1, p2 := k1.PublicKey(), k2.PublicKey()
	dump := "private_key=abc\nlisten_port=1\npublic_key=" + hex.EncodeToString(p1[:]) +
		"\nlast_handshake_time_sec=1700000000\nlast_handshake_time_nsec=5\nrx_bytes=10\ntx_bytes=20\n" +
		"public_key=" + hex.EncodeToString(p2[:]) + "\nlast_handshake_time_sec=0\nlast_handshake_time_nsec=0\nrx_bytes=3\ntx_bytes=4\n"
	s := parseUAPIStats(dump)
	if len(s) != 2 {
		t.Fatalf("got %d peers: %+v", len(s), s)
	}
	if a := s[p1]; a.LastHandshake != time.Unix(1700000000, 5) || a.RxBytes != 10 || a.TxBytes != 20 {
		t.Errorf("peer 1: %+v", a)
	}
	if b := s[p2]; !b.LastHandshake.IsZero() || b.RxBytes != 3 || b.TxBytes != 4 {
		t.Errorf("peer 2: %+v", b)
	}
}

func TestPeerChangedAndShared(t *testing.T) {
	a := proto.TunnelConfig{Tunnel: "x", Endpoint: "e:1", Subnets: []string{"10.0.0.0/24"}, Targets: []string{"a:1"}, Revision: "1"}
	b := a
	b.Targets, b.Revision = []string{"b:2"}, "2"
	b.Siblings = []proto.Sibling{{EdgePublicKey: "k"}}
	if peerChanged(a, b) {
		t.Error("target/sibling-only change should not restart the peer")
	}
	b.Endpoint = "e:2"
	if !peerChanged(a, b) {
		t.Error("endpoint change should restart the peer")
	}
	st := &State{Edges: []EdgeState{{Config: a}}}
	before := sharedSettings(st)
	st.Edges[0].Config.Targets = []string{"c:3"}
	if sharedSettings(st) != before {
		t.Error("targets are not a shared setting")
	}
	st.Edges[0].Config.Subnets = []string{"10.0.1.0/24"}
	if sharedSettings(st) == before {
		t.Error("subnet change should rebuild the link")
	}
}

func TestICMPChecksum(t *testing.T) {
	b := icmpEcho(0x1234, 1, 13)
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(b[i])<<8 | uint32(b[i+1])
	}
	sum += uint32(b[len(b)-1]) << 8
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	if uint16(sum) != 0xffff {
		t.Errorf("checksum does not verify: %#x", sum)
	}
}

// TestRelay runs the connector-side relay against the edge-side bridge: a
// datagram sent to the relay's loopback endpoint reaches the "WireGuard"
// listener and its reply comes back to the sender.
func TestRelay(t *testing.T) {
	wg, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer wg.Close()
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := wg.ReadFromUDP(buf)
			if err != nil {
				return
			}
			_, _ = wg.WriteToUDP(append([]byte("re:"), buf[:n]...), from)
		}
	}()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		udp, err := net.DialUDP("udp", nil, wg.LocalAddr().(*net.UDPAddr))
		if err != nil {
			t.Error(err)
			return
		}
		ws, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		_ = connector.Bridge(r.Context(), ws, udp)
	}))
	defer ts.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	relay, err := dialRelay(ctx, "ws"+strings.TrimPrefix(ts.URL, "http"), http.DefaultClient, nil, func(netip.AddrPort) bool { return true })
	if err != nil {
		t.Fatal(err)
	}
	defer relay.Close()
	c, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(relay.Endpoint()))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 100)
	n, err := c.Read(buf)
	if err != nil || string(buf[:n]) != "re:ping" {
		t.Fatalf("got %q, %v", buf[:n], err)
	}
}

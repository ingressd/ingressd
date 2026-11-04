// SPDX-License-Identifier: Apache-2.0

package nodeagent

import (
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/ingressd/ingressd/internal/tunnel"
	"github.com/ingressd/ingressd/pkg/config"
	"github.com/ingressd/ingressd/pkg/nodeproto"
)

func l4Cfg(t *testing.T, preset string, listen []string, port int) *config.Config {
	t.Helper()
	// Parsed but not validated: the target is loopback, which a real
	// config cannot route through a tunnel.
	cfg, err := config.Parse([]byte(fmt.Sprintf(`version: 1
tunnels:
  home: {site: router, listen_port: 51820, transit: 100.64.0.0/30}
l4:
  game:
    preset: %s
    listen: [%s]
    target: {tunnel: home, address: 127.0.0.1, port: %d}
    mode: proxy
    proxy_protocol: none
`, preset, strings.Join(listen, ", "), port)))
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func tunnelUp(t *testing.T, healthy bool) {
	t.Helper()
	prev := readTunnelStatus
	t.Cleanup(func() { readTunnelStatus = prev })
	readTunnelStatus = func(*config.Config) ([]tunnel.Status, error) {
		st := tunnel.Status{Tunnel: "home", Up: true}
		if healthy {
			st.LastHandshake = time.Now()
		}
		return []tunnel.Status{st}, nil
	}
}

func TestDiagnoseL4TCP(t *testing.T) {
	tunnelUp(t, true)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	port := ln.Addr().(*net.TCPAddr).Port
	// The TCP port is probed even when a UDP port is listed first.
	cfg := l4Cfg(t, "custom", []string{"25000/udp", "25000/tcp"}, port)
	r := DiagnoseL4(context.Background(), cfg, "game", 2*time.Second)
	if r.Code != nodeproto.DiagCodeOK || len(r.Steps) != 3 || r.Steps[2].Name != "connect" {
		t.Fatalf("tcp ok: %+v", r)
	}
	_ = ln.Close()
	r = DiagnoseL4(context.Background(), cfg, "game", 2*time.Second)
	if r.Code != nodeproto.DiagCodeRefused {
		t.Errorf("tcp refused: %+v", r)
	}
	if r := DiagnoseL4(context.Background(), cfg, "nope", time.Second); r.Code != "error" {
		t.Errorf("unknown service: %+v", r)
	}
}

func TestDiagnoseL4TunnelDown(t *testing.T) {
	tunnelUp(t, false)
	r := DiagnoseL4(context.Background(), l4Cfg(t, "custom", []string{"25565/tcp"}, 25565), "game", time.Second)
	if r.Code != nodeproto.DiagCodeTunnelDown || len(r.Steps) != 2 || r.Steps[1].Name != "tunnel" {
		t.Errorf("tunnel down: %+v", r)
	}
}

func TestDiagnoseL4UDP(t *testing.T) {
	tunnelUp(t, true)
	// A Bedrock server answers the unconnected ping with a pong.
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			if n == 33 && buf[0] == 0x01 {
				pong := append([]byte{0x1c}, buf[1:9]...)
				pong = append(pong, make([]byte, 8)...)
				pong = append(pong, raknetMagic...)
				pong = append(pong, []byte("MCPE;ingressd;")...)
				_, _ = pc.WriteTo(pong, from)
			}
		}
	}()
	port := pc.LocalAddr().(*net.UDPAddr).Port
	r := DiagnoseL4(context.Background(), l4Cfg(t, "minecraft_bedrock", []string{"19132/udp"}, port), "game", 2*time.Second)
	if r.Code != nodeproto.DiagCodeOK || !strings.Contains(r.Steps[len(r.Steps)-1].Detail, "Bedrock pong") {
		t.Fatalf("bedrock: %+v", r)
	}
	// Silence is fine for UDP games that ignore unknown packets.
	silent, _ := net.ListenPacket("udp", "127.0.0.1:0")
	defer silent.Close()
	r = DiagnoseL4(context.Background(), l4Cfg(t, "custom", []string{"2456/udp"}, silent.LocalAddr().(*net.UDPAddr).Port), "game", 2*time.Second)
	if r.Code != nodeproto.DiagCodeOK || !strings.Contains(r.Message, "no reply expected") {
		t.Errorf("silent udp: %+v", r)
	}
	// A closed port answers ICMP port unreachable.
	closed, _ := net.ListenPacket("udp", "127.0.0.1:0")
	cport := closed.LocalAddr().(*net.UDPAddr).Port
	_ = closed.Close()
	r = DiagnoseL4(context.Background(), l4Cfg(t, "custom", []string{"2456/udp"}, cport), "game", 2*time.Second)
	if r.Code != nodeproto.DiagCodeRefused {
		t.Errorf("closed udp: %+v", r)
	}
}

func TestBedrockPing(t *testing.T) {
	p := BedrockPing(time.Unix(1, 0))
	if len(p) != 33 || p[0] != 0x01 || IsBedrockPong(p) {
		t.Fatalf("ping %x", p)
	}
}

// SPDX-License-Identifier: Apache-2.0

package nodeagent

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"syscall"
	"time"

	"github.com/ingressd/ingressd/internal/render"
	"github.com/ingressd/ingressd/internal/tunnel"
	"github.com/ingressd/ingressd/pkg/config"
	"github.com/ingressd/ingressd/pkg/nodeproto"
)

// DiagnoseL4 checks an l4 service's target from the edge, through the
// site's tunnel: the tunnel handshake, then a TCP connect to the target
// for the first TCP listen port, else a UDP probe for the first UDP port.
//
// UDP has no handshake: a reply (Minecraft Bedrock answers its unconnected
// ping) proves the server is up, an ICMP port unreachable means nothing
// listens, and silence is reported as ok ("sent, no reply expected"): most
// game servers ignore packets that are not their protocol.
func DiagnoseL4(ctx context.Context, cfg *config.Config, name string, timeout time.Duration) nodeproto.DiagResult {
	var s stepper
	s.begin()
	svc, ok := cfg.L4[name]
	if !ok {
		s.end("edge", false, "unknown l4 service %q", name)
		return s.result("error", "unknown l4 service %q", name)
	}
	ports := svc.Ports()
	if len(ports) == 0 {
		s.end("edge", false, "no listen ports")
		return s.result("error", "l4 service %q has no listen ports", name)
	}
	addr, err := netip.ParseAddr(svc.Target.Address)
	if err != nil {
		s.end("edge", false, "invalid target %q", svc.Target.Address)
		return s.result("error", "l4 service %q has an invalid target address", name)
	}
	// Remapped tunnels: the edge reaches the site through the virtual
	// prefix (the same address caddy-l4 dials).
	addr = render.Virtual(cfg.Tunnels[svc.Target.Tunnel], addr)
	probe := ports[0]
	for _, p := range ports {
		if p.Proto == "tcp" {
			probe = p
			break
		}
	}
	dial := net.JoinHostPort(addr.String(), strconv.Itoa(svc.TargetPort(probe.Port)))
	s.end("edge", true, "%s → %s/%s", probe, dial, probe.Proto)

	if res, ok := checkTunnel(&s, cfg, svc.Target.Tunnel); !ok {
		return res
	}

	connectTimeout := min(5*time.Second, timeout/2)
	if probe.Proto == "tcp" {
		s.begin()
		d := net.Dialer{Timeout: connectTimeout}
		conn, err := d.DialContext(ctx, "tcp", dial)
		if err != nil {
			code, msg := classifyDialError(err)
			s.end("connect", false, "%s: %v", dial, err)
			return s.result(code, "%s", msg)
		}
		_ = conn.Close()
		s.end("connect", true, "TCP connected to %s", dial)
		return s.result(nodeproto.DiagCodeOK, "target %s accepts TCP connections", dial)
	}
	return probeUDP(ctx, &s, dial, svc.Preset, connectTimeout)
}

// checkTunnel adds the "tunnel" step; ok is false (with the result to
// return) when the site is not connected.
func checkTunnel(s *stepper, cfg *config.Config, tun string) (nodeproto.DiagResult, bool) {
	if tun == "" {
		return nodeproto.DiagResult{}, true
	}
	s.begin()
	sts, err := readTunnelStatus(cfg)
	var st *tunnel.Status
	for i := range sts {
		if sts[i].Tunnel == tun {
			st = &sts[i]
		}
	}
	now := time.Now()
	switch {
	case err != nil:
		s.end("tunnel", false, "reading WireGuard state: %v", err)
		return s.result(nodeproto.DiagCodeTunnelDown, "could not read tunnel %s: %v", tun, err), false
	case st == nil || !st.Up:
		s.end("tunnel", false, "interface for %s is not up", tun)
		return s.result(nodeproto.DiagCodeTunnelDown, "tunnel %s is not up on the edge", tun), false
	case !st.Healthy(now):
		detail := "no handshake yet"
		if !st.LastHandshake.IsZero() {
			detail = fmt.Sprintf("last handshake %s ago", now.Sub(st.LastHandshake).Round(time.Second))
		}
		s.end("tunnel", false, "%s", detail)
		return s.result(nodeproto.DiagCodeTunnelDown, "site %s is not connected (%s)", tun, detail), false
	}
	s.end("tunnel", true, "handshake %s ago", now.Sub(st.LastHandshake).Round(time.Second))
	return nodeproto.DiagResult{}, true
}

// raknetMagic is RakNet's offline message id (Minecraft Bedrock).
var raknetMagic = []byte{0x00, 0xff, 0xff, 0x00, 0xfe, 0xfe, 0xfe, 0xfe, 0xfd, 0xfd, 0xfd, 0xfd, 0x12, 0x34, 0x56, 0x78}

// BedrockPing is a RakNet unconnected ping (id 0x01, time, magic, GUID).
func BedrockPing(now time.Time) []byte {
	b := make([]byte, 0, 33)
	b = append(b, 0x01)
	b = binary.BigEndian.AppendUint64(b, uint64(now.UnixMilli()))
	b = append(b, raknetMagic...)
	b = binary.BigEndian.AppendUint64(b, 0x686f6d6565646765) // "ingressd"
	return b
}

// IsBedrockPong reports whether b is a RakNet unconnected pong (id 0x1c).
func IsBedrockPong(b []byte) bool {
	return len(b) >= 33 && b[0] == 0x1c && string(b[17:33]) == string(raknetMagic)
}

func probeUDP(ctx context.Context, s *stepper, dial, preset string, wait time.Duration) nodeproto.DiagResult {
	s.begin()
	var d net.Dialer
	conn, err := d.DialContext(ctx, "udp", dial)
	if err != nil {
		code, msg := classifyDialError(err)
		s.end("probe", false, "%s: %v", dial, err)
		return s.result(code, "%s", msg)
	}
	defer conn.Close()
	bedrock := preset == config.PresetMinecraftBedrock
	payload := []byte{0}
	if bedrock {
		payload = BedrockPing(time.Now())
	}
	deadline := time.Now().Add(wait)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	_ = conn.SetDeadline(deadline)
	if _, err := conn.Write(payload); err != nil {
		code, msg := classifyDialError(err)
		s.end("probe", false, "%s: %v", dial, err)
		return s.result(code, "%s", msg)
	}
	buf := make([]byte, 2048)
	n, err := conn.Read(buf)
	var ne net.Error
	switch {
	case err == nil && bedrock && !IsBedrockPong(buf[:n]):
		s.end("probe", true, "UDP reply from %s (%d bytes, not a Bedrock pong)", dial, n)
		return s.result(nodeproto.DiagCodeOK, "target %s answered over UDP", dial)
	case err == nil:
		what := "UDP reply"
		if bedrock {
			what = "Bedrock pong"
		}
		s.end("probe", true, "%s from %s (%d bytes)", what, dial, n)
		return s.result(nodeproto.DiagCodeOK, "target %s answered over UDP", dial)
	case errors.Is(err, syscall.ECONNREFUSED):
		s.end("probe", false, "%s: port unreachable", dial)
		return s.result(nodeproto.DiagCodeRefused, "the target answered port unreachable: nothing is listening on UDP %s", dial)
	case errors.As(err, &ne) && ne.Timeout():
		s.end("probe", true, "UDP sent to %s, no reply (expected for most games)", dial)
		return s.result(nodeproto.DiagCodeOK, "UDP sent to %s, no reply expected", dial)
	default:
		code, msg := classifyDialError(err)
		s.end("probe", false, "%s: %v", dial, err)
		return s.result(code, "%s", msg)
	}
}

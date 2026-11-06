// SPDX-License-Identifier: Apache-2.0

package client

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/ingressd/ingressd/internal/connector/proto"
)

// fakeLink reports every peer in up as handshaken now and dials dialTo
// for any tunnel address.
type fakeLink struct {
	up     map[wgtypes.Key]bool
	dialTo string
	dialed []string
}

func (l *fakeLink) SetPeer(peerConfig, bool) error   { return nil }
func (l *fakeLink) RemovePeer(wgtypes.Key) error     { return nil }
func (l *fakeLink) AddAddress(netip.Prefix) error    { return nil }
func (l *fakeLink) RemoveAddress(netip.Prefix) error { return nil }
func (l *fakeLink) SetMTU(int) error                 { return nil }
func (l *fakeLink) MTU() int                         { return 1420 }
func (l *fakeLink) ListenPort() (int, error)         { return 0, nil }
func (l *fakeLink) Kind() string                     { return "fake" }
func (l *fakeLink) Close() error                     { return nil }
func (l *fakeLink) Stats() (map[wgtypes.Key]peerStats, error) {
	out := map[wgtypes.Key]peerStats{}
	for k, up := range l.up {
		if up {
			out[k] = peerStats{LastHandshake: time.Now()}
		}
	}
	return out, nil
}
func (l *fakeLink) DialTunnel(ctx context.Context, addr string) (net.Conn, error) {
	l.dialed = append(l.dialed, addr)
	if l.dialTo == "" {
		return nil, errors.New("unreachable")
	}
	var d net.Dialer
	return d.DialContext(ctx, "tcp", l.dialTo)
}

func TestEWMA(t *testing.T) {
	var e ewma
	if e.value() != 0 {
		t.Fatal("unmeasured value")
	}
	e.add(100 * time.Millisecond)
	if e.value() != 100*time.Millisecond {
		t.Fatalf("first sample %v", e.value())
	}
	e.add(200 * time.Millisecond) // 0.3*200 + 0.7*100
	if d := e.value() - 130*time.Millisecond; d > time.Microsecond || d < -time.Microsecond {
		t.Fatalf("second sample %v", e.value())
	}
	for range 50 {
		e.add(20 * time.Millisecond)
	}
	if d := e.value() - 20*time.Millisecond; d > time.Microsecond || d < -time.Microsecond {
		t.Fatalf("converged to %v", e.value())
	}
	e.reset()
	if e.value() != 0 {
		t.Fatal("reset")
	}
	if millis(12345678*time.Nanosecond) != 12.35 {
		t.Errorf("millis %v", millis(12345678*time.Nanosecond))
	}
}

func TestCompareRank(t *testing.T) {
	ms := time.Millisecond
	cases := []struct {
		a, b edgeRank
		want int
	}{
		{edgeRank{0, 50 * ms}, edgeRank{1, 5 * ms}, -1}, // priority wins over RTT
		{edgeRank{1, 5 * ms}, edgeRank{1, 50 * ms}, -1},
		{edgeRank{1, 5 * ms}, edgeRank{1, 0}, -1}, // unknown RTT last
		{edgeRank{1, 0}, edgeRank{1, 0}, 0},
		{edgeRank{2, 0}, edgeRank{1, 0}, 1},
	}
	for _, c := range cases {
		if got := compareRank(c.a, c.b); got != c.want {
			t.Errorf("compare(%v, %v) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

// rttSession builds a session with three running edges A, B, C (state
// order) where B and C list each other and A with priorities.
func rttSession(t *testing.T) (*session, []*edge, *fakeLink) {
	t.Helper()
	var keys []wgtypes.Key
	for range 3 {
		k, _ := wgtypes.GeneratePrivateKey()
		keys = append(keys, k.PublicKey())
	}
	sib := func(i, prio int, pop string) proto.Sibling {
		return proto.Sibling{Node: string(rune('A' + i)), EdgePublicKey: keys[i].String(), Priority: prio, PoP: pop} //nolint:gosec // G115: i is a small test index
	}
	st := &State{}
	for i, k := range keys {
		es := EdgeState{Node: string(rune('A' + i)), Config: proto.TunnelConfig{EdgePublicKey: k.String(), EdgeAddress: "100.64.0.1"}}
		switch i {
		case 0:
			es.Config.Siblings = []proto.Sibling{sib(1, 1, "ams"), sib(2, 1, "lon")}
		case 1:
			es.Config.Siblings = []proto.Sibling{sib(0, 2, "nyc"), sib(2, 1, "lon")}
		}
		st.Edges = append(st.Edges, es)
	}
	l := &fakeLink{up: map[wgtypes.Key]bool{}}
	s := &session{st: st, edges: map[wgtypes.Key]*edge{}, link: l, mode: ModeTUN, upd: &updater{}, log: slog.New(slog.DiscardHandler),
		r: &Runner{StatePath: filepath.Join(t.TempDir(), "connector.json")}}
	var edges []*edge
	for i, k := range keys {
		e := &edge{s: s, key: k, cfg: st.Edges[i], kick: make(chan struct{}, 1)}
		s.edges[k] = e
		edges = append(edges, e)
	}
	return s, edges, l
}

func names(es []*edge) string {
	var b strings.Builder
	for _, e := range es {
		b.WriteString(e.cfg.Node)
	}
	return b.String()
}

func TestRankedEdges(t *testing.T) {
	s, e, _ := rttSession(t)
	if got := names(s.rankedEdges()); got != "BCA" { // A has priority 2; B, C tie: state order
		t.Errorf("unmeasured order %s", got)
	}
	e[2].rtt.add(10 * time.Millisecond)
	e[1].rtt.add(30 * time.Millisecond)
	e[0].rtt.add(time.Millisecond)
	if got := names(s.rankedEdges()); got != "CBA" {
		t.Errorf("measured order %s", got)
	}
	if info := siblingInfo(s.st); info[e[0].key.String()].PoP != "nyc" || info[e[2].key.String()].Priority != 1 {
		t.Errorf("sibling info %+v", info)
	}
}

func TestMeasureRTTAndReports(t *testing.T) {
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
	s, e, l := rttSession(t)
	if e[0].measureRTT(context.Background()) {
		t.Fatal("measured over a tunnel that is down")
	}
	l.up[e[0].key], l.up[e[1].key] = true, true
	l.dialTo = ln.Addr().String()
	if !e[0].measureRTT(context.Background()) || e[0].rttValue() <= 0 {
		t.Fatal("no sample")
	}
	if len(l.dialed) != 1 || l.dialed[0] != "100.64.0.1:51819" {
		t.Errorf("dialed %v", l.dialed)
	}
	e[0].transport, e[1].transport = proto.TransportUDP, proto.TransportWebSocket
	reps := s.edgeReports()
	if len(reps) != 3 || reps[2].Node != "A" || !reps[2].Up || reps[2].RTTMillis <= 0 || reps[2].Transport != "udp" ||
		reps[0].Node != "B" || !reps[0].Up || reps[0].RTTMillis != 0 || reps[1].Up {
		t.Errorf("reports %+v", reps)
	}
	b, _ := json.Marshal(proto.Health{Mode: "tun", Edges: reps[:2]})
	for _, want := range []string{`"edges":[{"node":"B","edge_public_key":"` + e[1].key.String() + `","up":true,"transport":"websocket"}`, `"node":"C"`} {
		if !strings.Contains(string(b), want) {
			t.Errorf("missing %s in %s", want, b)
		}
	}
	e[0].setTransport(proto.TransportWebSocket, "wss://x", wsMTU)
	if e[0].rttValue() != 0 {
		t.Error("RTT kept across a transport change")
	}
}

func TestSnapshotBestByRank(t *testing.T) {
	s, e, l := rttSession(t)
	for _, x := range e {
		l.up[x.key] = true
		x.transport = proto.TransportUDP
	}
	e[0].rtt.add(time.Millisecond)
	e[1].rtt.add(40 * time.Millisecond)
	e[2].rtt.add(20 * time.Millisecond)
	st := s.snapshot()
	if st.Transport != proto.TransportUDP {
		t.Fatalf("summary %+v", st)
	}
	if len(st.Edges) != 3 || st.Edges[0].Priority != 2 || st.Edges[0].PoP != "nyc" {
		t.Fatalf("edges %+v", st.Edges)
	}
	e[2].endpoint = "c:51820"
	if st := s.snapshot(); st.Endpoint != "c:51820" {
		t.Errorf("best edge endpoint %q, want C's", st.Endpoint)
	}
}

func TestOwnerByRankWithHysteresis(t *testing.T) {
	s, e, l := rttSession(t)
	s.st.Edges[0].Config.Transparent = []string{"tcp/192.168.0.17:25565"}
	s.st.reach = reachOf("192.168.0.0/24")
	for _, x := range e {
		l.up[x.key] = true
	}
	e[0].rtt.add(time.Millisecond)
	e[1].rtt.add(40 * time.Millisecond)
	e[2].rtt.add(20 * time.Millisecond)
	s.updateOwner()
	if s.owner != e[2].key {
		t.Fatalf("owner %v, want C (priority 1, lowest RTT)", s.owner)
	}
	e[2].rtt.reset()
	e[2].rtt.add(500 * time.Millisecond)
	s.updateOwner()
	if s.owner != e[2].key {
		t.Fatal("owner moved while it is still up")
	}
	l.up[e[2].key] = false
	s.updateOwner()
	if s.owner != e[1].key {
		t.Fatalf("owner %v after C went down, want B", s.owner)
	}
}

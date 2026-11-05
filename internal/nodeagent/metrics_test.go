// SPDX-License-Identifier: Apache-2.0

package nodeagent

import (
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ingressd/ingressd/internal/observe"
	"github.com/ingressd/ingressd/pkg/nodeproto"
)

func fixture(t *testing.T, rel string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "metrics", "proc", rel))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func near(a, b float64) bool { return math.Abs(a-b) < 1e-6 }

func TestProcParsers(t *testing.T) {
	c, cores, err := parseProcStat(fixture(t, "stat"))
	if err != nil || cores != 2 || c.user != 1000 || c.steal != 300 || c.total() != 9980 {
		t.Errorf("stat: %+v cores=%d err=%v", c, cores, err)
	}
	if l, err := parseLoadavg(fixture(t, "loadavg")); err != nil || l != [3]float64{0.52, 0.40, 0.31} {
		t.Errorf("loadavg: %v %v", l, err)
	}
	m, err := parseMeminfo(fixture(t, "meminfo"))
	if err != nil || m.total != 4000000*1024 || m.available != 3000000*1024 || m.swapTotal-m.swapFree != 250000*1024 {
		t.Errorf("meminfo: %+v %v", m, err)
	}
	ifs := parseNetDev(fixture(t, "net/dev"))
	if e := ifs["eth0"]; e.rxBytes != 1000000 || e.txPackets != 3000 || e.rxDrop != 2 || e.txErrs != 3 {
		t.Errorf("eth0: %+v", e)
	}
	if o := ifs["ix-office"]; o.rxBytes != 20000 || o.txBytes != 40000 {
		t.Errorf("ix-office (no space after colon): %+v", o)
	}
	if len(ifs) != 5 {
		t.Errorf("interfaces: %v", ifs)
	}
	if r := parseRoute(fixture(t, "net/route")); r != "eth0" {
		t.Errorf("default route iface %q", r)
	}
	est, web := parseTCP(fixture(t, "net/tcp"), webPorts)
	if est != 3 || web != 2 {
		t.Errorf("tcp: established %d web %d", est, web)
	}
	if est, web := parseTCP(fixture(t, "net/tcp6"), webPorts); est != 1 || web != 1 {
		t.Errorf("tcp6: established %d web %d", est, web)
	}
	if r, w, ok := parseDiskstats(fixture(t, "diskstats"), "sdb1"); !ok || r != 58000 || w != 78000 {
		t.Errorf("diskstats: %d %d %v", r, w, ok)
	}
	mounts := fixture(t, "self/mounts")
	for path, want := range map[string]string{
		"/var/lib/ingressd":     "sdb1",
		"/var/lib/ingressd/tmp": "", // tmpfs: no block device
		"/etc":                  "root",
		"/var/library":          "root", // not under /var/lib
	} {
		if got := parseMounts(mounts, path); got != want {
			t.Errorf("mount device of %s = %q, want %q", path, got, want)
		}
	}
	if n, ok := parseStatusRSS(fixture(t, "self/status")); !ok || n != 65536*1024 {
		t.Errorf("rss %d %v", n, ok)
	}
}

func TestSysReaderFixture(t *testing.T) {
	r := &sysReader{root: filepath.Join("testdata", "metrics"), stateDir: "/var/lib/ingressd"}
	s := r.read(time.Unix(1000, 0))
	if s.cpu == nil || s.cores != 2 || s.load == nil || s.mem == nil || s.pubIface != "eth0" {
		t.Fatalf("sample %+v", s)
	}
	if s.tcp == nil || s.tcp[0] != 4 || s.tcp[1] != 3 {
		t.Errorf("tcp %v", s.tcp)
	}
	if s.ctCount == nil || *s.ctCount != 1234 || s.ctMax != 262144 {
		t.Errorf("conntrack %v %d", s.ctCount, s.ctMax)
	}
	if s.diskDev != "sdb1" || s.disk == nil {
		t.Errorf("disk %q %v", s.diskDev, s.disk)
	}
	if s.agentRSS == nil || *s.agentRSS != 65536*1024 || s.edgeRSS == nil || *s.edgeRSS != 131072*1024 {
		t.Errorf("rss agent %v edge %v", s.agentRSS, s.edgeRSS)
	}
}

func TestDiffRates(t *testing.T) {
	t0 := time.Unix(1000, 0)
	prev := &rawSample{
		at:   t0,
		cpu:  &cpuTimes{user: 100, idle: 800, iowait: 50, steal: 50},
		disk: &[2]uint64{1000, 2000}, diskDev: "sda1",
		pubIface: "eth0",
		ifs: map[string]ifCounters{
			"eth0":    {rxBytes: 1000, txBytes: 2000, rxPackets: 10, txPackets: 20, rxDrop: 1},
			"ix-mesh": {rxBytes: 0},
			"ix-a":    {rxBytes: 100, txBytes: 100},
			"ix-b":    {rxBytes: 100, txBytes: 100},
		},
	}
	cur := &rawSample{
		at:   t0.Add(10 * time.Second),
		cpu:  &cpuTimes{user: 300, idle: 1500, iowait: 100, steal: 100}, // +1000 jiffies
		disk: &[2]uint64{1200, 2400}, diskDev: "sda1",
		pubIface: "eth0",
		mem:      &memInfo{total: 1000, available: 400, swapTotal: 100, swapFree: 60},
		ifs: map[string]ifCounters{
			"eth0":    {rxBytes: 11000, txBytes: 2000 + 5000, rxPackets: 110, txPackets: 70, rxDrop: 3, txErrs: 2},
			"ix-mesh": {rxBytes: 1250},
			"ix-a":    {rxBytes: 1100, txBytes: 600},
			"ix-b":    {rxBytes: 50, txBytes: 100}, // counter reset: no change
			"ix-new":  {rxBytes: 99999},            // not in prev: skipped
		},
	}
	p := diff(prev, cur, &observe.MetricsWindow{Requests: 50}, nil)
	g := p.gauges
	for k, want := range map[string]float64{
		gCPU: 25, gSteal: 5, gIOWait: 5,
		gDiskR: 200 * 512 / 10, gDiskW: 400 * 512 / 10,
		gMemUsed: 600, gMemAvail: 400, gSwap: 40,
		gRPS: 5,
	} {
		if !near(g[k], want) {
			t.Errorf("%s = %v, want %v", k, g[k], want)
		}
	}
	eth := p.ifs["eth0"]
	if eth.role != nodeproto.IfacePublic || !near(eth.rxBps, 8000) || !near(eth.txBps, 4000) || !near(eth.rxPps, 10) || !near(eth.txPps, 5) ||
		eth.drops != 2 || eth.errs != 2 {
		t.Errorf("eth0 %+v", eth)
	}
	if m := p.ifs[meshIfaceName]; m.role != nodeproto.IfaceMesh || !near(m.rxBps, 1000) {
		t.Errorf("mesh %+v", m)
	}
	if tu := p.ifs[tunnelsIfaceName]; tu.role != nodeproto.IfaceTunnels || !near(tu.rxBps, 800) || !near(tu.txBps, 400) {
		t.Errorf("tunnels %+v", tu)
	}
	if first := diff(nil, cur, nil, nil); first.gauges[gCPU] != 0 || len(first.ifs) != 0 || first.gauges[gMemUsed] != 600 {
		t.Errorf("first sample %+v", first)
	}
}

func TestWindowAggregation(t *testing.T) {
	t0 := time.Unix(1000, 0)
	w := newWindow(t0)
	load := [3]float64{1, 2, 3}
	for i, v := range []float64{10, 30, 20} {
		s := &rawSample{at: t0.Add(time.Duration(i+1) * 10 * time.Second), cores: 4, load: &load,
			mem: &memInfo{total: 100}, diskFree: 5, diskTotal: 10, ctMax: 99}
		lat := []time.Duration{}
		for j := 1; j <= 10; j++ {
			lat = append(lat, time.Duration(i*10+j)*time.Millisecond)
		}
		w.add(point{
			at: s.at, sys: s,
			gauges: map[string]float64{gCPU: v, gMemUsed: v * 2, gCT: v, gTCP: 1},
			ifs:    map[string]ifPoint{"eth0": {role: nodeproto.IfacePublic, rxBps: v, drops: 1}},
			edge: &observe.MetricsWindow{Requests: 10, Status5xx: 1, OriginErrors: 1, Latencies: lat,
				Hosts: map[string]observe.HostBytes{"a.example.com": {Requests: 1, BytesOut: 100}, "b.example.com": {BytesOut: int64(60 * (i + 1))}, "scan": {BytesOut: 1e9}}},
			tun: &nodeproto.TunnelMetrics{Up: i, Total: 3},
		})
	}
	appOf := func(h string) string {
		if h == "scan" {
			return ""
		}
		return strings.TrimSuffix(h, ".example.com")
	}
	m := w.metrics(appOf)
	if m.Samples != 3 || !m.From.Equal(t0) || !m.To.Equal(t0.Add(30*time.Second)) {
		t.Errorf("window %+v", m)
	}
	if m.CPU == nil || m.CPU.Cores != 4 || !near(m.CPU.Usage.Avg, 20) || m.CPU.Usage.Max != 30 || m.CPU.Load15 != 3 {
		t.Errorf("cpu %+v", m.CPU)
	}
	if m.Memory == nil || m.Memory.TotalBytes != 100 || !near(m.Memory.Used.Avg, 40) || m.Memory.EdgeRSS != nil {
		t.Errorf("memory %+v", m.Memory)
	}
	n := m.Network
	if n == nil || len(n.Interfaces) != 1 || n.Interfaces[0].Drops != 3 || n.Interfaces[0].RxBits.Max != 30 ||
		n.ConntrackCount == nil || n.ConntrackMax != 99 || n.TCPEstablished.Avg != 1 {
		t.Errorf("network %+v", n)
	}
	if m.Disk == nil || m.Disk.FreeBytes != 5 || m.Disk.ReadBytes != nil {
		t.Errorf("disk %+v", m.Disk)
	}
	e := m.Edge
	if e == nil || e.Requests != 30 || e.Status5xx != 3 || e.OriginErrors != 3 || e.LatencyP50MS != 15 || e.LatencyP95MS != 29 {
		t.Errorf("edge %+v", e)
	}
	if len(m.TopApps) != 2 || m.TopApps[0].App != "b" || m.TopApps[0].BytesOut != 360 || m.TopApps[1].Requests != 3 {
		t.Errorf("top apps %+v", m.TopApps)
	}
	if m.Tunnels == nil || m.Tunnels.Up != 2 {
		t.Errorf("tunnels %+v", m.Tunnels)
	}
}

func TestTopAppsLimit(t *testing.T) {
	hosts := map[string]observe.HostBytes{}
	for i := range 15 {
		hosts[string(rune('a'+i))] = observe.HostBytes{BytesIn: int64(i)}
	}
	top := topApps(hosts, func(h string) string { return h }, metricsTopApps)
	if len(top) != 10 || top[0].App != "o" || top[9].App != "f" {
		t.Errorf("top %+v", top)
	}
}

func TestTunnelMetrics(t *testing.T) {
	now := time.Unix(10000, 0)
	tm := tunnelMetrics([]nodeproto.TunnelStatus{
		{Site: "a", Up: true, LastHandshake: now.Add(-30 * time.Second), Transport: "udp"},
		{Site: "b", Up: true, LastHandshake: now.Add(-90 * time.Second), Transport: "websocket"},
		{Site: "c", Up: false, LastHandshake: now.Add(-time.Hour)},
	}, 4, now)
	if tm.Up != 2 || tm.Total != 4 || tm.WebSocket != 1 || tm.OldestHandshakeSeconds != 90 {
		t.Errorf("%+v", tm)
	}
}

func TestMetricsBufferResend(t *testing.T) {
	b := newMetricsBuffer(time.Unix(5000, 0))
	var seqs []int64
	for range maxBufferedMetrics + 5 {
		seqs = append(seqs, b.add(nodeproto.Metrics{}).Seq)
	}
	if seqs[0] != 5001 || b.lastSeq() != 5000+maxBufferedMetrics+5 || len(b.items) != maxBufferedMetrics {
		t.Fatalf("seqs %d..%d, kept %d", seqs[0], b.lastSeq(), len(b.items))
	}
	// Sent ones are not resent while the panel does not acknowledge.
	for _, s := range seqs[:len(seqs)-3] {
		b.markSent(s)
	}
	r := b.resend()
	if len(r) != 3 || r[0].Seq != seqs[len(seqs)-3] {
		t.Fatalf("resend before acks %v", r)
	}
	// Once the panel acknowledges, everything unacknowledged is resent.
	b.ack(seqs[len(seqs)-10])
	r = b.resend()
	if len(r) != 9 || r[0].Seq != seqs[len(seqs)-9] {
		t.Fatalf("resend after ack: %d from %d", len(r), r[0].Seq)
	}
	if b2 := newMetricsBuffer(time.Unix(5000+3600, 0)); b2.add(nodeproto.Metrics{}).Seq <= b.lastSeq() {
		t.Error("a restarted agent reuses seqs")
	}
}

func TestMetricsEncoding(t *testing.T) {
	m := nodeproto.Metrics{Seq: 7, Samples: 6, CPU: &nodeproto.CPUMetrics{Cores: 2, Steal: nodeproto.Gauge{Avg: 1.5, Max: 3}},
		TopApps: []nodeproto.AppBytes{{App: "web", BytesOut: 10}}}
	b, err := nodeproto.Encode(nodeproto.TypeMetrics, "", m)
	if err != nil {
		t.Fatal(err)
	}
	var env nodeproto.Envelope
	if err := json.Unmarshal(b, &env); err != nil || env.Type != "metrics" {
		t.Fatalf("%s %v", b, err)
	}
	for _, want := range []string{`"seq":7`, `"steal_pct":{"avg":1.5,"max":3}`, `"top_apps":[{"app":"web"`} {
		if !strings.Contains(string(env.Data), want) {
			t.Errorf("missing %s in %s", want, env.Data)
		}
	}
	if strings.Contains(string(env.Data), `"memory"`) {
		t.Errorf("absent group encoded: %s", env.Data)
	}
	live := nodeproto.MetricsLive{SubscriptionID: "s1", Metrics: m}
	b, _ = json.Marshal(live)
	var back nodeproto.MetricsLive
	if err := json.Unmarshal(b, &back); err != nil || back.SubscriptionID != "s1" || back.Seq != 7 || back.CPU.Cores != 2 {
		t.Errorf("live round trip %s → %+v %v", b, back, err)
	}
	if !strings.Contains(string(b), `"subscription_id":"s1","seq":7`) {
		t.Errorf("live sample is not flat: %s", b)
	}
}

func TestMetricsLiveLimits(t *testing.T) {
	a := &Agent{metricsWake: make(chan struct{}, 1)}
	s := &session{}
	a.startMetricsLive(s, nodeproto.MetricsSubscribe{SubscriptionID: "x", Until: time.Now().Add(time.Hour)})
	l := a.liveTarget(time.Now())
	if l == nil || time.Until(l.until) > metricsLiveMax {
		t.Fatalf("live %+v", l)
	}
	if a.liveTarget(time.Now().Add(metricsLiveMax+time.Second)) != nil {
		t.Error("live sampling outlasted its limit")
	}
	a.startMetricsLive(s, nodeproto.MetricsSubscribe{SubscriptionID: "y"})
	a.stopMetricsLive(&session{}, "") // another connection's teardown
	a.stopMetricsLive(s, "other")
	if a.liveTarget(time.Now()) == nil {
		t.Error("stopped by the wrong session or id")
	}
	a.stopMetricsLive(s, "y")
	if a.liveTarget(time.Now()) != nil {
		t.Error("unsubscribe ignored")
	}
}

// SPDX-License-Identifier: Apache-2.0

package nodeagent

import (
	"cmp"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/ingressd/ingressd/internal/alerts"
	"github.com/ingressd/ingressd/internal/observe"
	"github.com/ingressd/ingressd/pkg/config"
	"github.com/ingressd/ingressd/pkg/nodeproto"
)

// Node metrics (nodeproto.Metrics): sampled every metricsSample, sent as
// aggregates every metricsWindow, live samples every metricsLiveEvery.
const (
	metricsSample     = 10 * time.Second
	metricsWindow     = time.Minute
	metricsLiveEvery  = 2 * time.Second
	metricsLiveMax    = 10 * time.Minute
	metricsTopApps    = 10
	maxMergedLatency  = 8192
	edgeRescanEvery   = time.Minute
	sectorBytes       = 512
	tunnelsIfaceName  = "ix-*"
	meshIfaceName     = config.MeshInterface
	edgeProcessComm   = "ingressd-edge"
	edgeProcessLegacy = "caddy"
)

// webPorts are the edge's listeners counted as active connections.
var webPorts = map[uint64]bool{80: true, 443: true}

// rawSample is one reading of the system counters; nil/zero fields were
// not available.
type rawSample struct {
	at        time.Time
	cpu       *cpuTimes
	cores     int
	load      *[3]float64
	mem       *memInfo
	ifs       map[string]ifCounters
	pubIface  string
	tcp       *[2]int // established, on webPorts
	ctCount   *int64
	ctMax     int64
	diskDev   string
	disk      *[2]uint64 // sectors read, written
	diskFree  int64
	diskTotal int64
	edgeRSS   *int64
	agentRSS  *int64
}

// sysReader reads rawSamples from a /proc tree at root ("" = no /proc on
// this platform: only what the Go runtime and statfs give).
type sysReader struct {
	root     string
	stateDir string

	edgePID    string
	edgeLookup time.Time
}

func (r *sysReader) read(now time.Time) *rawSample {
	s := &rawSample{at: now, cores: runtime.NumCPU()}
	if u, err := alerts.DiskUsage(r.stateDir); err == nil {
		s.diskFree, s.diskTotal = int64(u.Free), int64(u.Total) //nolint:gosec // G115: disk sizes are far below 2^63
	}
	if r.root == "" {
		return s
	}
	rd := func(rel ...string) []byte {
		b, _ := os.ReadFile(filepath.Join(append([]string{r.root, "proc"}, rel...)...))
		return b
	}
	if c, n, err := parseProcStat(rd("stat")); err == nil {
		s.cpu = &c
		if n > 0 {
			s.cores = n
		}
	}
	if l, err := parseLoadavg(rd("loadavg")); err == nil {
		s.load = &l
	}
	if m, err := parseMeminfo(rd("meminfo")); err == nil {
		s.mem = &m
	}
	if b := rd("net", "dev"); len(b) > 0 {
		s.ifs = parseNetDev(b)
		s.pubIface = parseRoute(rd("net", "route"))
	}
	if b4, b6 := rd("net", "tcp"), rd("net", "tcp6"); len(b4) > 0 || len(b6) > 0 {
		e4, w4 := parseTCP(b4, webPorts)
		e6, w6 := parseTCP(b6, webPorts)
		s.tcp = &[2]int{e4 + e6, w4 + w6}
	}
	if n, ok := parseInt(rd("sys", "net", "netfilter", "nf_conntrack_count")); ok {
		s.ctCount = &n
		s.ctMax, _ = parseInt(rd("sys", "net", "netfilter", "nf_conntrack_max"))
	}
	dir := r.stateDir
	if !strings.HasPrefix(dir, "/") {
		dir, _ = filepath.Abs(dir)
	}
	if dir != "" {
		if dev := parseMounts(rd("self", "mounts"), filepath.ToSlash(dir)); dev != "" {
			if rs, ws, ok := parseDiskstats(rd("diskstats"), dev); ok {
				s.diskDev, s.disk = dev, &[2]uint64{rs, ws}
			}
		}
	}
	if n, ok := parseStatusRSS(rd("self", "status")); ok {
		s.agentRSS = &n
	}
	if pid := r.edgeProcess(now); pid != "" {
		if n, ok := parseStatusRSS(rd(pid, "status")); ok {
			s.edgeRSS = &n
		} else {
			r.edgePID = ""
		}
	}
	return s
}

// edgeProcess finds the edge proxy's pid, rescanning at most every
// edgeRescanEvery while it is not found (e.g. a separate container).
func (r *sysReader) edgeProcess(now time.Time) string {
	if r.edgePID != "" || now.Sub(r.edgeLookup) < edgeRescanEvery {
		return r.edgePID
	}
	r.edgeLookup = now
	r.edgePID = findProcess(r.root, edgeProcessComm, edgeProcessLegacy)
	return r.edgePID
}

// Gauge keys of a point.
const (
	gCPU      = "cpu.usage"
	gSteal    = "cpu.steal"
	gIOWait   = "cpu.iowait"
	gMemUsed  = "mem.used"
	gMemAvail = "mem.available"
	gSwap     = "mem.swap"
	gEdgeRSS  = "mem.edge_rss"
	gAgentRSS = "mem.agent_rss"
	gTCP      = "net.tcp"
	gConns    = "edge.conns"
	gCT       = "net.conntrack"
	gDiskR    = "disk.read"
	gDiskW    = "disk.write"
	gRPS      = "edge.rps"
)

// point is one sample turned into values: rates come from the difference
// to the previous sample.
type point struct {
	at     time.Time
	gauges map[string]float64
	ifs    map[string]ifPoint
	sys    *rawSample // for the end-of-window values (load, free disk, …)
	edge   *observe.MetricsWindow
	tun    *nodeproto.TunnelMetrics
}

type ifPoint struct {
	role                       string
	rxBps, txBps, rxPps, txPps float64
	drops, errs                int64
}

// sub is a counter delta; a counter that went backwards (interface
// recreated, wrap) counts as no change.
func sub(a, b uint64) uint64 {
	if a < b {
		return 0
	}
	return a - b
}

func ifDelta(a, b ifCounters) ifCounters {
	return ifCounters{
		rxBytes: sub(b.rxBytes, a.rxBytes), rxPackets: sub(b.rxPackets, a.rxPackets),
		rxErrs: sub(b.rxErrs, a.rxErrs), rxDrop: sub(b.rxDrop, a.rxDrop),
		txBytes: sub(b.txBytes, a.txBytes), txPackets: sub(b.txPackets, a.txPackets),
		txErrs: sub(b.txErrs, a.txErrs), txDrop: sub(b.txDrop, a.txDrop),
	}
}

// diff computes a point from two consecutive samples (prev may be nil).
func diff(prev, cur *rawSample, edge *observe.MetricsWindow, tun *nodeproto.TunnelMetrics) point {
	p := point{at: cur.at, gauges: map[string]float64{}, ifs: map[string]ifPoint{}, sys: cur, edge: edge, tun: tun}
	g := p.gauges
	if m := cur.mem; m != nil {
		g[gMemUsed] = float64(m.total - m.available)
		g[gMemAvail] = float64(m.available)
		g[gSwap] = float64(m.swapTotal - m.swapFree)
	}
	if cur.edgeRSS != nil {
		g[gEdgeRSS] = float64(*cur.edgeRSS)
	}
	if cur.agentRSS != nil {
		g[gAgentRSS] = float64(*cur.agentRSS)
	}
	if cur.tcp != nil {
		g[gTCP] = float64(cur.tcp[0])
		g[gConns] = float64(cur.tcp[1])
	}
	if cur.ctCount != nil {
		g[gCT] = float64(*cur.ctCount)
	}
	if prev == nil {
		return p
	}
	dt := cur.at.Sub(prev.at).Seconds()
	if dt <= 0 {
		return p
	}
	if edge != nil {
		g[gRPS] = float64(edge.Requests) / dt
	}
	if a, b := prev.cpu, cur.cpu; a != nil && b != nil {
		if tot := float64(sub(b.total(), a.total())); tot > 0 {
			idle := float64(sub(b.idle, a.idle))
			iow := float64(sub(b.iowait, a.iowait))
			g[gCPU] = 100 * max(tot-idle-iow, 0) / tot
			g[gSteal] = 100 * float64(sub(b.steal, a.steal)) / tot
			g[gIOWait] = 100 * iow / tot
		}
	}
	if a, b := prev.disk, cur.disk; a != nil && b != nil && prev.diskDev == cur.diskDev {
		g[gDiskR] = float64(sub(b[0], a[0])*sectorBytes) / dt
		g[gDiskW] = float64(sub(b[1], a[1])*sectorBytes) / dt
	}
	rate := func(name, role string, d ifCounters) {
		p.ifs[name] = ifPoint{
			role:  role,
			rxBps: float64(d.rxBytes*8) / dt, txBps: float64(d.txBytes*8) / dt,
			rxPps: float64(d.rxPackets) / dt, txPps: float64(d.txPackets) / dt,
			drops: int64(d.rxDrop + d.txDrop), errs: int64(d.rxErrs + d.txErrs), //nolint:gosec // G115: counter deltas are far below 2^63
		}
	}
	both := func(name string) (ifCounters, bool) {
		a, ok1 := prev.ifs[name]
		b, ok2 := cur.ifs[name]
		return ifDelta(a, b), ok1 && ok2
	}
	if name := cur.pubIface; name != "" {
		if d, ok := both(name); ok {
			rate(name, nodeproto.IfacePublic, d)
		}
	}
	if d, ok := both(meshIfaceName); ok {
		rate(meshIfaceName, nodeproto.IfaceMesh, d)
	}
	// Tunnel interfaces come and go; sum the deltas of those in both.
	var sum ifCounters
	n := 0
	for name := range cur.ifs {
		if !strings.HasPrefix(name, "ix-") || name == meshIfaceName {
			continue
		}
		if d, ok := both(name); ok {
			sum.addTo(d)
			n++
		}
	}
	if n > 0 {
		rate(tunnelsIfaceName, nodeproto.IfaceTunnels, sum)
	}
	return p
}

type gaugeAcc struct {
	sum, max float64
	n        int
}

func (a *gaugeAcc) add(v float64) {
	if a.n == 0 || v > a.max {
		a.max = v
	}
	a.sum += v
	a.n++
}

func (a *gaugeAcc) gauge() nodeproto.Gauge {
	if a == nil || a.n == 0 {
		return nodeproto.Gauge{}
	}
	return nodeproto.Gauge{Avg: a.sum / float64(a.n), Max: a.max}
}

type ifAcc struct {
	role             string
	rx, tx, rxp, txp gaugeAcc
	drops, errs      int64
}

// window aggregates points into one nodeproto.Metrics.
type window struct {
	from, to time.Time
	n        int
	g        map[string]*gaugeAcc
	ifs      map[string]*ifAcc
	last     *rawSample
	tun      *nodeproto.TunnelMetrics
	edge     *observe.MetricsWindow
}

func newWindow(from time.Time) *window {
	return &window{from: from, g: map[string]*gaugeAcc{}, ifs: map[string]*ifAcc{}}
}

func (w *window) add(p point) {
	w.n++
	w.to = p.at
	w.last = p.sys
	if p.tun != nil {
		w.tun = p.tun
	}
	for k, v := range p.gauges {
		a := w.g[k]
		if a == nil {
			a = &gaugeAcc{}
			w.g[k] = a
		}
		a.add(v)
	}
	for name, ip := range p.ifs {
		a := w.ifs[name]
		if a == nil {
			a = &ifAcc{role: ip.role}
			w.ifs[name] = a
		}
		a.rx.add(ip.rxBps)
		a.tx.add(ip.txBps)
		a.rxp.add(ip.rxPps)
		a.txp.add(ip.txPps)
		a.drops += ip.drops
		a.errs += ip.errs
	}
	if e := p.edge; e != nil {
		if w.edge == nil {
			w.edge = &observe.MetricsWindow{Hosts: map[string]observe.HostBytes{}}
		}
		w.edge.Requests += e.Requests
		w.edge.Status4xx += e.Status4xx
		w.edge.Status5xx += e.Status5xx
		w.edge.OriginErrors += e.OriginErrors
		w.edge.Seen += e.Seen
		if room := maxMergedLatency - len(w.edge.Latencies); room > 0 {
			w.edge.Latencies = append(w.edge.Latencies, e.Latencies[:min(room, len(e.Latencies))]...)
		}
		for h, hb := range e.Hosts {
			t := w.edge.Hosts[h]
			t.Requests += hb.Requests
			t.BytesIn += hb.BytesIn
			t.BytesOut += hb.BytesOut
			w.edge.Hosts[h] = t
		}
	}
}

func (w *window) gauge(k string) (nodeproto.Gauge, bool) {
	a, ok := w.g[k]
	return a.gauge(), ok
}

func (w *window) gaugePtr(k string) *nodeproto.Gauge {
	if g, ok := w.gauge(k); ok {
		return &g
	}
	return nil
}

// percentile is the nearest-rank p-th percentile of sorted durations, in ms.
func percentile(sorted []time.Duration, p float64) float64 {
	if len(sorted) == 0 {
		return 0
	}
	i := int(float64(len(sorted))*p/100+0.999999) - 1
	i = min(max(i, 0), len(sorted)-1)
	return float64(sorted[i].Microseconds()) / 1000
}

// metrics builds the message; appOf maps a request host to its app key
// ("" for none).
func (w *window) metrics(appOf func(string) string) nodeproto.Metrics {
	m := nodeproto.Metrics{From: w.from.UTC(), To: w.to.UTC(), Samples: w.n}
	s := w.last
	if s == nil {
		return m
	}
	if s.cores > 0 {
		c := &nodeproto.CPUMetrics{Cores: s.cores}
		c.Usage, _ = w.gauge(gCPU)
		c.Steal, _ = w.gauge(gSteal)
		c.IOWait, _ = w.gauge(gIOWait)
		if s.load != nil {
			c.Load1, c.Load5, c.Load15 = s.load[0], s.load[1], s.load[2]
		}
		m.CPU = c
	}
	if s.mem != nil {
		mm := &nodeproto.MemoryMetrics{TotalBytes: s.mem.total, EdgeRSS: w.gaugePtr(gEdgeRSS), AgentRSS: w.gaugePtr(gAgentRSS)}
		mm.Used, _ = w.gauge(gMemUsed)
		mm.Available, _ = w.gauge(gMemAvail)
		mm.SwapUsed, _ = w.gauge(gSwap)
		m.Memory = mm
	}
	if tcp, ok := w.gauge(gTCP); ok || len(w.ifs) > 0 {
		n := &nodeproto.NetworkMetrics{TCPEstablished: tcp, ConntrackCount: w.gaugePtr(gCT)}
		if n.ConntrackCount != nil {
			n.ConntrackMax = s.ctMax
		}
		for name, a := range w.ifs {
			n.Interfaces = append(n.Interfaces, nodeproto.InterfaceMetrics{
				Name: name, Role: a.role,
				RxBits: a.rx.gauge(), TxBits: a.tx.gauge(), RxPackets: a.rxp.gauge(), TxPackets: a.txp.gauge(),
				Drops: a.drops, Errors: a.errs,
			})
		}
		order := map[string]int{nodeproto.IfacePublic: 0, nodeproto.IfaceMesh: 1, nodeproto.IfaceTunnels: 2}
		slices.SortFunc(n.Interfaces, func(a, b nodeproto.InterfaceMetrics) int {
			return cmp.Or(cmp.Compare(order[a.Role], order[b.Role]), strings.Compare(a.Name, b.Name))
		})
		m.Network = n
	}
	if s.diskTotal > 0 || s.disk != nil {
		d := &nodeproto.DiskMetrics{FreeBytes: s.diskFree, TotalBytes: s.diskTotal, ReadBytes: w.gaugePtr(gDiskR), WriteBytes: w.gaugePtr(gDiskW)}
		if d.ReadBytes != nil {
			d.Device = s.diskDev
		}
		m.Disk = d
	}
	if e := w.edge; e != nil {
		em := &nodeproto.EdgeMetrics{
			Requests: e.Requests, Status4xx: e.Status4xx, Status5xx: e.Status5xx, OriginErrors: e.OriginErrors,
		}
		em.RequestsPerSec, _ = w.gauge(gRPS)
		em.ActiveConns, _ = w.gauge(gConns)
		lat := slices.Clone(e.Latencies)
		slices.Sort(lat)
		em.LatencyP50MS, em.LatencyP95MS = percentile(lat, 50), percentile(lat, 95)
		m.Edge = em
		m.TopApps = topApps(e.Hosts, appOf, metricsTopApps)
	}
	m.Tunnels = w.tun
	return m
}

// topApps sums host bytes per app and returns the n busiest.
func topApps(hosts map[string]observe.HostBytes, appOf func(string) string, n int) []nodeproto.AppBytes {
	if appOf == nil {
		return nil
	}
	by := map[string]*nodeproto.AppBytes{}
	for h, hb := range hosts {
		app := appOf(h)
		if app == "" {
			continue
		}
		a := by[app]
		if a == nil {
			a = &nodeproto.AppBytes{App: app}
			by[app] = a
		}
		a.Requests += hb.Requests
		a.BytesIn += hb.BytesIn
		a.BytesOut += hb.BytesOut
	}
	out := make([]nodeproto.AppBytes, 0, len(by))
	for _, a := range by {
		out = append(out, *a)
	}
	slices.SortFunc(out, func(a, b nodeproto.AppBytes) int {
		return cmp.Or(cmp.Compare(b.BytesIn+b.BytesOut, a.BytesIn+a.BytesOut), strings.Compare(a.App, b.App))
	})
	if len(out) > n {
		out = out[:n]
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// SPDX-License-Identifier: Apache-2.0

package client

import (
	"cmp"
	"context"
	"math"
	"net"
	"slices"
	"strconv"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/ingressd/ingressd/internal/connector/proto"
)

// RTT measurement: a TCP connect to the edge's tunnel control port at its
// transit address is exactly one round trip through the tunnel (SYN,
// SYN-ACK), needs nothing new on the node and works on every edge.
const (
	rttInterval = 10 * time.Second
	rttTimeout  = 3 * time.Second
	rttAlpha    = 0.3
)

// ewma is an exponentially weighted moving average of durations.
type ewma struct {
	v  float64 // seconds
	ok bool
}

func (e *ewma) add(d time.Duration) {
	if !e.ok {
		e.v, e.ok = d.Seconds(), true
		return
	}
	e.v = rttAlpha*d.Seconds() + (1-rttAlpha)*e.v
}

func (e *ewma) value() time.Duration {
	if !e.ok {
		return 0
	}
	return time.Duration(e.v * float64(time.Second))
}

func (e *ewma) reset() { *e = ewma{} }

func millis(d time.Duration) float64 { return math.Round(float64(d.Microseconds())/10) / 100 }

// rttLoop measures the edge's RTT while its tunnel is up.
func (e *edge) rttLoop(ctx context.Context) {
	t := time.NewTicker(rttInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			e.measureRTT(ctx)
		}
	}
}

// measureRTT takes one sample; failures are not samples (the transport
// loop notices a dead tunnel).
func (e *edge) measureRTT(ctx context.Context) bool {
	addr := e.config().Config.EdgeAddress
	if addr == "" || !e.tunnelUp() {
		return false
	}
	dctx, cancel := context.WithTimeout(ctx, rttTimeout)
	defer cancel()
	start := time.Now()
	c, err := e.s.link.DialTunnel(dctx, net.JoinHostPort(addr, strconv.Itoa(proto.TunnelControlPort)))
	d := time.Since(start)
	if err != nil {
		return false
	}
	_ = c.Close()
	e.mu.Lock()
	e.rtt.add(d)
	e.mu.Unlock()
	return true
}

func (e *edge) rttValue() time.Duration {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.rtt.value()
}

// edgeRank is what edge order is decided by.
type edgeRank struct {
	priority int
	rtt      time.Duration // 0 = unknown, sorts after every measured edge
}

func compareRank(a, b edgeRank) int {
	key := func(r edgeRank) time.Duration {
		if r.rtt <= 0 {
			return math.MaxInt64
		}
		return r.rtt
	}
	return cmp.Or(cmp.Compare(a.priority, b.priority), cmp.Compare(key(a), key(b)))
}

// siblingInfo returns each edge's sibling entry (priority, PoP) as some
// edge lists it, keyed by edge public key; an edge never lists itself, so
// a site's edges learn their order from each other.
func siblingInfo(st *State) map[string]proto.Sibling {
	out := map[string]proto.Sibling{}
	for _, es := range st.Edges {
		for _, sb := range es.Config.Siblings {
			if _, ok := out[sb.EdgePublicKey]; !ok {
				out[sb.EdgePublicKey] = sb
			}
		}
	}
	return out
}

// rankedEdges returns the running edges ordered by priority, then RTT,
// keeping state order between equals.
func (s *session) rankedEdges() []*edge {
	s.mu.Lock()
	info := siblingInfo(s.st)
	var out []*edge
	for _, es := range s.st.Edges {
		if e := s.edgeByKey(es.Config.EdgePublicKey); e != nil {
			out = append(out, e)
		}
	}
	s.mu.Unlock()
	ranks := map[*edge]edgeRank{}
	for _, e := range out {
		ranks[e] = edgeRank{priority: info[e.key.String()].Priority, rtt: e.rttValue()}
	}
	slices.SortStableFunc(out, func(a, b *edge) int { return compareRank(ranks[a], ranks[b]) })
	return out
}

// edgeReports is what every report carries about all edges.
func (s *session) edgeReports() []proto.EdgeReport {
	var out []proto.EdgeReport
	for _, e := range s.rankedEdges() {
		e.mu.Lock()
		r := proto.EdgeReport{Node: e.cfg.Node, EdgePublicKey: e.key.String(), RTTMillis: millis(e.rtt.value()), Transport: e.transport}
		e.mu.Unlock()
		r.Up = r.Transport != "" && e.tunnelUp()
		out = append(out, r)
	}
	return out
}

// edgeByKey returns the running edge with that public key; s.mu is held.
func (s *session) edgeByKey(key string) *edge {
	k, err := wgtypes.ParseKey(key)
	if err != nil {
		return nil
	}
	return s.edges[k]
}

func statusRank(es EdgeStatus) edgeRank {
	return edgeRank{priority: es.Priority, rtt: time.Duration(es.RTTMillis * float64(time.Millisecond))}
}

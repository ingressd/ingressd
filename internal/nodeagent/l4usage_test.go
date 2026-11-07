// SPDX-License-Identifier: Apache-2.0

package nodeagent

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/ingressd/ingressd/internal/l4"
	"github.com/ingressd/ingressd/pkg/config"
	"github.com/ingressd/ingressd/pkg/nodeproto"
)

func TestL4Deltas(t *testing.T) {
	q := &usageQueue{}
	if got := q.l4Deltas(nil); got != nil {
		t.Fatalf("unread totals reported: %+v", got)
	}
	// A new service's counters started at zero, so all of it is usage.
	got := q.l4Deltas(map[string]l4.Counters{"mc": {BytesIn: 100, BytesOut: 1000, Conns: 2}})
	want := []nodeproto.AppUsage{{App: "mc", Requests: 2, BytesIn: 100, BytesOut: 1000}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("first: %+v", got)
	}
	got = q.l4Deltas(map[string]l4.Counters{"mc": {BytesIn: 150, BytesOut: 1500, Conns: 2}})
	want = []nodeproto.AppUsage{{App: "mc", BytesIn: 50, BytesOut: 500}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("delta: %+v", got)
	}
	if got := q.l4Deltas(map[string]l4.Counters{"mc": {BytesIn: 150, BytesOut: 1500, Conns: 2}}); len(got) != 0 {
		t.Fatalf("idle service reported: %+v", got)
	}
	// A failed read keeps the baseline.
	q.l4Deltas(nil)
	// An apply restarted the counters.
	got = q.l4Deltas(map[string]l4.Counters{"mc": {BytesIn: 10, BytesOut: 20, Conns: 1}})
	want = []nodeproto.AppUsage{{App: "mc", Requests: 1, BytesIn: 10, BytesOut: 20}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("restart: %+v", got)
	}
}

func TestRecordCountsL4Alone(t *testing.T) {
	q := &usageQueue{path: t.TempDir() + "/usage.json"}
	u, err := q.record(collector{l4: map[string]l4.Counters{"mc": {BytesOut: 5}}}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if u == nil || len(u.Apps) != 1 || u.Apps[0].App != "mc" {
		t.Fatalf("usage = %+v", u)
	}
}

func TestL4Services(t *testing.T) {
	cfg := &config.Config{L4: config.L4Services{"mc": {}, "rust": {}}}
	cases := []struct {
		name string
		f    liveFilter
		want []string
	}{
		{"all", liveFilter{}, []string{"mc", "rust"}},
		{"one app", liveFilter{apps: map[string]bool{"mc": true}}, []string{"mc"}},
		{"web app", liveFilter{apps: map[string]bool{"web": true}}, nil},
		{"host filter", liveFilter{hosts: map[string]bool{"web.example.test": true}}, nil},
	}
	for _, c := range cases {
		if got := c.f.l4Services(cfg); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
	if got := (liveFilter{}).l4Services(nil); got != nil {
		t.Errorf("no config: %v", got)
	}
}

func TestL4Connections(t *testing.T) {
	a := l4.Peer{IP: "203.0.113.2", Proto: "tcp", Port: 1000}
	b := l4.Peer{IP: "203.0.113.3", Proto: "udp", Port: 2000}
	var peers []l4.Peer
	var readErr error
	old := readL4Peers
	readL4Peers = func(context.Context, string) ([]l4.Peer, error) { return peers, readErr }
	defer func() { readL4Peers = old }()

	seen := map[string]map[l4.Peer]bool{}
	now := time.Now()
	poll := func() []nodeproto.LogEntry { return l4Connections(context.Background(), []string{"mc"}, seen, now) }

	peers = []l4.Peer{a}
	got := poll()
	if len(got) != 1 || got[0].App != "mc" || got[0].Method != "TCP" || got[0].ClientIP != a.IP || got[0].Decision != nodeproto.DecisionAllow {
		t.Fatalf("first poll: %+v", got)
	}
	if got := poll(); len(got) != 0 {
		t.Fatalf("connection reported twice: %+v", got)
	}
	peers = []l4.Peer{a, b}
	if got := poll(); len(got) != 1 || got[0].Method != "UDP" {
		t.Fatalf("new connection: %+v", got)
	}
	readErr = errors.New("nft failed")
	if got := poll(); len(got) != 0 {
		t.Fatalf("failed read: %+v", got)
	}
	readErr = nil
	if got := poll(); len(got) != 0 {
		t.Fatalf("reported again after a failed read: %+v", got)
	}
}

// SPDX-License-Identifier: Apache-2.0

package main

import (
	"strings"
	"testing"
	"time"

	"github.com/ingressd/ingressd/internal/connector/client"
	"github.com/ingressd/ingressd/internal/connector/proto"
)

func TestPrintStatusShowsEveryEdge(t *testing.T) {
	now := time.Now()
	st := &client.State{Mode: "tun", Edges: []client.EdgeState{
		{URL: "https://a.example.test", Config: proto.TunnelConfig{Tunnel: "home", Address: "100.64.0.6/30", Subnets: []string{"192.168.0.0/24"}}},
		{URL: "https://b.example.test", Learned: true, Config: proto.TunnelConfig{Tunnel: "home", Address: "100.64.0.10/30"}},
	}}
	s := &client.Status{
		Health:   proto.Health{Time: now, Transport: "udp", MTU: 1420, LastHandshake: now.Add(-5 * time.Second)},
		Endpoint: "172.16.1.1:51820", LastPoll: now,
		Edges: []client.EdgeStatus{
			{URL: "https://a.example.test", Address: "100.64.0.6/30", Transport: "udp", Endpoint: "172.16.1.1:51820", LastHandshake: now.Add(-5 * time.Second), LastPoll: now},
			{URL: "https://b.example.test", Address: "100.64.0.10/30", Learned: true, LastPoll: now, PollError: "connection refused"},
		},
	}
	var b strings.Builder
	if err := printStatus(&b, st, s, now); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{
		"State:", "up (1 of 2 edges up)", "Transport:", "udp 172.16.1.1:51820", "Control channel:", "ok",
		"Edge 1:", "https://a.example.test site 100.64.0.6/30: up udp",
		"Edge 2:", "https://b.example.test (learned) site 100.64.0.10/30: connecting -", "control error: connection refused",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("status lacks %q:\n%s", want, out)
		}
	}
	b.Reset()
	_ = printStatus(&b, st, nil, now)
	if !strings.Contains(b.String(), "not running") || !strings.Contains(b.String(), "Edge 2:") {
		t.Errorf("not-running status:\n%s", b.String())
	}
}

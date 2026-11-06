// SPDX-License-Identifier: Apache-2.0

package main

import (
	"io"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ingressd/ingressd/internal/connector/client"
	"github.com/ingressd/ingressd/internal/connector/proto"
)

func runAllow(t *testing.T, path string, args ...string) (string, error) {
	t.Helper()
	var b strings.Builder
	cmd := newRootCmd()
	cmd.SetOut(&b)
	cmd.SetErr(io.Discard)
	cmd.SetArgs(append([]string{"--state", path, "allow"}, args...))
	err := cmd.Execute()
	return b.String(), err
}

func TestAllowCommands(t *testing.T) {
	path := filepath.Join(t.TempDir(), "connector.json")
	st := &client.State{Mode: "netstack", Edges: []client.EdgeState{{Config: proto.TunnelConfig{Subnets: []string{"192.168.0.0/24", "10.0.0.0/8"}}}}}
	if err := st.Save(path); err != nil {
		t.Fatal(err)
	}
	out, err := runAllow(t, path, "list")
	if err != nil || !strings.Contains(out, "192.168.0.0/16") || !strings.Contains(out, "pinned at the next start") {
		t.Fatalf("%q, %v", out, err)
	}
	if out, err = runAllow(t, path, "add", "203.0.113.0/24"); err != nil || !strings.Contains(out, "203.0.113.0/24") {
		t.Fatalf("%q, %v", out, err)
	}
	if _, err = runAllow(t, path, "add", "0.0.0.0/0"); err == nil || !strings.Contains(err.Error(), "--allow-any-network") {
		t.Fatalf("got %v", err)
	}
	if _, err = runAllow(t, path, "add", "::/0", "--allow-any-network"); err != nil {
		t.Fatal(err)
	}
	if _, err = runAllow(t, path, "remove", "::/0", "10.0.0.0/8"); err != nil {
		t.Fatal(err)
	}
	out, err = runAllow(t, path, "list")
	if err != nil || !strings.Contains(out, "Refused: 10.0.0.0/8") || !strings.Contains(out, "allow add 10.0.0.0/8") || strings.Contains(out, "::/0") {
		t.Errorf("%q, %v", out, err)
	}
}

func TestPrintStatusLANFilter(t *testing.T) {
	now := time.Now()
	st := &client.State{Mode: "tun"}
	var b strings.Builder
	s := &client.Status{Health: proto.Health{Time: now}, LANFilterOff: true}
	if err := printStatus(&b, st, s, now); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), "NOT ENFORCED") {
		t.Errorf("%s", b.String())
	}
}

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

// SPDX-License-Identifier: Apache-2.0

package client

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/ingressd/ingressd/internal/connector/proto"
)

func TestLoadStateMigratesSingleEdge(t *testing.T) {
	path := filepath.Join(t.TempDir(), "connector.json")
	old := `{"edge_url":"https://edge.example.test","edge_addr":"172.16.1.1","ca_pem":"PEM","mode":"tun",
	"private_key":"KEY","credential":"cred","config":{"tunnel":"cloud","edge_public_key":"EK","endpoint":"edge.example.test:51820",
	"address":"10.100.1.2/24","edge_address":"10.100.1.1","subnets":["192.168.0.0/24"],"revision":"r1"},"enrolled_at":"2026-01-01T00:00:00Z"}`
	if err := os.WriteFile(path, []byte(old), 0o600); err != nil {
		t.Fatal(err)
	}
	st, err := LoadState(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(st.Edges) != 1 {
		t.Fatalf("edges %+v", st.Edges)
	}
	e := st.Edges[0]
	if e.URL != "https://edge.example.test" || e.Addr != "172.16.1.1" || e.CAPEM != "PEM" || e.Credential != "cred" ||
		e.Config.Tunnel != "cloud" || e.Config.Revision != "r1" || st.Mode != "tun" || st.PrivateKey != "KEY" {
		t.Errorf("migrated %+v / %+v", st, e)
	}
	if err := st.Save(path); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(path)
	if strings.Contains(string(b), `"edge_url"`) || !strings.Contains(string(b), `"edges"`) {
		t.Errorf("saved state is not in the new format:\n%s", b)
	}
	again, err := LoadState(path)
	if err != nil || len(again.Edges) != 1 || again.Edges[0].Credential != "cred" {
		t.Errorf("reload: %+v %v", again, err)
	}
	if err := os.WriteFile(path, []byte(`{"mode":"tun"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadState(path); err == nil {
		t.Error("a state without edges loaded")
	}
}

func key(t *testing.T) string {
	t.Helper()
	k, _ := wgtypes.GeneratePrivateKey()
	return k.PublicKey().String()
}

func TestMergeSiblings(t *testing.T) {
	now := time.Now()
	ka, kb, kc := key(t), key(t), key(t)
	sibB := proto.Sibling{Node: "nod_b", Endpoint: "b.example.test:51822", EdgePublicKey: kb, Address: "100.64.0.10/30", EdgeAddress: "100.64.0.9", WSURL: "wss://b.example.test/.ingressd/tunnel/home"}
	a := EdgeState{URL: "https://a.example.test", Credential: "cred", LastSeen: now, Config: proto.TunnelConfig{
		Tunnel: "home", EdgePublicKey: ka, Address: "100.64.0.6/30", Subnets: []string{"192.168.0.0/24"}, Keepalive: 25, MTU: 1420,
		Targets: []string{"192.168.0.17:80"}, Siblings: []proto.Sibling{sibB},
	}}
	st := &State{Edges: []EdgeState{a}}
	gone := map[string]bool{}

	// A lists B: B is added as a learned edge with A's shared settings.
	if !mergeSiblings(st, gone, now) || len(st.Edges) != 2 {
		t.Fatalf("B not added: %+v", st.Edges)
	}
	b := st.Edges[1]
	if !b.Learned || b.Node != "nod_b" || b.URL != "https://b.example.test" || b.Credential != "" ||
		b.Config.EdgePublicKey != kb || b.Config.Address != "100.64.0.10/30" || b.Config.EdgeAddress != "100.64.0.9" ||
		!b.Config.FallbackWS || b.Config.Subnets[0] != "192.168.0.0/24" || b.Config.Revision != "" || b.Config.Keepalive != 25 {
		t.Errorf("learned edge %+v", b)
	}
	if mergeSiblings(st, gone, now) {
		t.Error("second merge changed something")
	}

	// A's list gains C while A itself is down: B (fresh) does not list C
	// but A's persisted list still adds it.
	st.Edges[0].Config.Siblings = append(st.Edges[0].Config.Siblings, proto.Sibling{Endpoint: "c:1", EdgePublicKey: kc, Address: "100.64.0.14/30"})
	if !mergeSiblings(st, gone, now) || st.Edge(kc) == nil {
		t.Fatalf("C not added: %+v", st.Edges)
	}

	// Enrolment edge A goes away for good: B (fresh) no longer lists it
	// and A has not answered for longer than removeAfter.
	later := now.Add(10 * time.Minute)
	st.Edge(kb).LastSeen = later
	st.Edge(kb).Config.Siblings = []proto.Sibling{{Endpoint: "c:1", EdgePublicKey: kc, Address: "100.64.0.14/30"}}
	st.Edge(kc).LastSeen = later
	if !mergeSiblings(st, gone, later) || st.Edge(ka) != nil || len(st.Edges) != 2 {
		t.Fatalf("A not removed: %+v", st.Edges)
	}

	// An edge that answers 410 is dropped at once, but never the last one.
	gone[kc] = true
	if !mergeSiblings(st, gone, later) || st.Edge(kc) != nil {
		t.Fatalf("C not removed after 410: %+v", st.Edges)
	}
	st.Edge(kb).Config.Siblings = nil
	gone[kb] = true
	mergeSiblings(st, gone, later)
	if len(st.Edges) != 1 {
		t.Errorf("last edge removed: %+v", st.Edges)
	}
}

func TestMergeKeepsUnlistedFreshEdge(t *testing.T) {
	now := time.Now()
	ka, kb := key(t), key(t)
	// B just started on a node whose config does not list A yet; A was
	// polled recently, so it stays.
	st := &State{Edges: []EdgeState{
		{LastSeen: now.Add(-30 * time.Second), Config: proto.TunnelConfig{EdgePublicKey: ka, Address: "100.64.0.6/30"}},
		{Learned: true, LastSeen: now, Config: proto.TunnelConfig{EdgePublicKey: kb, Address: "100.64.0.10/30"}},
	}}
	if mergeSiblings(st, map[string]bool{}, now) || len(st.Edges) != 2 {
		t.Errorf("fresh edges dropped: %+v", st.Edges)
	}
	// A learned edge that was never polled is kept while a fresh edge
	// lists it, and its link settings follow the list.
	kc := key(t)
	st.Edges[0].Config.Siblings = []proto.Sibling{{Endpoint: "c:1", EdgePublicKey: kc, Address: "100.64.0.14/30"}}
	mergeSiblings(st, map[string]bool{}, now)
	st.Edges[0].Config.Siblings[0].Endpoint = "c:2"
	if !mergeSiblings(st, map[string]bool{}, now) || st.Edge(kc).Config.Endpoint != "c:2" {
		t.Errorf("never-polled edge not updated from the list: %+v", st.Edge(kc))
	}
}

func TestURLFromWS(t *testing.T) {
	for in, want := range map[string]string{
		"wss://b.example.test/.ingressd/tunnel/home":  "https://b.example.test",
		"wss://198.51.100.7:8443/.ingressd/connector": "https://198.51.100.7:8443",
		"": "",
	} {
		if got := urlFromWS(in); got != want {
			t.Errorf("urlFromWS(%q) = %q, want %q", in, got, want)
		}
	}
}

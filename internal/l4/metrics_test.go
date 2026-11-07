// SPDX-License-Identifier: Apache-2.0

package l4

import (
	"reflect"
	"testing"
)

// Output of nft 1.1.6 for a service that served one TCP and one UDP client.
const (
	nftCounters = `{"nftables": [{"metainfo": {"version": "1.1.6", "json_schema_version": 1}},
		{"counter": {"family": "ip", "name": "svc_game_x_in", "table": "ingressd_l4", "handle": 7, "packets": 15, "bytes": 693}},
		{"counter": {"family": "ip", "name": "svc_game_x_out", "table": "ingressd_l4", "handle": 8, "packets": 15, "bytes": 105668}},
		{"counter": {"family": "ip", "name": "svc_game_x_conns", "table": "ingressd_l4", "handle": 9, "packets": 2, "bytes": 92}}]}`
	nftSet = `{"nftables": [{"metainfo": {"version": "1.1.6", "json_schema_version": 1}},
		{"set": {"family": "ip", "name": "svc_game_x_live", "table": "ingressd_l4", "type": ["ipv4_addr", "inet_proto", "inet_service"],
		"handle": 10, "size": 1024, "flags": ["timeout", "dynamic"], "timeout": 30, "elem": [
		{"elem": {"val": {"concat": ["203.0.113.2", "tcp", 45512]}, "expires": 29}},
		{"elem": {"val": {"concat": ["203.0.113.2", "udp", 57321]}, "expires": 29}}]}}]}`
)

func TestParseCounters(t *testing.T) {
	got, err := parseCounters([]byte(nftCounters), []string{"game-x", "other"})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]Counters{"game-x": {BytesIn: 693, BytesOut: 105668, Conns: 2}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
	if got, err := parseCounters(nil, []string{"game-x"}); err != nil || len(got) != 0 {
		t.Fatalf("no table: %+v, %v", got, err)
	}
	if _, err := parseCounters([]byte("{"), nil); err == nil {
		t.Fatal("bad JSON accepted")
	}
}

func TestParsePeers(t *testing.T) {
	got, err := parsePeers([]byte(nftSet))
	if err != nil {
		t.Fatal(err)
	}
	want := []Peer{{"203.0.113.2", "tcp", 45512}, {"203.0.113.2", "udp", 57321}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
	bare := `{"nftables": [{"set": {"elem": [{"concat": ["203.0.113.9", "tcp", 1000]}, {"concat": ["bad"]}]}}]}`
	if got, err := parsePeers([]byte(bare)); err != nil || len(got) != 1 || got[0].IP != "203.0.113.9" {
		t.Fatalf("bare element: %+v, %v", got, err)
	}
	if got, err := parsePeers(nil); err != nil || got != nil {
		t.Fatalf("no set: %+v, %v", got, err)
	}
}

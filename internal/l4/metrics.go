// SPDX-License-Identifier: Apache-2.0

package l4

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strings"

	"github.com/ingressd/ingressd/internal/render"
)

// Counters are a service's running totals since its table was last created.
type Counters struct {
	BytesIn  int64 `json:"in"`
	BytesOut int64 `json:"out"`
	Conns    int64 `json:"conns"`
}

// Peer is a recent new connection to a service.
type Peer struct {
	IP    string
	Proto string
	Port  int
}

// ReadCounters returns the running totals of services. A service without
// counters is absent, for example before the first apply.
func ReadCounters(ctx context.Context, services []string) (map[string]Counters, error) {
	out, err := nftJSON(ctx, "list", "counters", "table", "ip", render.L4Table)
	if err != nil {
		return nil, err
	}
	return parseCounters(out, services)
}

// ReadPeers returns a service's recent new connections.
func ReadPeers(ctx context.Context, service string) ([]Peer, error) {
	out, err := nftJSON(ctx, "list", "set", "ip", render.L4Table, render.L4LiveSet(service))
	if err != nil {
		return nil, err
	}
	return parsePeers(out)
}

// nftJSON runs nft with JSON output. A table or set that does not exist
// yet is no output rather than an error.
func nftJSON(ctx context.Context, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "nft", append([]string{"-j"}, args...)...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	var exit *exec.ExitError
	if errors.As(err, &exit) && strings.Contains(stderr.String(), "No such file or directory") {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("nft: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return out, nil
}

func parseCounters(b []byte, services []string) (map[string]Counters, error) {
	out := map[string]Counters{}
	if len(b) == 0 {
		return out, nil
	}
	var doc struct {
		Nftables []struct {
			Counter *struct {
				Name    string `json:"name"`
				Packets int64  `json:"packets"`
				Bytes   int64  `json:"bytes"`
			} `json:"counter"`
		} `json:"nftables"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, fmt.Errorf("nft counters: %w", err)
	}
	type reading struct{ packets, bytes int64 }
	byName := map[string]reading{}
	for _, e := range doc.Nftables {
		if e.Counter != nil {
			byName[e.Counter.Name] = reading{e.Counter.Packets, e.Counter.Bytes}
		}
	}
	for _, s := range services {
		in, ok := byName[render.L4CounterIn(s)]
		if !ok {
			continue
		}
		out[s] = Counters{BytesIn: in.bytes, BytesOut: byName[render.L4CounterOut(s)].bytes, Conns: byName[render.L4CounterConns(s)].packets}
	}
	return out, nil
}

func parsePeers(b []byte) ([]Peer, error) {
	if len(b) == 0 {
		return nil, nil
	}
	var doc struct {
		Nftables []struct {
			Set *struct {
				Elem []json.RawMessage `json:"elem"`
			} `json:"set"`
		} `json:"nftables"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, fmt.Errorf("nft set: %w", err)
	}
	var out []Peer
	for _, e := range doc.Nftables {
		if e.Set == nil {
			continue
		}
		for _, raw := range e.Set.Elem {
			if p, ok := parsePeer(raw); ok {
				out = append(out, p)
			}
		}
	}
	return out, nil
}

// parsePeer reads one set element: {"elem": {"val": {"concat": [...]}, ...}},
// or the bare {"concat": [...]} of an element without an expiry.
func parsePeer(raw json.RawMessage) (Peer, bool) {
	var e struct {
		Elem struct {
			Val struct {
				Concat []any `json:"concat"`
			} `json:"val"`
		} `json:"elem"`
		Concat []any `json:"concat"`
	}
	if json.Unmarshal(raw, &e) != nil {
		return Peer{}, false
	}
	c := e.Elem.Val.Concat
	if c == nil {
		c = e.Concat
	}
	if len(c) != 3 {
		return Peer{}, false
	}
	ip, ok := c[0].(string)
	proto, okProto := c[1].(string)
	port, okPort := c[2].(float64)
	if !ok || !okProto || !okPort {
		return Peer{}, false
	}
	return Peer{IP: ip, Proto: proto, Port: int(port)}, true
}

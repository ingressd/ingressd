// SPDX-License-Identifier: Apache-2.0

// Package client implements ingressd-connector: enrollment, the WireGuard
// link in TUN or netstack mode, transport selection (UDP with a
// WebSocket-over-443 fallback), and the control channel to the edges.
//
// A site may be attached to several nodes (multi-PoP). The connector keeps
// one WireGuard device with one peer per edge; it learns the other edges
// from each edge's tunnel config (siblings) and keeps them up to date by
// polling every edge it can reach, over the tunnel where possible.
package client

import (
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"time"

	"github.com/ingressd/ingressd/internal/connector/proto"
	"github.com/ingressd/ingressd/internal/upgrade"
)

// Modes.
const (
	ModeTUN      = "tun"
	ModeNetstack = "netstack"
)

// State is the connector's persistent state file (mode 0600). It holds the
// site's private key, which never leaves this machine.
type State struct {
	Mode       string `json:"mode"`
	Interface  string `json:"interface,omitempty"`
	Masquerade bool   `json:"masquerade,omitempty"`
	// NoDiscovery refuses LAN discovery requests from the edge.
	NoDiscovery bool      `json:"no_discovery,omitempty"`
	PrivateKey  string    `json:"private_key"`
	EnrolledAt  time.Time `json:"enrolled_at"`
	// Edges are the nodes this site is linked to. The first is the one the
	// connector enrolled with; others are learned from sibling lists.
	Edges []EdgeState `json:"edges"`
}

// EdgeState is one edge (node) of the site.
type EdgeState struct {
	// URL is the edge's HTTPS base URL for the public control channel, e.g.
	// https://edge.example.com ("" = reachable only over the tunnel).
	URL string `json:"url,omitempty"`
	// Addr, if set, is dialled instead of resolving the edge's hostname
	// (for both HTTPS and the WireGuard endpoint).
	Addr string `json:"addr,omitempty"`
	// CAFile is a PEM bundle trusted for the edge's certificate.
	CAFile string `json:"ca_file,omitempty"`
	// CAPEM is the CA from a join string, pinned for the edge certificate.
	CAPEM string `json:"ca_pem,omitempty"`
	// Insecure skips certificate verification (testing only).
	Insecure bool `json:"insecure,omitempty"`
	// Credential is from enrolment on this edge. Edges learned from a
	// sibling list have none: they accept the connector by its WireGuard
	// key (over the tunnel, or a IngressdKey header).
	Credential string `json:"credential,omitempty"`
	Node       string `json:"node,omitempty"`
	// Learned marks an edge added from another edge's sibling list.
	Learned bool               `json:"learned,omitempty"`
	Config  proto.TunnelConfig `json:"config"`
	// LastSeen is the last successful poll of this edge.
	LastSeen time.Time `json:"last_seen,omitempty"`
}

// legacyState is the single-edge state file written before multi-edge.
type legacyState struct {
	EdgeURL    string              `json:"edge_url"`
	EdgeAddr   string              `json:"edge_addr"`
	CAFile     string              `json:"ca_file"`
	CAPEM      string              `json:"ca_pem"`
	Insecure   bool                `json:"insecure"`
	Credential string              `json:"credential"`
	Config     *proto.TunnelConfig `json:"config"`
}

// Primary is the edge the connector enrolled with (or the first left).
func (s *State) Primary() *EdgeState {
	if len(s.Edges) == 0 {
		return &EdgeState{}
	}
	return &s.Edges[0]
}

// Tunnel is the site's tunnel name (the same on every edge).
func (s *State) Tunnel() string { return s.Primary().Config.Tunnel }

// Edge returns the edge with the given edge public key, or nil.
func (s *State) Edge(key string) *EdgeState {
	for i := range s.Edges {
		if s.Edges[i].Config.EdgePublicKey == key {
			return &s.Edges[i]
		}
	}
	return nil
}

// Addresses are the site's transit addresses, one per edge.
func (s *State) Addresses() []netip.Prefix {
	var out []netip.Prefix
	for _, e := range s.Edges {
		if p, err := netip.ParsePrefix(e.Config.Address); err == nil && !slices.Contains(out, p) {
			out = append(out, p)
		}
	}
	return out
}

// Subnets is the union of every edge's routed subnets.
func (s *State) Subnets() []string {
	return s.union(func(c proto.TunnelConfig) []string { return c.Subnets })
}

// Transparent is the union of every edge's transparent L4 sources.
func (s *State) Transparent() []string {
	return s.union(func(c proto.TunnelConfig) []string { return c.Transparent })
}

// Targets is the union of every edge's reachability targets.
func (s *State) Targets() []string {
	return s.union(func(c proto.TunnelConfig) []string { return c.Targets })
}

func (s *State) union(f func(proto.TunnelConfig) []string) []string {
	var out []string
	for _, e := range s.Edges {
		out = append(out, f(e.Config)...)
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// MTU is the tunnel MTU the edges ask for (default 1420).
func (s *State) MTU() int { return cmp.Or(s.Primary().Config.MTU, 1420) }

// Status is written by `run` and read by `status`. The embedded health and
// the top-level transport fields summarise the best edge; Edges has each.
type Status struct {
	proto.Health
	Tunnel    string       `json:"tunnel"`
	Endpoint  string       `json:"endpoint"`
	Interface string       `json:"interface,omitempty"`
	Started   time.Time    `json:"started"`
	LastPoll  time.Time    `json:"last_poll,omitempty"`
	PollError string       `json:"poll_error,omitempty"`
	Edges     []EdgeStatus `json:"edges,omitempty"`
}

// EdgeStatus is the live state of one edge.
type EdgeStatus struct {
	Node          string    `json:"node,omitempty"`
	URL           string    `json:"url,omitempty"`
	EdgePublicKey string    `json:"edge_public_key"`
	Address       string    `json:"address"`
	EdgeAddress   string    `json:"edge_address"`
	Learned       bool      `json:"learned,omitempty"`
	Transport     string    `json:"transport,omitempty"`
	Endpoint      string    `json:"endpoint,omitempty"`
	LastHandshake time.Time `json:"last_handshake,omitempty"`
	RxBytes       int64     `json:"rx_bytes"`
	TxBytes       int64     `json:"tx_bytes"`
	LastPoll      time.Time `json:"last_poll,omitempty"`
	PollError     string    `json:"poll_error,omitempty"`
}

// Up reports whether the edge has a transport and a recent handshake.
func (e EdgeStatus) Up(now time.Time) bool {
	return e.Transport != "" && !e.LastHandshake.IsZero() && now.Sub(e.LastHandshake) < staleAfter
}

// DefaultStatePath is where the state file lives unless --state is given.
func DefaultStatePath() string {
	switch runtime.GOOS {
	case "windows":
		if pd := os.Getenv("ProgramData"); pd != "" {
			return filepath.Join(pd, "ingressd-connector", "connector.json")
		}
	case "darwin":
		if os.Geteuid() == 0 {
			return "/Library/Application Support/ingressd-connector/connector.json"
		}
	default:
		if os.Geteuid() == 0 {
			return "/var/lib/ingressd-connector/connector.json"
		}
	}
	if d, err := os.UserConfigDir(); err == nil {
		return filepath.Join(d, "ingressd-connector", "connector.json")
	}
	return "connector.json"
}

// StatusPath is the status file next to the state file.
func StatusPath(statePath string) string {
	return filepath.Join(filepath.Dir(statePath), "status.json")
}

// LoadState reads the state file, migrating a single-edge file.
func LoadState(path string) (*State, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("%s not found: run ingressd-connector enroll first", path)
	}
	if err != nil {
		return nil, err
	}
	return parseState(path, b)
}

func parseState(path string, b []byte) (*State, error) {
	var s State
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if len(s.Edges) == 0 {
		var l legacyState
		if err := json.Unmarshal(b, &l); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		if l.EdgeURL != "" && l.Config != nil {
			s.Edges = []EdgeState{{
				URL: l.EdgeURL, Addr: l.EdgeAddr, CAFile: l.CAFile, CAPEM: l.CAPEM,
				Insecure: l.Insecure, Credential: l.Credential, Config: *l.Config,
			}}
		}
	}
	if len(s.Edges) == 0 {
		return nil, fmt.Errorf("%s: no edges (enroll again)", path)
	}
	return &s, nil
}

// writeJSONFile writes v atomically with mode 0600 through a new temporary
// file. A missing directory is created private to this account and
// administrators (mode 0700; on Windows a protected DACL, see
// upgrade.SecureDir).
func writeJSONFile(path string, v any) error {
	if err := upgrade.EnsureDir(filepath.Dir(path)); err != nil {
		return err
	}
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return upgrade.WriteFileAtomic(path, append(b, '\n'))
}

// SecureStateDir makes the state directory (and the upgrade work directory
// in it) private to this account and administrators, repairing an install
// made before this was enforced. On Windows %ProgramData% otherwise lets
// every local user read the site's private key and plant files the
// SYSTEM service and its upgrade helper would act on.
func SecureStateDir(statePath string) error {
	return upgrade.SecureDir(filepath.Dir(statePath))
}

// Save writes the state file.
func (s *State) Save(path string) error { return writeJSONFile(path, s) }

// LoadStatus reads the status file written by a running connector.
func LoadStatus(statePath string) (*Status, error) {
	b, err := os.ReadFile(StatusPath(statePath))
	if err != nil {
		return nil, err
	}
	var s Status
	return &s, json.Unmarshal(b, &s)
}

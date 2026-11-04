// SPDX-License-Identifier: Apache-2.0

// Package nodeagent is the node side of managed mode (docs/rev1/ARCHITECTURE.md
// §4): enrolment with a hosted panel, the outbound WebSocket control channel,
// signed config snapshots applied through the existing pipeline, and the
// status, usage, live-log, diagnostics and node-answered requests the panel
// needs. Standalone nodes never start it.
package nodeagent

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"time"
)

// File names inside the state directory.
const (
	// StateFile marks a node as managed. Deleting it (detach) returns the
	// node to standalone mode.
	StateFile = "node.json"
	// EndpointFile records how sites and connectors reach this node (its
	// hostname or public IP). It outlives detach so connector endpoints keep
	// working on a node that became standalone.
	EndpointFile = "edge-endpoint.json"
	// RuntimeFile is the running agent's connection state, for
	// `ingressd node status`.
	RuntimeFile = "node-runtime.json"
	// UsageFile holds the usage sequence and unacknowledged deltas.
	UsageFile = "node-usage.json"
	// SnapshotFile is the last applied snapshot's config, restored at
	// startup if config.yaml was edited locally.
	SnapshotFile = "node-snapshot.yaml"
)

// State is the content of node.json (mode 0600).
type State struct {
	NodeID     string `json:"node_id"`
	OrgID      string `json:"org_id,omitempty"`
	Name       string `json:"name,omitempty"`
	Credential string `json:"credential"`
	// OrgSigningKey is the pinned ed25519 public key (base64).
	OrgSigningKey string    `json:"org_signing_key"`
	PanelURL      string    `json:"panel_url"`
	Hostname      string    `json:"hostname,omitempty"`
	PublicIPv4    string    `json:"public_ipv4,omitempty"`
	PublicIPv6    string    `json:"public_ipv6,omitempty"`
	SSHPort       int       `json:"ssh_port,omitempty"`
	EnrolledAt    time.Time `json:"enrolled_at"`
	// AppliedRevision and AppliedConfigSHA describe the last snapshot
	// applied successfully.
	AppliedRevision  int64  `json:"applied_revision"`
	AppliedConfigSHA string `json:"applied_config_sha,omitempty"`
	// AppliedSnapshotSHA identifies the whole applied snapshot (config and
	// secrets), so an identical redelivery is acknowledged without re-applying.
	AppliedSnapshotSHA string `json:"applied_snapshot_sha,omitempty"`
}

// StatePath returns node.json's path in stateDir.
func StatePath(stateDir string) string { return filepath.Join(stateDir, StateFile) }

// Managed reports whether stateDir holds a node.json.
func Managed(stateDir string) bool {
	_, err := os.Stat(StatePath(stateDir))
	return err == nil
}

// LoadState reads node.json. A missing file returns an error wrapping
// fs.ErrNotExist.
func LoadState(stateDir string) (*State, error) {
	b, err := os.ReadFile(StatePath(stateDir))
	if err != nil {
		return nil, err
	}
	st := &State{}
	if err := json.Unmarshal(b, st); err != nil {
		return nil, fmt.Errorf("%s: %w", StatePath(stateDir), err)
	}
	if st.NodeID == "" || st.Credential == "" || st.OrgSigningKey == "" || st.PanelURL == "" {
		return nil, fmt.Errorf("%s is incomplete (re-enroll with ingressd node enroll)", StatePath(stateDir))
	}
	return st, nil
}

// SaveState writes node.json atomically with mode 0600.
func SaveState(stateDir string, st *State) error {
	return writeJSON(StatePath(stateDir), st, 0o600)
}

// RemoveState deletes node.json (detach). A missing file is not an error.
func RemoveState(stateDir string) error {
	err := os.Remove(StatePath(stateDir))
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return err
}

// Endpoint is how sites and connectors reach the node.
type Endpoint struct {
	Hostname   string `json:"hostname,omitempty"`
	PublicIPv4 string `json:"public_ipv4,omitempty"`
}

// Host returns the hostname if set, else the public IPv4, else "".
func (e Endpoint) Host() string {
	if e.Hostname != "" {
		return e.Hostname
	}
	return e.PublicIPv4
}

// HostIsIP reports whether Host is a bare IP address (served with a
// certificate from Caddy's internal CA).
func (e Endpoint) HostIsIP() bool {
	_, err := netip.ParseAddr(e.Host())
	return err == nil
}

// LoadEndpoint reads edge-endpoint.json; a missing or broken file yields
// the zero Endpoint.
func LoadEndpoint(stateDir string) Endpoint {
	var ep Endpoint
	b, err := os.ReadFile(filepath.Join(stateDir, EndpointFile))
	if err != nil {
		return Endpoint{}
	}
	if json.Unmarshal(b, &ep) != nil {
		return Endpoint{}
	}
	return ep
}

// SaveEndpoint writes edge-endpoint.json.
func SaveEndpoint(stateDir string, ep Endpoint) error {
	return writeJSON(filepath.Join(stateDir, EndpointFile), ep, 0o644)
}

// Runtime is the agent's connection state as seen by `ingressd node status`.
type Runtime struct {
	Connected     bool      `json:"connected"`
	Since         time.Time `json:"since,omitempty"`
	LastConnected time.Time `json:"last_connected,omitempty"`
	LastError     string    `json:"last_error,omitempty"`
	PID           int       `json:"pid"`
	UsageSeq      int64     `json:"usage_seq"`
	UsagePending  int       `json:"usage_pending"`
}

// LoadRuntime reads node-runtime.json.
func LoadRuntime(stateDir string) (*Runtime, error) {
	b, err := os.ReadFile(filepath.Join(stateDir, RuntimeFile))
	if err != nil {
		return nil, err
	}
	r := &Runtime{}
	return r, json.Unmarshal(b, r)
}

func writeJSON(path string, v any, mode os.FileMode) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(path, append(b, '\n'), mode)
}

func writeFileAtomic(path string, b []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, mode); err != nil {
		return err
	}
	if err := os.Chmod(tmp, mode); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// SPDX-License-Identifier: Apache-2.0

package health

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// EdgeState is the body of POST /ingressd/state on Caddy's admin API, read
// by the edge_state app (edge/modules/edgestate, which mirrors these types).
type EdgeState struct {
	Pools map[string]EdgePool `json:"pools"`
	// Tunnels lists the tunnels that are down (PoP forwarding sends their
	// apps to sibling nodes).
	Tunnels map[string]EdgeTunnel `json:"tunnels,omitempty"`
	// StickyKey signs sticky-session cookies (base64 in JSON).
	StickyKey []byte `json:"sticky_key,omitempty"`
}

type EdgePool struct {
	// Tier is the lowest priority tier for new sessions (failback hold).
	Tier     int                   `json:"tier,omitempty"`
	Origins  map[string]EdgeOrigin `json:"origins,omitempty"`
	Override *EdgeOverride         `json:"override,omitempty"`
}

// EdgeTunnel carries no reason: it changes with every poll (handshake age)
// and would defeat the unchanged-state check in push.
type EdgeTunnel struct {
	Down bool `json:"down,omitempty"`
}

type EdgeOrigin struct {
	Healthy *bool  `json:"healthy,omitempty"`
	State   string `json:"state,omitempty"`
	Reason  string `json:"reason,omitempty"`
}

type EdgeOverride struct {
	Tier    int        `json:"tier,omitempty"`
	Origins []string   `json:"origins,omitempty"`
	Until   *time.Time `json:"until,omitempty"`
	Reason  string     `json:"reason,omitempty"`
}

// StatePath is the edge_state admin API route.
const StatePath = "/ingressd/state"

// Pusher sends state to Caddy's admin API over its unix socket.
type Pusher struct {
	client *http.Client
}

func NewPusher(adminSocket string) *Pusher {
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", adminSocket)
		},
	}
	return &Pusher{client: &http.Client{Transport: tr, Timeout: 5 * time.Second}}
}

// Push replaces the edge's runtime state.
func (p *Pusher) Push(ctx context.Context, st EdgeState) error {
	b, err := json.Marshal(st)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://localhost"+StatePath, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := p.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("POST %s: %s: %s", StatePath, resp.Status, strings.TrimSpace(string(msg)))
	}
	return nil
}

// LoadStickyKey returns the cookie signing key from the state directory,
// creating it on first use so cookies survive restarts.
func LoadStickyKey(stateDir string) ([]byte, error) {
	path := filepath.Join(stateDir, StickyKeyFile)
	b, err := os.ReadFile(path)
	if err == nil && len(b) >= 32 {
		return b[:32], nil
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	b = make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(stateDir, 0o750); err != nil {
		return nil, err
	}
	return b, os.WriteFile(path, b, 0o600)
}

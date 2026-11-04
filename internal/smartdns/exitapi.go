// SPDX-License-Identifier: Apache-2.0

package smartdns

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"time"

	"github.com/ingressd/ingressd/internal/mesh"
	"github.com/ingressd/ingressd/pkg/config"
)

// The exit resolve API (mesh API, JSON over HTTP on the mesh address, only
// reachable from mesh peers):
//
//	POST /v1/resolve {"exit":"nl","name":"tv.stream.example"}
//	→ {"exit_up":true,"rcode":0,"addrs":["18.239.36.1"],"ttl":60}
//	→ {"exit_up":false,"error":"VPN tunnel ix-x-nl has no recent handshake"}
//	→ {"exit_up":true,"error":"10.2.0.1:53: i/o timeout"}   (resolution failed)

type resolveRequest struct {
	Exit string `json:"exit"`
	Name string `json:"name"`
}

type resolveResponse struct {
	ExitUp bool         `json:"exit_up"`
	Rcode  int          `json:"rcode"`
	Addrs  []netip.Addr `json:"addrs,omitempty"`
	TTL    int          `json:"ttl,omitempty"` // seconds
	Error  string       `json:"error,omitempty"`
}

// errExitDown means the exit cannot egress: its node is unreachable over the
// mesh or its VPN is down. Service names then fail closed (SERVFAIL).
var errExitDown = errors.New("exit is down")

// exitClient talks to exits on other nodes (tests replace it).
type exitClient interface {
	// Resolve asks node to resolve name for exit. An error means the node
	// could not be reached (transport failure).
	Resolve(ctx context.Context, node, exit, name string) (resolveResponse, error)
	// Connect opens a relayed stream through node.
	Connect(ctx context.Context, node string, req ConnectRequest) (net.Conn, error)
	Up(node string) bool
	MarkDown(node string, err error)
}

type meshExitClient struct{ m *mesh.Mesh }

func (c meshExitClient) Up(node string) bool             { return c.m.Up(node) }
func (c meshExitClient) MarkDown(node string, err error) { c.m.MarkDown(node, err) }

func (c meshExitClient) Resolve(ctx context.Context, node, exit, name string) (resolveResponse, error) {
	var out resolveResponse
	u, err := c.m.URL(node, "/v1/resolve")
	if err != nil {
		return out, err
	}
	body, _ := json.Marshal(resolveRequest{Exit: exit, Name: name})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(body))
	if err != nil {
		return out, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.m.Client().Do(req)
	if err != nil {
		return out, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return out, fmt.Errorf("exit node answered HTTP %d", resp.StatusCode)
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return out, fmt.Errorf("exit node: %w", err)
	}
	return out, nil
}

func (c meshExitClient) Connect(ctx context.Context, node string, req ConnectRequest) (net.Conn, error) {
	conn, err := c.m.DialPeer(ctx, node, config.MeshRelayPort)
	if err != nil {
		return nil, err
	}
	conn.SetDeadline(time.Now().Add(dialTimeout*2 + probeTimeout))
	if err := WriteConnectRequest(conn, req); err != nil {
		conn.Close()
		return nil, err
	}
	resp, err := ReadConnectResponse(conn)
	if err != nil {
		conn.Close()
		return nil, err
	}
	if !resp.OK {
		conn.Close()
		return nil, &relayRefused{resp.Error}
	}
	conn.SetDeadline(time.Time{})
	return conn, nil
}

// relayRefused is an exit's refusal (as opposed to a transport failure).
type relayRefused struct{ msg string }

func (e *relayRefused) Error() string { return "exit refused: " + e.msg }

// resolveHandler serves POST /v1/resolve on exit nodes.
func (m *Manager) resolveHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req resolveRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil || req.Name == "" {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		resp := m.resolveLocal(r.Context(), req.Exit, normalize(req.Name))
		json.NewEncoder(w).Encode(resp)
	})
}

// resolveLocal resolves name for one of this node's own exits.
func (m *Manager) resolveLocal(ctx context.Context, exit, name string) resolveResponse {
	e, ok := m.state().egress[exit]
	if !ok {
		return resolveResponse{Error: fmt.Sprintf("exit %q is not hosted on this node", exit)}
	}
	if up, msg := e.up(); !up {
		return resolveResponse{Error: msg}
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	rcode, a, err := e.resolve(ctx, name)
	if err != nil {
		return resolveResponse{ExitUp: true, Error: err.Error()}
	}
	if len(a.Addrs) > 0 {
		m.edges.prewarm(e, name, a.Addrs)
	}
	return resolveResponse{ExitUp: true, Rcode: rcode, Addrs: a.Addrs, TTL: int(a.TTL / time.Second)}
}

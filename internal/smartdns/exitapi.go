// SPDX-License-Identifier: Apache-2.0

package smartdns

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"time"

	"github.com/ingressd/ingressd/internal/mesh"
	"github.com/ingressd/ingressd/pkg/config"
)

// The exit resolve API (mesh API, JSON over HTTP on the mesh address, only
// reachable from mesh peers):
//
//	POST /v1/resolve {"exit":"nl","name":"tv.stream.example","realm":""}
//	→ {"exit_up":true,"rcode":0,"addrs":["18.239.36.1"],"ttl":60}
//	→ {"exit_up":false,"error":"VPN tunnel ix-x-nl has no recent handshake"}
//	→ {"exit_up":true,"error":"10.2.0.1:53: i/o timeout"}   (resolution failed)
//
//	GET /v1/exits?realm=<r>   (health of the exits the node hosts for realm r,
//	                          default none; 404 on older nodes)
//
// An exit of realm r (realms.r.smartdns) is only resolved, relayed through
// and reported for requests naming r, and an exit outside realms only for
// requests naming none.
//	→ {"exits":{"gb-lon":{"up":true},"gb-ams":{"up":false,"error":"no recent handshake"}}}

type resolveRequest struct {
	Exit string `json:"exit"`
	Name string `json:"name"`
	// Realm is the realm the home node resolves for ("" outside realms);
	// the exit node refuses an exit of any other realm.
	Realm string `json:"realm,omitempty"`
}

type resolveResponse struct {
	ExitUp bool         `json:"exit_up"`
	Rcode  int          `json:"rcode"`
	Addrs  []netip.Addr `json:"addrs,omitempty"`
	TTL    int          `json:"ttl,omitempty"` // seconds
	Error  string       `json:"error,omitempty"`
}

type exitState struct {
	Up    bool   `json:"up"`
	Error string `json:"error,omitempty"`
}

type exitsResponse struct {
	Exits map[string]exitState `json:"exits"`
}

// errHealthUnsupported: the exit node predates GET /v1/exits; its exits are
// then judged by the mesh probe and resolve answers only.
var errHealthUnsupported = errors.New("exit node does not report exit health")

// errExitDown means the exit cannot egress: its node is unreachable over the
// mesh or its VPN is down. Service names then fail closed (SERVFAIL).
var errExitDown = errors.New("exit is down")

// exitClient talks to exits on other nodes (tests replace it).
type exitClient interface {
	// Resolve asks node to resolve name for exit. An error means the node
	// could not be reached (transport failure).
	Resolve(ctx context.Context, node, realm, exit, name string) (resolveResponse, error)
	// Connect opens a relayed stream through node.
	Connect(ctx context.Context, node string, req ConnectRequest) (net.Conn, error)
	// Health returns the state of the exits node hosts for realm, or
	// errHealthUnsupported.
	Health(ctx context.Context, node, realm string) (map[string]exitState, error)
	Up(node string) bool
	MarkDown(node string, err error)
}

type meshExitClient struct{ m *mesh.Mesh }

func (c meshExitClient) Up(node string) bool             { return c.m.Up(node) }
func (c meshExitClient) MarkDown(node string, err error) { c.m.MarkDown(node, err) }

func (c meshExitClient) Resolve(ctx context.Context, node, realm, exit, name string) (resolveResponse, error) {
	var out resolveResponse
	u, err := c.m.URL(node, "/v1/resolve")
	if err != nil {
		return out, err
	}
	body, _ := json.Marshal(resolveRequest{Exit: exit, Name: name, Realm: realm})
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

func (c meshExitClient) Health(ctx context.Context, node, realm string) (map[string]exitState, error) {
	path := "/v1/exits"
	if realm != "" {
		path += "?realm=" + url.QueryEscape(realm)
	}
	u, err := c.m.URL(node, path)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.m.Client().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound, http.StatusMethodNotAllowed:
		return nil, errHealthUnsupported
	default:
		return nil, fmt.Errorf("exit node answered HTTP %d", resp.StatusCode)
	}
	var out exitsResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&out); err != nil {
		return nil, fmt.Errorf("exit node: %w", err)
	}
	return out.Exits, nil
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
		return nil, &relayRefused{msg: resp.Error, exitDown: resp.ExitDown}
	}
	conn.SetDeadline(time.Time{})
	return conn, nil
}

// relayRefused is an exit's refusal (as opposed to a transport failure).
type relayRefused struct {
	msg      string
	exitDown bool
}

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
		resp := m.resolveLocal(r.Context(), req.Realm, req.Exit, normalize(req.Name))
		json.NewEncoder(w).Encode(resp)
	})
}

// exitsHandler serves GET /v1/exits on exit nodes.
func (m *Manager) exitsHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		out := exitsResponse{Exits: map[string]exitState{}}
		st, realm := m.state(), r.URL.Query().Get("realm")
		for name, e := range st.egress {
			if st.exits[name].realm != realm {
				continue
			}
			up, msg := e.up()
			out.Exits[name] = exitState{Up: up, Error: msg}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(out)
	})
}

// resolveLocal resolves name for one of this node's own exits of realm.
func (m *Manager) resolveLocal(ctx context.Context, realm, exit, name string) resolveResponse {
	e, err := m.selfExit(realm, exit)
	if err != nil {
		return resolveResponse{Error: err.Error()}
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

// selfExit returns one of this node's exits, provided it belongs to the
// realm the request is for: a home node serving one realm can never use,
// probe or relay through another realm's exit.
func (m *Manager) selfExit(realm, exit string) (*egress, error) {
	st := m.state()
	e, ok := st.egress[exit]
	switch {
	case !ok:
		return nil, fmt.Errorf("exit %q is not hosted on this node", exit)
	case st.exits[exit].realm != realm && realm == "":
		return nil, fmt.Errorf("exit %q belongs to a realm; the request names none", exit)
	case st.exits[exit].realm != realm:
		return nil, fmt.Errorf("exit %q is not hosted on this node for realm %q", exit, realm)
	}
	return e, nil
}

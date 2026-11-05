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
	"strconv"
	"time"

	"github.com/ingressd/ingressd/pkg/config"
)

// The node exit API, served on each allowed connector tunnel's edge transit
// address (config.SmartDNSExitAPIPort) and reached by the connector through
// that tunnel only:
//
//	POST /v1/resolve {"name":"tv.stream.example"}
//	→ {"exit_up":true,"rcode":0,"addrs":["18.239.36.1"],"ttl":60}
//	→ {"exit_up":false,"error":"egress 198.51.100.7 geolocates to DE, expected NL"}
//	→ {"exit_up":true,"error":"1.1.1.1:53: i/o timeout"}   (resolution failed)
//
//	GET /v1/exit → {"up":true,"country":"NL","egress":"198.51.100.7"}

type resolveRequest struct {
	Name string `json:"name"`
}

type resolveResponse struct {
	ExitUp bool         `json:"exit_up"`
	Rcode  int          `json:"rcode"`
	Addrs  []netip.Addr `json:"addrs,omitempty"`
	TTL    int          `json:"ttl,omitempty"` // seconds
	Error  string       `json:"error,omitempty"`
}

type exitState struct {
	Up      bool   `json:"up"`
	Country string `json:"country,omitempty"`
	Egress  string `json:"egress,omitempty"`
	Error   string `json:"error,omitempty"`
}

// errExitDown means the exit cannot egress: its node is unreachable or
// reports itself down, or its VPN is down. Service names then fail closed
// (SERVFAIL).
var errExitDown = errors.New("exit is down")

// ExitClient talks to node exits (the connector reaches them through its
// tunnels; tests replace it).
type ExitClient interface {
	// Resolve asks node to resolve name. An error means the node could not
	// be reached (transport failure).
	Resolve(ctx context.Context, node, name string) (resolveResponse, error)
	// Connect opens a relayed stream through node.
	Connect(ctx context.Context, node string, req ConnectRequest) (net.Conn, error)
	// Health returns the node exit's state.
	Health(ctx context.Context, node string) (exitState, error)
	// Up reports whether node is reachable at all (its tunnel is up).
	Up(node string) bool
}

// TunnelExitClient reaches node exits at their edge transit addresses
// through Dial (the connector's tunnel).
type TunnelExitClient struct {
	// Addr returns a node's edge transit address, false when the site has
	// no tunnel to it.
	Addr func(node string) (netip.Addr, bool)
	// NodeUp reports whether the tunnel to node is up.
	NodeUp func(node string) bool
	Dial   DialFunc
}

func (c *TunnelExitClient) Up(node string) bool { return c.NodeUp(node) }

func (c *TunnelExitClient) addr(node string, port int) (string, error) {
	a, ok := c.Addr(node)
	if !ok {
		return "", fmt.Errorf("no tunnel to node %s", node)
	}
	return net.JoinHostPort(a.String(), strconv.Itoa(port)), nil
}

func (c *TunnelExitClient) http() *http.Client {
	return &http.Client{
		Timeout:   healthTimeout,
		Transport: &http.Transport{DialContext: c.Dial, Proxy: nil, DisableKeepAlives: true},
	}
}

func (c *TunnelExitClient) Resolve(ctx context.Context, node, name string) (resolveResponse, error) {
	var out resolveResponse
	a, err := c.addr(node, config.SmartDNSExitAPIPort)
	if err != nil {
		return out, err
	}
	body, _ := json.Marshal(resolveRequest{Name: name})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://"+a+"/v1/resolve", bytes.NewReader(body))
	if err != nil {
		return out, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http().Do(req)
	if err != nil {
		return out, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return out, fmt.Errorf("exit node answered HTTP %d", resp.StatusCode)
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&out); err != nil {
		return out, fmt.Errorf("exit node: %w", err)
	}
	return out, nil
}

func (c *TunnelExitClient) Health(ctx context.Context, node string) (exitState, error) {
	var out exitState
	a, err := c.addr(node, config.SmartDNSExitAPIPort)
	if err != nil {
		return out, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+a+"/v1/exit", nil)
	if err != nil {
		return out, err
	}
	resp, err := c.http().Do(req)
	if err != nil {
		return out, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return out, fmt.Errorf("exit node answered HTTP %d", resp.StatusCode)
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&out); err != nil {
		return out, fmt.Errorf("exit node: %w", err)
	}
	return out, nil
}

func (c *TunnelExitClient) Connect(ctx context.Context, node string, req ConnectRequest) (net.Conn, error) {
	a, err := c.addr(node, config.SmartDNSExitRelayPort)
	if err != nil {
		return nil, err
	}
	conn, err := c.Dial(ctx, "tcp4", a)
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

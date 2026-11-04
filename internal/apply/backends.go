// SPDX-License-Identifier: Apache-2.0

package apply

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os/exec"
	"strings"
	"time"
)

// NFT loads an nft script as a single atomic transaction.
func NFT(ctx context.Context, script string) error {
	cmd := exec.CommandContext(ctx, "nft", "-f", "-")
	cmd.Stdin = strings.NewReader(script)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// Caddy talks to Caddy's admin API over a unix socket.
type Caddy struct {
	client *http.Client
}

func NewCaddy(socket string) *Caddy {
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", socket)
		},
	}
	return &Caddy{client: &http.Client{Transport: tr, Timeout: 2 * time.Minute}}
}

// Load replaces Caddy's running config. Caddy validates and provisions the
// new config before switching, and keeps the old one if that fails.
func (c *Caddy) Load(ctx context.Context, cfg json.RawMessage) error {
	_, err := c.do(ctx, http.MethodPost, "/load", cfg)
	return err
}

// Config returns Caddy's running config.
func (c *Caddy) Config(ctx context.Context) (json.RawMessage, error) {
	return c.do(ctx, http.MethodGet, "/config/", nil)
}

func (c *Caddy) do(ctx context.Context, method, path string, body []byte) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, method, "http://localhost"+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s %s: %s: %s", method, path, resp.Status, strings.TrimSpace(string(b)))
	}
	return b, nil
}

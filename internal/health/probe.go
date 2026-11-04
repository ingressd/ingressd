// SPDX-License-Identifier: Apache-2.0

package health

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"time"

	"github.com/ingressd/ingressd/pkg/config"
)

// Target is what one origin's check dials.
type Target struct {
	// Dial is host:port as reached from the edge (render.DialAddress), so
	// remapped tunnels are probed at their virtual address.
	Dial string
	// Scheme is the origin's scheme; https checks use TLS.
	Scheme string
	// Host is the origin's own host (from its address), used as the Host
	// header and TLS server name when the check sets none.
	Host string
}

// maxBody bounds how much of a response is read for expect_body.
const maxBody = 64 << 10

// Probe runs one check and returns its latency, or why it failed.
func Probe(ctx context.Context, h *config.HealthCheck, t Target) (time.Duration, error) {
	ctx, cancel := context.WithTimeout(ctx, time.Duration(h.Timeout))
	defer cancel()
	start := time.Now()
	var err error
	if h.Type == config.HealthTCP {
		err = probeTCP(ctx, t)
	} else {
		err = probeHTTP(ctx, h, t)
	}
	return time.Since(start), err
}

func probeTCP(ctx context.Context, t Target) error {
	var d net.Dialer
	c, err := d.DialContext(ctx, "tcp", t.Dial)
	if err != nil {
		return err
	}
	return c.Close()
}

func probeHTTP(ctx context.Context, h *config.HealthCheck, t Target) error {
	host := h.Host
	if host == "" {
		host = t.Host
	}
	serverName, _, err := net.SplitHostPort(host)
	if err != nil {
		serverName = host
	}
	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, t.Dial)
		},
		// Origin TLS verification modes arrive in Phase 7; until then the
		// check matches the proxy, which encrypts without verifying.
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true, ServerName: serverName}, //nolint:gosec
		DisableKeepAlives: true,
	}
	defer tr.CloseIdleConnections()
	client := &http.Client{
		Transport:     tr,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	u := url.URL{Scheme: t.Scheme, Host: t.Dial, Path: h.Path}
	if u.Scheme == "" {
		u.Scheme = "http"
	}
	req, err := http.NewRequestWithContext(ctx, h.Method, u.String(), nil)
	if err != nil {
		return err
	}
	req.Host = host
	req.Header.Set("User-Agent", "ingressd-health/1")
	resp, err := client.Do(req)
	if err != nil {
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			return fmt.Errorf("timeout after %s", time.Duration(h.Timeout))
		}
		return err
	}
	defer resp.Body.Close()
	if len(h.ExpectStatus) > 0 && !slices.Contains(h.ExpectStatus, resp.StatusCode) {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	if h.ExpectBody != "" {
		re, err := regexp.Compile(h.ExpectBody)
		if err != nil {
			return err
		}
		b, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
		if err != nil {
			return err
		}
		if !re.Match(b) {
			return fmt.Errorf("body does not match %q", h.ExpectBody)
		}
	}
	return nil
}

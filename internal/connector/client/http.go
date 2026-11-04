// SPDX-License-Identifier: Apache-2.0

package client

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"
)

// dialFunc dials a TCP address.
type dialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// edgeHost returns the hostname of the edge URL.
func edgeHost(edgeURL string) (string, error) {
	u, err := url.Parse(edgeURL)
	if err != nil {
		return "", err
	}
	if u.Scheme != "https" || u.Hostname() == "" {
		return "", fmt.Errorf("edge URL must look like https://edge.example.com, got %q", edgeURL)
	}
	return u.Hostname(), nil
}

// tlsConfig returns the TLS settings for talking to the edge. A CA from a
// file or inline PEM (from a join string) replaces the system roots, which
// pins the edge to that CA.
func tlsConfig(serverName, caFile, caPEM string, insecure bool) (*tls.Config, error) {
	c := &tls.Config{ServerName: serverName, InsecureSkipVerify: insecure, NextProtos: []string{"http/1.1"}} //nolint:gosec // insecure is the explicit --insecure testing flag
	if caFile != "" || caPEM != "" {
		pem := []byte(caPEM)
		if caFile != "" {
			b, err := os.ReadFile(caFile) //nolint:gosec // operator-supplied CA file
			if err != nil {
				return nil, err
			}
			pem = b
		} else {
			caFile = "join string CA"
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("%s: no PEM certificates", caFile)
		}
		c.RootCAs = pool
	}
	return c, nil
}

// publicDialer dials the edge over the internet, replacing the edge's
// hostname with edgeAddr when one is configured.
func publicDialer(host, edgeAddr string) dialFunc {
	d := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		if h, port, err := net.SplitHostPort(addr); err == nil && edgeAddr != "" && h == host {
			addr = net.JoinHostPort(edgeAddr, port)
		}
		return d.DialContext(ctx, network, addr)
	}
}

// httpClient builds an HTTP/1.1 client for the edge with the given dialer.
func httpClient(tc *tls.Config, dial dialFunc, timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DialContext:         dial,
			TLSClientConfig:     tc,
			TLSHandshakeTimeout: 10 * time.Second,
			IdleConnTimeout:     60 * time.Second,
			MaxIdleConnsPerHost: 2,
		},
	}
}

// SPDX-License-Identifier: Apache-2.0

package nodeagent

import (
	"cmp"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"syscall"
	"time"

	"github.com/ingressd/ingressd/internal/edgecert"
	"github.com/ingressd/ingressd/internal/render"
	"github.com/ingressd/ingressd/internal/tunnel"
	"github.com/ingressd/ingressd/pkg/config"
	"github.com/ingressd/ingressd/pkg/nodeproto"
)

const defaultDiagTimeout = 10 * time.Second

// readTunnelStatus is replaceable in tests.
var readTunnelStatus = tunnel.ReadStatus

// Diagnose runs one diagnostic request.
func (a *Agent) Diagnose(ctx context.Context, req nodeproto.DiagRequest) nodeproto.DiagResult {
	timeout := req.Timeout
	if timeout <= 0 || timeout > time.Minute {
		timeout = defaultDiagTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var res nodeproto.DiagResult
	cfg, err := a.loadConfig()
	switch {
	case err != nil:
		res = nodeproto.DiagResult{Code: "error", Message: "config: " + err.Error()}
	case req.Kind == nodeproto.DiagOrigin:
		res = DiagnoseOrigin(ctx, cfg, req.App, timeout)
	case req.Kind == nodeproto.DiagHTTP:
		res = a.diagnoseHTTP(ctx, cfg, req, timeout)
	case req.Kind == nodeproto.DiagTunnel:
		res = diagnoseTunnel(cfg, req)
	case req.Kind == nodeproto.DiagL4:
		res = DiagnoseL4(ctx, cfg, req.App, timeout)
	default:
		res = nodeproto.DiagResult{Code: "error", Message: fmt.Sprintf("unknown diagnostic kind %q", req.Kind)}
	}
	res.RequestID, res.Kind = req.RequestID, req.Kind
	res.OK = res.Code == nodeproto.DiagCodeOK
	return res
}

type stepper struct {
	steps []nodeproto.DiagStep
	t     time.Time
}

func (s *stepper) begin() { s.t = time.Now() }

func (s *stepper) end(name string, ok bool, format string, args ...any) {
	s.steps = append(s.steps, nodeproto.DiagStep{
		Name: name, OK: ok, Detail: fmt.Sprintf(format, args...),
		DurationMS: float64(time.Since(s.t).Microseconds()) / 1000,
	})
}

func (s *stepper) result(code, format string, args ...any) nodeproto.DiagResult {
	return nodeproto.DiagResult{Code: code, Steps: s.steps, Message: fmt.Sprintf(format, args...)}
}

// originTarget resolves an app's first active origin: dial address (with
// tunnel remapping), scheme, tunnel name and the Host header to send.
func originTarget(cfg *config.Config, appName string) (dial, scheme, tun, host string, err error) {
	app, ok := cfg.Apps[appName]
	if !ok {
		return "", "", "", "", fmt.Errorf("unknown app %q", appName)
	}
	ts, err := render.OriginTargets(cfg, app)
	if err != nil {
		return "", "", "", "", err
	}
	if len(ts) == 0 {
		return "", "", "", "", fmt.Errorf("app %q has no active origin", appName)
	}
	t := ts[0]
	tun = app.Tunnel
	if app.Pool != "" {
		for _, o := range cfg.Pools[app.Pool].Origins {
			if o.Name == t.Name {
				tun = o.Tunnel
			}
		}
	}
	for _, h := range app.Hosts {
		if !strings.HasPrefix(h, "*.") {
			host = h
			break
		}
	}
	return t.Dial, t.Scheme, tun, host, nil
}

// DiagnoseOrigin checks an app's origin hop by hop: the site's tunnel, a
// TCP connection through it, TLS (https origins) and an HTTP response.
func DiagnoseOrigin(ctx context.Context, cfg *config.Config, appName string, timeout time.Duration) nodeproto.DiagResult {
	var s stepper
	s.begin()
	dial, scheme, tun, host, err := originTarget(cfg, appName)
	if err != nil {
		s.end("edge", false, "%v", err)
		return s.result("error", "%v", err)
	}
	s.end("edge", true, "origin %s://%s", scheme, dial)

	if tun != "" {
		s.begin()
		sts, err := readTunnelStatus(cfg)
		var st *tunnel.Status
		for i := range sts {
			if sts[i].Tunnel == tun {
				st = &sts[i]
			}
		}
		now := time.Now()
		switch {
		case err != nil:
			s.end("tunnel", false, "reading WireGuard state: %v", err)
			return s.result(nodeproto.DiagCodeTunnelDown, "could not read tunnel %s: %v", tun, err)
		case st == nil || !st.Up:
			s.end("tunnel", false, "interface for %s is not up", tun)
			return s.result(nodeproto.DiagCodeTunnelDown, "tunnel %s is not up on the edge", tun)
		case !st.Healthy(now):
			detail := "no handshake yet"
			if !st.LastHandshake.IsZero() {
				detail = fmt.Sprintf("last handshake %s ago", now.Sub(st.LastHandshake).Round(time.Second))
			}
			s.end("tunnel", false, "%s", detail)
			return s.result(nodeproto.DiagCodeTunnelDown, "site %s is not connected (%s)", tun, detail)
		default:
			s.end("tunnel", true, "handshake %s ago", now.Sub(st.LastHandshake).Round(time.Second))
		}
	}

	connectTimeout := min(5*time.Second, timeout/2)
	s.begin()
	d := net.Dialer{Timeout: connectTimeout}
	conn, err := d.DialContext(ctx, "tcp", dial)
	if err != nil {
		code, msg := classifyDialError(err)
		// Through a connector it is the connector's machine that dials the
		// service, so a timeout is never the router's VPN firewall zone.
		var ne net.Error
		if t, ok := cfg.Tunnels[tun]; ok && t.Site == config.SiteConnector && (errors.As(err, &ne) && ne.Timeout() || errors.Is(err, context.DeadlineExceeded)) {
			msg = "no reply to the connection attempt: the tunnel is up, so the connector's machine could not reach the service or its replies did not come back (a tun-mode connector that is not the LAN's router needs masquerade on: see 'ingressd-connector status'; also check the address and port, that the service listens on the LAN and not only on localhost, and firewalls between the connector's machine and the service)"
		}
		s.end("connect", false, "%s: %v", dial, err)
		return s.result(code, "%s", msg)
	}
	defer conn.Close()
	s.end("connect", true, "TCP connected to %s", dial)

	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	var rw net.Conn = conn
	if scheme == "https" {
		s.begin()
		sn, _, _ := net.SplitHostPort(dial)
		if host != "" {
			sn = host
		}
		tc := tls.Client(conn, &tls.Config{ServerName: sn, InsecureSkipVerify: true}) //nolint:gosec // reachability, not trust
		if err := tc.HandshakeContext(ctx); err != nil {
			s.end("tls", false, "%v", err)
			return s.result(nodeproto.DiagCodeTLSError, "TLS handshake with the origin failed: %v", err)
		}
		s.end("tls", true, "%s", tls.VersionName(tc.ConnectionState().Version))
		rw = tc
	}

	s.begin()
	status, err := httpOnConn(ctx, rw, scheme, cmp.Or(host, dial))
	if err != nil {
		s.end("http", false, "%v", err)
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() || errors.Is(err, context.DeadlineExceeded) {
			return s.result(nodeproto.DiagCodeTimeout, "the origin accepted the connection but sent no HTTP response")
		}
		return s.result(nodeproto.DiagCodeTimeout, "no valid HTTP response from the origin: %v", err)
	}
	if status >= 500 {
		s.end("http", false, "HTTP %d", status)
		return s.result(nodeproto.DiagCodeHTTPError, "the origin answered HTTP %d", status)
	}
	s.end("http", true, "HTTP %d", status)
	return s.result(nodeproto.DiagCodeOK, "origin reachable (HTTP %d)", status)
}

// classifyDialError maps a TCP connect failure to a diagnostic code.
func classifyDialError(err error) (code, msg string) {
	var ne net.Error
	switch {
	case errors.Is(err, syscall.ECONNREFUSED):
		return nodeproto.DiagCodeRefused, "connection refused: nothing is listening on the origin port"
	case errors.As(err, &ne) && ne.Timeout(), errors.Is(err, context.DeadlineExceeded):
		return nodeproto.DiagCodeNoReply, "no reply to the connection attempt: the tunnel is up, so the site's router is probably dropping traffic from the tunnel (check its firewall zone for the VPN)"
	case errors.Is(err, syscall.EHOSTUNREACH), errors.Is(err, syscall.ENETUNREACH):
		return nodeproto.DiagCodeNoReply, "the site's router reports the origin unreachable: " + err.Error()
	default:
		return nodeproto.DiagCodeNoReply, err.Error()
	}
}

// httpOnConn sends one GET / over an established connection and returns the
// status code.
func httpOnConn(ctx context.Context, c net.Conn, scheme, host string) (int, error) {
	used := false
	tr := &http.Transport{
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			if used {
				return nil, errors.New("connection already used")
			}
			used = true
			return c, nil
		},
		DialTLSContext: func(context.Context, string, string) (net.Conn, error) {
			if used {
				return nil, errors.New("connection already used")
			}
			used = true
			return c, nil
		},
		DisableKeepAlives: true,
	}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, scheme+"://"+host+"/", nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("User-Agent", "ingressd-diag/1")
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	return resp.StatusCode, nil
}

// diagnoseHTTP requests https://<host>/ from the node's own public address
// with the right SNI, verifying the certificate (system roots plus Caddy's
// internal CA for acme.ca internal / bare-IP endpoints).
func (a *Agent) diagnoseHTTP(ctx context.Context, cfg *config.Config, req nodeproto.DiagRequest, timeout time.Duration) nodeproto.DiagResult {
	var s stepper
	s.begin()
	host := req.Host
	if host == "" && req.App != "" {
		if app, ok := cfg.Apps[req.App]; ok {
			for _, h := range app.Hosts {
				if !strings.HasPrefix(h, "*.") {
					host = h
					break
				}
			}
		}
	}
	if host == "" {
		s.end("edge", false, "no host")
		return s.result("error", "diag http needs a host or an app with a host")
	}
	st := a.State()
	ip := cmp.Or(st.PublicIPv4, cfg.Edge.PublicIPv4, "127.0.0.1")
	addr := net.JoinHostPort(ip, "443")
	s.end("edge", true, "https://%s via %s", host, addr)

	roots, _ := x509.SystemCertPool()
	if roots == nil {
		roots = x509.NewCertPool()
	}
	if pem, err := edgecert.InternalCARoot(a.o.CaddyStorage); err == nil {
		roots.AppendCertsFromPEM(pem)
	}
	s.begin()
	d := net.Dialer{Timeout: min(5*time.Second, timeout/2)}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		code, _ := classifyDialError(err)
		if code == nodeproto.DiagCodeNoReply {
			code = nodeproto.DiagCodeTimeout
		}
		s.end("connect", false, "%v", err)
		return s.result(code, "could not connect to the edge at %s: %v", addr, err)
	}
	defer conn.Close()
	s.end("connect", true, "connected to %s", addr)
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	s.begin()
	tc := tls.Client(conn, &tls.Config{ServerName: host, RootCAs: roots, NextProtos: []string{"http/1.1"}})
	if err := tc.HandshakeContext(ctx); err != nil {
		s.end("tls", false, "%v", err)
		return s.result(nodeproto.DiagCodeTLSError, "TLS to the edge failed for %s: %v", host, err)
	}
	s.end("tls", true, "certificate valid for %s", host)
	s.begin()
	status, err := httpOnConn(ctx, tc, "https", host)
	if err != nil {
		s.end("http", false, "%v", err)
		return s.result(nodeproto.DiagCodeTimeout, "no HTTP response from the edge: %v", err)
	}
	switch {
	case status < 400, status == 401, status == 403:
		s.end("http", true, "HTTP %d", status)
		return s.result(nodeproto.DiagCodeOK, "live (HTTP %d)", status)
	default:
		s.end("http", false, "HTTP %d", status)
		return s.result(nodeproto.DiagCodeHTTPError, "the edge answered HTTP %d for %s", status, host)
	}
}

// diagnoseTunnel summarises a site's tunnel (req.Host names the site, or
// req.App selects the app's site).
func diagnoseTunnel(cfg *config.Config, req nodeproto.DiagRequest) nodeproto.DiagResult {
	var s stepper
	s.begin()
	site := req.Host
	if site == "" && req.App != "" {
		site = cfg.Apps[req.App].Tunnel
	}
	if _, ok := cfg.Tunnels[site]; !ok {
		s.end("tunnel", false, "unknown site %q", site)
		return s.result("error", "unknown site %q", site)
	}
	sts, err := readTunnelStatus(cfg)
	if err != nil {
		s.end("tunnel", false, "%v", err)
		return s.result(nodeproto.DiagCodeTunnelDown, "%v", err)
	}
	for _, st := range sts {
		if st.Tunnel != site {
			continue
		}
		if st.Healthy(time.Now()) {
			s.end("tunnel", true, "handshake %s ago, endpoint %s", time.Since(st.LastHandshake).Round(time.Second), st.Endpoint)
			return s.result(nodeproto.DiagCodeOK, "site %s connected", site)
		}
	}
	s.end("tunnel", false, "no recent handshake")
	return s.result(nodeproto.DiagCodeTunnelDown, "site %s is not connected", site)
}

// SPDX-License-Identifier: Apache-2.0

package smartdns

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"time"
)

const (
	peekTimeout = 10 * time.Second
	relayBuf    = 64 << 10
)

func (m *Manager) listenRelay(addr string, isTLS bool) (io.Closer, error) {
	ln, err := m.listenFn("tcp4", addr)
	if err != nil {
		return nil, err
	}
	go acceptLoop(ln, func(c net.Conn) { m.handleRelay(c, isTLS) })
	return ln, nil
}

func acceptLoop(ln net.Listener, handle func(net.Conn)) {
	for {
		c, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			time.Sleep(50 * time.Millisecond)
			continue
		}
		go handle(c)
	}
}

// peekHost reads from c until the TLS SNI or HTTP Host is known and returns
// it with the bytes read (to be replayed upstream).
func peekHost(c net.Conn, isTLS bool) (string, []byte, error) {
	parse := hostFromHTTP
	if isTLS {
		parse = sniFromHello
	}
	c.SetReadDeadline(time.Now().Add(peekTimeout))
	defer c.SetReadDeadline(time.Time{})
	data := make([]byte, 0, 4096)
	buf := make([]byte, 4096)
	for {
		host, err := parse(data)
		if !errors.Is(err, errNeedMore) {
			return host, data, err
		}
		if len(data) > maxHello {
			return "", nil, errors.New("hello too large")
		}
		n, err := c.Read(buf)
		if n > 0 {
			data = append(data, buf[:n]...)
			continue
		}
		if err != nil {
			return "", nil, fmt.Errorf("closed before the hostname: %w", err)
		}
	}
}

// handleRelay serves one LAN connection to the relay (:443 or :80 on the
// listen address): only hostnames of enabled services, only from private
// sources, only through one of the service's exits.
func (m *Manager) handleRelay(c net.Conn, isTLS bool) {
	defer c.Close()
	client := netAddr(c.RemoteAddr())
	if !allowedClient(client) {
		m.refused.Add(1)
		return
	}
	host, head, err := peekHost(c, isTLS)
	if err != nil || host == "" {
		m.refused.Add(1)
		m.log.Debug("relay: no hostname", "client", client, "err", err)
		return
	}
	st := m.state()
	r, ok := st.match.match(host)
	if !ok {
		m.refused.Add(1)
		m.log.Info("relay refused: not a service hostname", "host", host, "client", client)
		return
	}
	port := 80
	if isTLS {
		port = 443
	}
	ctx, cancel := context.WithTimeout(m.ctx(), queryTimeout+dialTimeout*2)
	up, exit, err := m.connectUpstream(ctx, st, r, host, port)
	cancel()
	if err != nil {
		m.err.Add(1)
		m.log.Warn("relay failed", "host", host, "service", r.Service, "exit", exit, "err", err)
		return
	}
	defer up.Close()
	ctr := m.counter(r.Service)
	ctr.conns.Add(1)
	// From here on the stream is committed to this exit: once a client
	// byte went upstream, a retry elsewhere could replay a request.
	if _, err := up.Write(head); err != nil {
		return
	}
	ctr.bytes.Add(int64(len(head)))
	pipe(c, up, &ctr.bytes)
}

// connectUpstream resolves host and connects to it through the service's
// active exit. When that exit turns out to be down before any client byte
// was sent (tunnel failure, or a refusal saying the exit is down), it is
// marked down and the next exit is tried, at most once per exit.
func (m *Manager) connectUpstream(ctx context.Context, st *state, r route, host string, port int) (net.Conn, string, error) {
	tried := map[string]bool{}
	var lastErr error
	for {
		a, rcode, _, exit, err := m.lookup(ctx, st, r, host)
		if err != nil {
			return nil, exit, err
		}
		if tried[exit] {
			return nil, exit, lastErr
		}
		tried[exit] = true
		if rcode != 0 || len(a.Addrs) == 0 {
			return nil, exit, fmt.Errorf("no A records for %s at exit %s", host, exit)
		}
		c, retry, err := m.openUpstream(ctx, st, r.Service, exit, host, a.Addrs, port)
		if err == nil {
			return c, exit, nil
		}
		if !retry || ctx.Err() != nil {
			return nil, exit, err
		}
		m.log.Info("relay: exit down before any byte was sent; trying the next exit", "host", host, "service", r.Service, "exit", exit, "err", err)
		lastErr = err
	}
}

// openUpstream connects to the destination through exit. retry reports
// that the exit itself is down (and is now marked so).
func (m *Manager) openUpstream(ctx context.Context, st *state, service, exit, host string, addrs []netip.Addr, port int) (c net.Conn, retry bool, err error) {
	ex, ok := st.exit(exit)
	if !ok {
		return nil, false, fmt.Errorf("unknown exit %q", exit)
	}
	if ex.Egress != nil {
		e, ok := st.egress[exit]
		if !ok {
			return nil, false, fmt.Errorf("exit %q not configured", exit)
		}
		c, _, err := dialOrdered(ctx, e, m.edges, host, addrs, port)
		return c, errors.Is(err, errExitDown), err
	}
	if m.remote == nil {
		return nil, true, fmt.Errorf("%w: no tunnel to exit node %s", errExitDown, ex.Node)
	}
	c, err = m.remote.Connect(ctx, ex.Node, ConnectRequest{Exit: exit, Service: service, Host: host, Port: port, Addrs: addrs})
	if err != nil {
		var refused *relayRefused
		if !errors.As(err, &refused) {
			m.setRemoteDown(exit, true, err.Error())
			return nil, true, err
		}
		if refused.exitDown {
			m.setRemoteDown(exit, true, refused.msg)
			return nil, true, err
		}
		return nil, false, err
	}
	return c, false, nil
}

// dialOrdered connects from a local egress, trying CDN edges best first.
func dialOrdered(ctx context.Context, e *egress, edges *edgeChecker, host string, addrs []netip.Addr, port int) (net.Conn, netip.Addr, error) {
	if up, msg := e.up(); !up {
		return nil, netip.Addr{}, fmt.Errorf("%w: %s", errExitDown, msg)
	}
	return e.dial(ctx, edges.order(ctx, e, host, addrs), port)
}

type counterAdder interface{ Add(int64) int64 }

// pipe copies both ways until both directions finish. Without a counter it
// uses io.Copy, which splices between two kernel TCP sockets.
func pipe(a, b net.Conn, count counterAdder) {
	done := make(chan struct{}, 2)
	cp := func(dst, src net.Conn) {
		if count == nil {
			io.Copy(dst, src)
		} else {
			buf := make([]byte, relayBuf)
			for {
				n, err := src.Read(buf)
				if n > 0 {
					if _, werr := dst.Write(buf[:n]); werr != nil {
						break
					}
					count.Add(int64(n))
				}
				if err != nil {
					break
				}
			}
		}
		if tc, ok := dst.(interface{ CloseWrite() error }); ok {
			tc.CloseWrite()
		} else {
			dst.Close()
		}
		done <- struct{}{}
	}
	go cp(a, b)
	go cp(b, a)
	<-done
	<-done
}

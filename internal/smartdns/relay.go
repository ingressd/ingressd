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
	ln, err := net.Listen("tcp4", addr)
	if err != nil {
		return nil, err
	}
	go acceptLoop(ln, func(c net.Conn) { m.handleRelay(c, isTLS) })
	return ln, nil
}

func (m *Manager) listenExitRelay(addr string) (io.Closer, error) {
	ln, err := net.Listen("tcp4", addr)
	if err != nil {
		return nil, err
	}
	go acceptLoop(ln, m.handleExitRelay)
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

// handleRelay serves one home connection to the relay (:443 or :80 on a
// listen address): only hostnames of enabled services, only from home
// sources, only through the service's exit.
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
	a, rcode, _, err := m.lookup(ctx, st, r, host)
	if err == nil && (rcode != 0 || len(a.Addrs) == 0) {
		err = fmt.Errorf("no A records for %s at exit %s", host, r.Exit)
	}
	var up net.Conn
	if err == nil {
		up, err = m.openUpstream(ctx, st, r, host, a.Addrs, port)
	}
	cancel()
	if err != nil {
		m.errors.Add(1)
		m.log.Warn("relay failed", "host", host, "service", r.Service, "exit", r.Exit, "err", err)
		return
	}
	defer up.Close()
	ctr := m.counter(r.Service)
	ctr.conns.Add(1)
	if _, err := up.Write(head); err != nil {
		return
	}
	ctr.bytes.Add(int64(len(head)))
	pipe(c, up, &ctr.bytes)
}

// openUpstream connects to the destination through the route's exit.
func (m *Manager) openUpstream(ctx context.Context, st *state, r route, host string, addrs []netip.Addr, port int) (net.Conn, error) {
	ex, ok := st.exit(r.Exit)
	if !ok {
		return nil, fmt.Errorf("unknown exit %q", r.Exit)
	}
	if ex.IsSelf() {
		e, ok := st.egress[r.Exit]
		if !ok {
			return nil, fmt.Errorf("exit %q not configured", r.Exit)
		}
		c, _, err := m.dialOrdered(ctx, e, host, addrs, port)
		return c, err
	}
	c, err := m.remote.Connect(ctx, ex.Node, ConnectRequest{Exit: r.Exit, Service: r.Service, Host: host, Port: port, Addrs: addrs})
	if err != nil {
		var refused *relayRefused
		if !errors.As(err, &refused) {
			m.remote.MarkDown(ex.Node, err)
		}
		return nil, err
	}
	return c, nil
}

// dialOrdered connects from a self exit, trying edges best first.
func (m *Manager) dialOrdered(ctx context.Context, e *egress, host string, addrs []netip.Addr, port int) (net.Conn, netip.Addr, error) {
	if up, msg := e.up(); !up {
		return nil, netip.Addr{}, fmt.Errorf("%w: %s", errExitDown, msg)
	}
	return e.dial(ctx, m.edges.order(ctx, e, host, addrs), port)
}

// handleExitRelay serves one relayed stream from a mesh peer on an exit node.
func (m *Manager) handleExitRelay(c net.Conn) {
	defer c.Close()
	peer, ok := m.mesh.PeerByAddr(netAddr(c.RemoteAddr()))
	if !ok {
		return
	}
	c.SetDeadline(time.Now().Add(peekTimeout))
	req, err := ReadConnectRequest(c)
	if err != nil {
		return
	}
	refuse := func(msg string) {
		WriteConnectResponse(c, ConnectResponse{Error: msg})
		m.log.Warn("exit relay refused", "peer", peer, "exit", req.Exit, "host", req.Host, "reason", msg)
	}
	e, ok := m.state().egress[req.Exit]
	if !ok {
		refuse(fmt.Sprintf("exit %q is not hosted on this node", req.Exit))
		return
	}
	if err := checkConnect(req); err != nil {
		refuse(err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(m.ctx(), dialTimeout*2+probeTimeout)
	up, addr, err := m.dialOrdered(ctx, e, normalize(req.Host), req.Addrs, req.Port)
	cancel()
	if err != nil {
		refuse(err.Error())
		return
	}
	defer up.Close()
	if err := WriteConnectResponse(c, ConnectResponse{OK: true, Addr: addr.String()}); err != nil {
		return
	}
	c.SetDeadline(time.Time{})
	pipe(c, up, nil)
}

type counterAdder interface{ Add(int64) int64 }

// pipe copies both ways until both directions finish, counting bytes.
func pipe(a, b net.Conn, count counterAdder) {
	done := make(chan struct{}, 2)
	cp := func(dst, src net.Conn) {
		buf := make([]byte, relayBuf)
		for {
			n, err := src.Read(buf)
			if n > 0 {
				if _, werr := dst.Write(buf[:n]); werr != nil {
					break
				}
				if count != nil {
					count.Add(int64(n))
				}
			}
			if err != nil {
				break
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

// SPDX-License-Identifier: Apache-2.0

package client

import (
	"context"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"sync/atomic"

	"github.com/coder/websocket"
)

// wsRelay carries WireGuard over a WebSocket. It listens on a loopback UDP
// port that becomes the WireGuard peer endpoint, so the same relay works for
// kernel WireGuard and wireguard-go: datagrams from the local WireGuard
// socket go out as binary WebSocket messages and messages coming back are
// returned to that socket.
type wsRelay struct {
	local *net.UDPConn
	ws    *websocket.Conn
	peer  atomic.Pointer[netip.AddrPort]
	done  chan struct{}
	once  sync.Once
	err   error
}

// dialRelay connects the WebSocket and starts relaying.
func dialRelay(ctx context.Context, url string, hc *http.Client, header http.Header) (*wsRelay, error) {
	ws, _, err := websocket.Dial(ctx, url, &websocket.DialOptions{HTTPClient: hc, HTTPHeader: header})
	if err != nil {
		return nil, err
	}
	ws.SetReadLimit(1 << 16)
	local, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		ws.CloseNow()
		return nil, err
	}
	r := &wsRelay{local: local, ws: ws, done: make(chan struct{})}
	go r.up()
	go r.down()
	return r, nil
}

// Endpoint is the loopback address WireGuard should send to.
func (r *wsRelay) Endpoint() netip.AddrPort {
	return r.local.LocalAddr().(*net.UDPAddr).AddrPort()
}

// Done is closed when the relay fails or is closed.
func (r *wsRelay) Done() <-chan struct{} { return r.done }

func (r *wsRelay) fail(err error) {
	r.once.Do(func() {
		r.err = err
		close(r.done)
		r.ws.CloseNow()
		r.local.Close()
	})
}

func (r *wsRelay) Close() { r.fail(net.ErrClosed) }

func (r *wsRelay) up() {
	buf := make([]byte, 1<<16)
	for {
		n, from, err := r.local.ReadFromUDPAddrPort(buf)
		if err != nil {
			r.fail(err)
			return
		}
		r.peer.Store(&from)
		if err := r.ws.Write(context.Background(), websocket.MessageBinary, buf[:n]); err != nil {
			r.fail(err)
			return
		}
	}
}

func (r *wsRelay) down() {
	for {
		_, b, err := r.ws.Read(context.Background())
		if err != nil {
			r.fail(err)
			return
		}
		if p := r.peer.Load(); p != nil {
			_, _ = r.local.WriteToUDPAddrPort(b, *p)
		}
	}
}

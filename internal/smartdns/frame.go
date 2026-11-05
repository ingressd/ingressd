// SPDX-License-Identifier: Apache-2.0

package smartdns

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
)

// The mesh relay protocol. A home node opens a TCP connection to the exit
// node's mesh address on config.MeshRelayPort and sends one request frame;
// the exit answers with one response frame and, if OK, both sides then copy
// raw bytes (the client's TLS or HTTP stream, untouched) until EOF.
//
//	request:  "HER1" | uint16 length | JSON ConnectRequest
//	response:          uint16 length | JSON ConnectResponse
//
// The exit accepts connections only from mesh peers (WireGuard
// authenticates their source address) and only to public unicast addresses
// on ports 80 and 443.

var relayMagic = [4]byte{'H', 'E', 'R', '1'}

const maxFrame = 4096

// ConnectRequest asks an exit to open a stream.
type ConnectRequest struct {
	Exit    string       `json:"exit"`              // exit name, must be a self exit on the exit node
	Realm   string       `json:"realm,omitempty"`   // realm the home node relays for; must be the exit's
	Service string       `json:"service,omitempty"` // informational (logs)
	Host    string       `json:"host"`              // SNI / Host of the client's stream
	Port    int          `json:"port"`              // 443 or 80
	Addrs   []netip.Addr `json:"addrs"`             // exit-resolved upstream addresses, preferred first
}

// ConnectResponse is the exit's answer.
type ConnectResponse struct {
	OK    bool   `json:"ok"`
	Addr  string `json:"addr,omitempty"` // upstream address connected to
	Error string `json:"error,omitempty"`
	// ExitDown marks a refusal because the exit cannot egress, which the
	// home node may retry through the service's next exit; any other
	// refusal is final. Older exit nodes never set it.
	ExitDown bool `json:"exit_down,omitempty"`
}

func writeFrame(w io.Writer, magic bool, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if len(b) > maxFrame {
		return fmt.Errorf("relay frame too large (%d bytes)", len(b))
	}
	buf := make([]byte, 0, 6+len(b))
	if magic {
		buf = append(buf, relayMagic[:]...)
	}
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(b)))
	buf = append(buf, b...)
	_, err = w.Write(buf)
	return err
}

func readFrame(r io.Reader, magic bool, v any) error {
	if magic {
		var m [4]byte
		if _, err := io.ReadFull(r, m[:]); err != nil {
			return err
		}
		if m != relayMagic {
			return errors.New("not a relay request")
		}
	}
	var l [2]byte
	if _, err := io.ReadFull(r, l[:]); err != nil {
		return err
	}
	n := int(binary.BigEndian.Uint16(l[:]))
	if n == 0 || n > maxFrame {
		return fmt.Errorf("bad relay frame length %d", n)
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

// WriteConnectRequest and the functions below implement the framing.
func WriteConnectRequest(w io.Writer, req ConnectRequest) error { return writeFrame(w, true, req) }

func ReadConnectRequest(r io.Reader) (ConnectRequest, error) {
	var req ConnectRequest
	err := readFrame(r, true, &req)
	return req, err
}

func WriteConnectResponse(w io.Writer, resp ConnectResponse) error {
	return writeFrame(w, false, resp)
}

func ReadConnectResponse(r io.Reader) (ConnectResponse, error) {
	var resp ConnectResponse
	err := readFrame(r, false, &resp)
	return resp, err
}

// checkConnect validates a request at the exit: allowed port, a hostname,
// and only public unicast destinations (the relay must never reach the exit
// node's own LAN, loopback or mesh).
func checkConnect(req ConnectRequest) error {
	if req.Port != 443 && req.Port != 80 {
		return fmt.Errorf("port %d not allowed", req.Port)
	}
	if req.Host == "" || len(req.Host) > 253 {
		return errors.New("missing host")
	}
	if len(req.Addrs) == 0 || len(req.Addrs) > 32 {
		return errors.New("need 1-32 upstream addresses")
	}
	for _, a := range req.Addrs {
		if !publicUnicast(a) {
			return fmt.Errorf("upstream %s is not a public address", a)
		}
	}
	return nil
}

var nonPublic = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("240.0.0.0/4"),
}

func publicUnicast(a netip.Addr) bool {
	a = a.Unmap()
	if !a.IsValid() || !a.Is4() || a.IsLoopback() || a.IsPrivate() || a.IsLinkLocalUnicast() ||
		a.IsMulticast() || a.IsUnspecified() || a == netip.AddrFrom4([4]byte{255, 255, 255, 255}) {
		return false
	}
	for _, p := range nonPublic {
		if p.Contains(a) {
			return false
		}
	}
	return true
}

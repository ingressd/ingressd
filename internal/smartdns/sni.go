// SPDX-License-Identifier: Apache-2.0

package smartdns

import (
	"bytes"
	"encoding/binary"
	"errors"
	"strings"
)

// errNeedMore means the parser needs more bytes from the client.
var errNeedMore = errors.New("need more data")

const maxHello = 16384 + 5

// sniFromHello returns the server name from a TLS ClientHello record: ""
// when the hello has no SNI, errNeedMore when incomplete, another error
// when it is not a ClientHello.
func sniFromHello(data []byte) (string, error) {
	if len(data) < 5 {
		return "", errNeedMore
	}
	if data[0] != 0x16 {
		return "", errors.New("not a TLS handshake")
	}
	recLen := int(binary.BigEndian.Uint16(data[3:5]))
	if len(data) < 5+recLen {
		return "", errNeedMore
	}
	h := data[5 : 5+recLen]
	if len(h) < 4 || h[0] != 0x01 {
		return "", errors.New("not a ClientHello")
	}
	bad := errors.New("malformed ClientHello")
	off := 4 + 2 + 32 // handshake header, client version, random
	if off >= len(h) {
		return "", bad
	}
	off += 1 + int(h[off]) // session id
	if off+2 > len(h) {
		return "", bad
	}
	off += 2 + int(binary.BigEndian.Uint16(h[off:])) // cipher suites
	if off >= len(h) {
		return "", bad
	}
	off += 1 + int(h[off]) // compression methods
	if off+2 > len(h) {
		return "", nil // no extensions
	}
	end := min(off+2+int(binary.BigEndian.Uint16(h[off:])), len(h))
	off += 2
	for off+4 <= end {
		etype := binary.BigEndian.Uint16(h[off:])
		elen := int(binary.BigEndian.Uint16(h[off+2:]))
		off += 4
		if off+elen > end {
			return "", bad
		}
		if etype == 0 { // server_name
			p, ext := off+2, off+elen
			for p+3 <= ext {
				ntype, nlen := h[p], int(binary.BigEndian.Uint16(h[p+1:]))
				if p+3+nlen > ext {
					return "", bad
				}
				if ntype == 0 {
					return normalize(string(h[p+3 : p+3+nlen])), nil
				}
				p += 3 + nlen
			}
			return "", nil
		}
		off += elen
	}
	return "", nil
}

// hostFromHTTP returns the Host header of an HTTP/1.x request head ("" if
// absent), errNeedMore until the head is complete.
func hostFromHTTP(data []byte) (string, error) {
	head, _, ok := bytes.Cut(data, []byte("\r\n\r\n"))
	if !ok {
		if len(data) > 16384 {
			return "", errors.New("request head too large")
		}
		return "", errNeedMore
	}
	lines := bytes.Split(head, []byte("\r\n"))
	for _, line := range lines[1:] {
		k, v, ok := bytes.Cut(line, []byte(":"))
		if ok && strings.EqualFold(string(bytes.TrimSpace(k)), "host") {
			host := strings.TrimSpace(string(v))
			if i := strings.LastIndexByte(host, ':'); i >= 0 && !strings.Contains(host[i:], "]") {
				host = host[:i]
			}
			return normalize(host), nil
		}
	}
	return "", nil
}

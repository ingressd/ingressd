// SPDX-License-Identifier: Apache-2.0

package client

// icmpEcho builds an ICMPv4 echo request with a zero-filled payload.
func icmpEcho(id, seq uint16, payload int) []byte {
	if payload < 0 {
		payload = 0
	}
	b := make([]byte, 8+payload)
	b[0] = 8 // echo request
	b[4], b[5] = byte(id>>8), byte(id)
	b[6], b[7] = byte(seq>>8), byte(seq)
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	cs := ^uint16(sum)
	b[2], b[3] = byte(cs>>8), byte(cs)
	return b
}

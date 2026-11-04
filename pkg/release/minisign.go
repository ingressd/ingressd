// SPDX-License-Identifier: Apache-2.0

package release

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/blake2b"
)

// Minisign (https://jedisct1.github.io/minisign/) signature verification:
// Ed25519 over the file ("Ed") or over its BLAKE2b-512 hash ("ED", the
// default since minisign 0.11), plus a global signature binding the
// trusted comment.

// PublicKey is a minisign public key.
type PublicKey struct {
	ID  [8]byte
	Key ed25519.PublicKey
}

// ParsePublicKey parses a minisign public key: the base64 line alone, or
// the whole .pub file.
func ParsePublicKey(s string) (PublicKey, error) {
	var line string
	for _, l := range strings.Split(strings.TrimSpace(s), "\n") {
		l = strings.TrimSpace(l)
		if l != "" && !strings.HasPrefix(l, "untrusted comment:") {
			line = l
		}
	}
	b, err := base64.StdEncoding.DecodeString(line)
	if err != nil || len(b) != 2+8+ed25519.PublicKeySize || string(b[:2]) != "Ed" {
		return PublicKey{}, errors.New("invalid minisign public key")
	}
	var pk PublicKey
	copy(pk.ID[:], b[2:10])
	pk.Key = ed25519.PublicKey(b[10:])
	return pk, nil
}

// Verify checks a minisign signature file over message. It returns the
// trusted comment.
func (pk PublicKey) Verify(message, sigFile []byte) (string, error) {
	var lines []string
	for _, l := range strings.Split(strings.ReplaceAll(string(sigFile), "\r\n", "\n"), "\n") {
		if strings.TrimSpace(l) != "" {
			lines = append(lines, l)
		}
	}
	if len(lines) < 4 || !strings.HasPrefix(lines[0], "untrusted comment:") || !strings.HasPrefix(lines[2], "trusted comment: ") {
		return "", errors.New("malformed minisign signature")
	}
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(lines[1]))
	if err != nil || len(sig) != 2+8+ed25519.SignatureSize {
		return "", errors.New("malformed minisign signature")
	}
	alg, keyID, s := string(sig[:2]), sig[2:10], sig[10:]
	if !bytes.Equal(keyID, pk.ID[:]) {
		return "", fmt.Errorf("signed with key %X, expected %X", keyID, pk.ID)
	}
	msg := message
	switch alg {
	case "Ed":
	case "ED":
		h := blake2b.Sum512(message)
		msg = h[:]
	default:
		return "", fmt.Errorf("unsupported signature algorithm %q", alg)
	}
	if !ed25519.Verify(pk.Key, msg, s) {
		return "", errors.New("signature verification failed")
	}
	trusted := strings.TrimPrefix(lines[2], "trusted comment: ")
	global, err := base64.StdEncoding.DecodeString(strings.TrimSpace(lines[3]))
	if err != nil || len(global) != ed25519.SignatureSize {
		return "", errors.New("malformed minisign global signature")
	}
	if !ed25519.Verify(pk.Key, append(append([]byte{}, s...), trusted...), global) {
		return "", errors.New("trusted comment signature verification failed")
	}
	return trusted, nil
}

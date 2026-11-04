// SPDX-License-Identifier: Apache-2.0

package release

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strings"

	"golang.org/x/crypto/blake2b"
)

// Minisign signing, for test keys and tools. Real releases are signed in
// CI with the minisign CLI; keys made here are interchangeable with
// `minisign -G -W` (unencrypted) keys.

// SecretKey is an unencrypted minisign secret key.
type SecretKey struct {
	ID  [8]byte
	Key ed25519.PrivateKey
}

// GenerateKey creates a minisign key pair and returns the public and secret
// key files (the formats minisign writes to minisign.pub and an
// unencrypted minisign.key).
func GenerateKey() (pubFile, secFile string, err error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	var id [8]byte
	if _, err := rand.Read(id[:]); err != nil {
		return "", "", err
	}
	pubFile = "untrusted comment: minisign public key " + keyIDString(id) + "\n" +
		base64.StdEncoding.EncodeToString(append(append([]byte("Ed"), id[:]...), pub...)) + "\n"
	sk := SecretKey{ID: id, Key: priv}
	return pubFile, sk.Encode(), nil
}

func keyIDString(id [8]byte) string {
	const hexd = "0123456789ABCDEF"
	var b strings.Builder
	for i := len(id) - 1; i >= 0; i-- { // minisign prints the id little-endian
		b.WriteByte(hexd[id[i]>>4])
		b.WriteByte(hexd[id[i]&15])
	}
	return b.String()
}

// Encode returns the unencrypted minisign secret key file.
func (k SecretKey) Encode() string {
	var b bytes.Buffer
	b.WriteString("Ed")
	b.Write([]byte{0, 0}) // kdf: none
	b.WriteString("B2")
	b.Write(make([]byte, 32+8+8)) // salt, opslimit, memlimit (unused)
	b.Write(k.ID[:])
	b.Write(k.Key)
	sum := k.checksum()
	b.Write(sum[:])
	return "untrusted comment: minisign encrypted secret key\n" + base64.StdEncoding.EncodeToString(b.Bytes()) + "\n"
}

func (k SecretKey) checksum() [32]byte {
	h, _ := blake2b.New256(nil)
	h.Write([]byte("Ed"))
	h.Write(k.ID[:])
	h.Write(k.Key)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// ParseSecretKey parses an unencrypted minisign secret key file.
func ParseSecretKey(s string) (SecretKey, error) {
	var line string
	for _, l := range strings.Split(strings.TrimSpace(s), "\n") {
		l = strings.TrimSpace(l)
		if l != "" && !strings.HasPrefix(l, "untrusted comment:") {
			line = l
		}
	}
	b, err := base64.StdEncoding.DecodeString(line)
	if err != nil || len(b) != 2+2+2+32+8+8+8+64+32 || string(b[:2]) != "Ed" || string(b[4:6]) != "B2" {
		return SecretKey{}, errors.New("invalid minisign secret key")
	}
	if b[2] != 0 || b[3] != 0 {
		return SecretKey{}, errors.New("encrypted minisign secret keys are not supported (create the key with minisign -G -W)")
	}
	off := 2 + 2 + 2 + 32 + 8 + 8
	var k SecretKey
	copy(k.ID[:], b[off:off+8])
	k.Key = ed25519.PrivateKey(append([]byte{}, b[off+8:off+8+64]...))
	if sum := k.checksum(); !bytes.Equal(sum[:], b[off+72:]) {
		return SecretKey{}, errors.New("minisign secret key checksum mismatch")
	}
	return k, nil
}

// PublicKey returns the key's public half in minisign format.
func (k SecretKey) PublicKey() string {
	pub := k.Key.Public().(ed25519.PublicKey)
	return base64.StdEncoding.EncodeToString(append(append([]byte("Ed"), k.ID[:]...), pub...))
}

// Sign returns a minisign signature file over message (prehashed "ED"
// signatures, the minisign default) with the given trusted comment.
func (k SecretKey) Sign(message []byte, trustedComment string) []byte {
	h := blake2b.Sum512(message)
	sig := ed25519.Sign(k.Key, h[:])
	global := ed25519.Sign(k.Key, append(append([]byte{}, sig...), trustedComment...))
	return []byte("untrusted comment: signature from minisign secret key\n" +
		base64.StdEncoding.EncodeToString(append(append([]byte("ED"), k.ID[:]...), sig...)) + "\n" +
		"trusted comment: " + trustedComment + "\n" +
		base64.StdEncoding.EncodeToString(global) + "\n")
}

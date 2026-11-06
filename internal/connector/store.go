// SPDX-License-Identifier: Apache-2.0

// Package connector is the edge side of ingressd-connector: one-time
// enrollment tokens, per-connector credentials, the long-poll control channel
// and the WireGuard-over-WebSocket bridge. State lives in
// <state-dir>/connector.json (mode 0600); config.yaml is never modified.
package connector

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/ingressd/ingressd/internal/connector/proto"
	"github.com/ingressd/ingressd/pkg/nodeproto"
)

// TokenTTL is how long an enrollment token stays valid.
const TokenTTL = 15 * time.Minute

// StateFile is the store's file name inside the state directory.
const StateFile = "connector.json"

// State is the content of connector.json.
type State struct {
	Tokens []Token `json:"tokens,omitempty"`
	// Connectors maps a tunnel name to its enrolled connector.
	Connectors map[string]*Connector `json:"connectors,omitempty"`
	// Updates maps a tunnel name to the panel's update notice for its
	// connector (update.go).
	Updates map[string]*proto.UpdateNotice `json:"updates,omitempty"`
}

// Token is a pending one-time enrollment token (only its hash is stored).
type Token struct {
	Hash    string    `json:"hash"`
	Tunnel  string    `json:"tunnel"`
	Expires time.Time `json:"expires"`
}

// Connector is an enrolled site connector.
type Connector struct {
	PublicKey      string        `json:"public_key"`
	CredentialHash string        `json:"credential_hash"`
	EnrolledAt     time.Time     `json:"enrolled_at"`
	Hostname       string        `json:"hostname,omitempty"`
	Health         *proto.Health `json:"health,omitempty"`
	Discovery      *Discovery    `json:"discovery,omitempty"` // discovery.go
	// SmartDNSUsage are relay usage deltas reported by the connector and not
	// yet taken into the node's usage (TakeSmartDNSUsage).
	SmartDNSUsage []nodeproto.ServiceUsage `json:"smartdns_usage,omitempty"`
}

// Store reads and updates connector.json. Updates hold an exclusive file
// lock so the CLI (enroll-token) and the control server can share it.
type Store struct{ Path string }

// NewStore returns the store in stateDir.
func NewStore(stateDir string) *Store { return &Store{Path: filepath.Join(stateDir, StateFile)} }

// Load returns the current state; a missing file is an empty state.
func (s *Store) Load() (*State, error) {
	st := &State{}
	b, err := os.ReadFile(s.Path)
	if errors.Is(err, os.ErrNotExist) {
		return st, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, st); err != nil {
		return nil, fmt.Errorf("%s: %w", s.Path, err)
	}
	return st, nil
}

// Update loads the state, applies fn and saves the result atomically.
func (s *Store) Update(fn func(*State) error) error {
	if err := os.MkdirAll(filepath.Dir(s.Path), 0o700); err != nil {
		return err
	}
	unlock, err := lockFile(s.Path + ".lock")
	if err != nil {
		return err
	}
	defer unlock()
	st, err := s.Load()
	if err != nil {
		return err
	}
	if st.Connectors == nil {
		st.Connectors = map[string]*Connector{}
	}
	if err := fn(st); err != nil {
		return err
	}
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.Path + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.Path)
}

// SitePublicKey returns the enrolled connector's public key for a tunnel, or
// "" when none is enrolled. It plugs into tunnel.Keys.SiteKey.
func (s *Store) SitePublicKey(tunnel string) string {
	st, err := s.Load()
	if err != nil {
		return ""
	}
	if c := st.Connectors[tunnel]; c != nil {
		return c.PublicKey
	}
	return ""
}

// CreateToken issues a one-time enrollment token for a tunnel.
func (s *Store) CreateToken(tunnel string, now time.Time) (string, error) {
	tok, err := randomSecret()
	if err != nil {
		return "", err
	}
	err = s.Update(func(st *State) error {
		st.Tokens = pruneTokens(st.Tokens, now)
		st.Tokens = append(st.Tokens, Token{Hash: hashSecret(tok), Tunnel: tunnel, Expires: now.Add(TokenTTL)})
		return nil
	})
	return tok, err
}

// ErrBadToken means the token is unknown, used or expired.
var ErrBadToken = errors.New("enrollment token is invalid, expired or already used")

// Enroll consumes a token and records the connector's public key. It returns
// the tunnel name and a new credential (shown once, stored hashed).
func (s *Store) Enroll(token, publicKey, hostname string, now time.Time) (tunnel, credential string, err error) {
	credential, err = randomSecret()
	if err != nil {
		return "", "", err
	}
	h := hashSecret(token)
	err = s.Update(func(st *State) error {
		st.Tokens = pruneTokens(st.Tokens, now)
		for i, t := range st.Tokens {
			if subtle.ConstantTimeCompare([]byte(t.Hash), []byte(h)) == 1 {
				tunnel = t.Tunnel
				st.Tokens = append(st.Tokens[:i], st.Tokens[i+1:]...)
				st.Connectors[tunnel] = &Connector{
					PublicKey:      publicKey,
					CredentialHash: hashSecret(credential),
					EnrolledAt:     now.UTC(),
					Hostname:       hostname,
				}
				return nil
			}
		}
		return ErrBadToken
	})
	return tunnel, credential, err
}

// Authenticate checks a connector credential for a tunnel.
func (s *Store) Authenticate(tunnel, credential string) bool {
	st, err := s.Load()
	if err != nil {
		return false
	}
	c := st.Connectors[tunnel]
	return c != nil && subtle.ConstantTimeCompare([]byte(c.CredentialHash), []byte(hashSecret(credential))) == 1
}

// Report records a connector's health report.
func (s *Store) Report(tunnel string, h proto.Health) error {
	return s.Update(func(st *State) error {
		c := st.Connectors[tunnel]
		if c == nil {
			// A connector that enrolled on another node of the site and is
			// accepted here by the tunnel's configured public_key.
			c = &Connector{}
			st.Connectors[tunnel] = c
		}
		if len(h.SmartDNSUsage) > 0 {
			c.SmartDNSUsage = mergeUsage(c.SmartDNSUsage, h.SmartDNSUsage)
			h.SmartDNSUsage = nil
		}
		if sd := h.SmartDNS; sd != nil && len(sd.Recent) > maxRecentLookups {
			sd.Recent = sd.Recent[:maxRecentLookups]
		}
		c.Health = &h
		return nil
	})
}

// maxRecentLookups bounds the lookups kept per connector.
const maxRecentLookups = 200

func mergeUsage(into, add []nodeproto.ServiceUsage) []nodeproto.ServiceUsage {
	for _, u := range add {
		if u.Service == "" || u.Bytes < 0 || u.Conns < 0 {
			continue
		}
		merged := false
		for i := range into {
			if into[i].Service == u.Service {
				into[i].Bytes += u.Bytes
				into[i].Conns += u.Conns
				merged = true
				break
			}
		}
		if !merged && len(into) < 256 {
			into = append(into, nodeproto.ServiceUsage{Service: u.Service, Bytes: u.Bytes, Conns: u.Conns})
		}
	}
	return into
}

// TakeSmartDNSUsage returns and clears every connector's pending relay
// usage, with Site set to the tunnel.
func (s *Store) TakeSmartDNSUsage() ([]nodeproto.ServiceUsage, error) {
	var out []nodeproto.ServiceUsage
	err := s.Update(func(st *State) error {
		for _, name := range slices.Sorted(maps.Keys(st.Connectors)) {
			c := st.Connectors[name]
			for _, u := range c.SmartDNSUsage {
				u.Site = name
				out = append(out, u)
			}
			c.SmartDNSUsage = nil
		}
		return nil
	})
	return out, err
}

// SmartDNSRecent returns a connector's latest reported lookups, newest first.
func (s *Store) SmartDNSRecent(tunnel string, limit int) ([]nodeproto.RecentLookup, error) {
	st, err := s.Load()
	if err != nil {
		return nil, err
	}
	c := st.Connectors[tunnel]
	if c == nil || c.Health == nil || c.Health.SmartDNS == nil {
		return []nodeproto.RecentLookup{}, nil
	}
	r := c.Health.SmartDNS.Recent
	if limit > 0 && len(r) > limit {
		r = r[:limit]
	}
	return r, nil
}

func pruneTokens(ts []Token, now time.Time) []Token {
	out := ts[:0]
	for _, t := range ts {
		if now.Before(t.Expires) {
			out = append(out, t)
		}
	}
	return out
}

func randomSecret() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	// Hex, not base64: a token must never start with "-" on a command line.
	return hex.EncodeToString(b), nil
}

func hashSecret(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

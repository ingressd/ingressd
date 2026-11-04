// SPDX-License-Identifier: Apache-2.0

// Package l4 manages the runtime side of L4 (TCP/UDP) services: allowlist
// entries added by operators or by players through login-to-play, their
// persistence, and keeping the nftables sets rendered by internal/render in
// sync with them.
package l4

import (
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"time"
)

// Entry allows one source IP to connect to one service until Expires.
type Entry struct {
	Service string    `json:"service"`
	IP      string    `json:"ip"`
	Email   string    `json:"email,omitempty"` // who signed in (login-to-play) or who added it
	Added   time.Time `json:"added"`
	Expires time.Time `json:"expires,omitzero"` // zero: never
}

// Expired reports whether the entry has run out at now.
func (e Entry) Expired(now time.Time) bool { return !e.Expires.IsZero() && !now.Before(e.Expires) }

// Store persists entries in a JSON file (<state-dir>/l4-allowlist.json).
// The control plane and the CLI both write it, so updates take a file lock.
type Store struct {
	Path string
	// Now is the clock (tests); nil means time.Now.
	Now func() time.Time
}

// FileName is the store's file name inside the state directory.
const FileName = "l4-allowlist.json"

func (s *Store) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// List returns the unexpired entries, sorted by service then IP.
func (s *Store) List() ([]Entry, error) {
	all, err := s.read()
	if err != nil {
		return nil, err
	}
	return live(all, s.now()), nil
}

// Put adds or replaces the entry for (e.Service, e.IP).
func (s *Store) Put(e Entry) error {
	return s.update(func(es []Entry) []Entry {
		es = slices.DeleteFunc(es, func(x Entry) bool { return x.Service == e.Service && x.IP == e.IP })
		return append(es, e)
	})
}

// Delete removes the entry for (service, ip) and reports whether it existed.
func (s *Store) Delete(service, ip string) (bool, error) {
	found := false
	err := s.update(func(es []Entry) []Entry {
		return slices.DeleteFunc(es, func(x Entry) bool {
			if x.Service == service && x.IP == ip {
				found = true
				return true
			}
			return false
		})
	})
	return found, err
}

// update runs fn on the current unexpired entries under the file lock and
// writes the result atomically.
func (s *Store) update(fn func([]Entry) []Entry) error {
	if err := os.MkdirAll(filepath.Dir(s.Path), 0o700); err != nil {
		return err
	}
	unlock, err := lockFile(s.Path + ".lock")
	if err != nil {
		return fmt.Errorf("lock %s: %w", s.Path, err)
	}
	defer unlock()
	all, err := s.read()
	if err != nil {
		return err
	}
	es := live(fn(live(all, s.now())), s.now())
	b, err := json.MarshalIndent(es, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.Path + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.Path)
}

func (s *Store) read() ([]Entry, error) {
	b, err := os.ReadFile(s.Path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var es []Entry
	if err := json.Unmarshal(b, &es); err != nil {
		return nil, fmt.Errorf("decode %s: %w", s.Path, err)
	}
	return es, nil
}

func live(es []Entry, now time.Time) []Entry {
	out := slices.DeleteFunc(slices.Clone(es), func(e Entry) bool { return e.Expired(now) })
	slices.SortFunc(out, func(a, b Entry) int {
		return cmp.Or(cmp.Compare(a.Service, b.Service), cmp.Compare(a.IP, b.IP))
	})
	if out == nil {
		out = []Entry{}
	}
	return out
}

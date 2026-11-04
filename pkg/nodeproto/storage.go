// SPDX-License-Identifier: Apache-2.0

package nodeproto

import (
	"errors"
	"path"
	"slices"
	"strings"
	"time"
)

// Shared certificate storage (multi-PoP, docs/rev1/CERT-STORAGE.md).
//
// Caddy on a managed node keeps its certmagic storage in the panel, shared
// by every node of the org: the edge's storage module (caddy.storage.ingressd)
// talks to `ingressd serve` over a unix socket, and serve relays each
// operation to the panel as a storage_request; the panel answers with a
// storage_response carrying the same envelope id.
const (
	TypeStorageRequest  = "storage_request"  // node → panel
	TypeStorageResponse = "storage_response" // panel → node, ID echoes the request
)

// Storage operations (StorageRequest.Op). They mirror certmagic.Storage.
const (
	StorageLoad   = "load"
	StorageStore  = "store"
	StorageDelete = "delete"
	StorageExists = "exists"
	StorageList   = "list"
	StorageStat   = "stat"
	// StorageLock tries once to take (or renew, for the same owner) the lock
	// Name for StorageLockTTL; it never blocks. Response.Acquired reports
	// the outcome. Callers poll to wait and renew while they hold it.
	StorageLock = "lock"
	// StorageUnlock releases Name if Owner holds it.
	StorageUnlock = "unlock"
)

// Storage limits enforced by the panel (and the fake panel).
const (
	// StorageLockTTL is how long a lock lives without renewal.
	StorageLockTTL = 2 * time.Minute
	// StorageMaxValue is the largest value accepted by store (bytes).
	StorageMaxValue = 1 << 20
	// StorageMaxKey is the longest key accepted (bytes).
	StorageMaxKey = 1024
)

// StorageRequest is one certmagic storage operation.
type StorageRequest struct {
	Op        string `json:"op"`
	Key       string `json:"key,omitempty"`
	Value     []byte `json:"value,omitempty"` // store
	Recursive bool   `json:"recursive,omitempty"`
	// Name and Owner identify a lock (lock, unlock). Owner is a random token
	// per acquisition chosen by the node; the panel scopes it to the node.
	Name  string `json:"name,omitempty"`
	Owner string `json:"owner,omitempty"`
}

// StorageResponse answers a StorageRequest.
type StorageResponse struct {
	// NotExist is set when the key does not exist (load, stat, list); the
	// node maps it to fs.ErrNotExist.
	NotExist bool `json:"not_exist,omitempty"`
	// Error is any other failure (quota, invalid key, panel error).
	Error    string          `json:"error,omitempty"`
	Value    []byte          `json:"value,omitempty"`    // load
	Exists   bool            `json:"exists,omitempty"`   // exists
	Keys     []string        `json:"keys,omitempty"`     // list
	Info     *StorageKeyInfo `json:"info,omitempty"`     // stat
	Acquired bool            `json:"acquired,omitempty"` // lock
}

// StorageKeyInfo is certmagic.KeyInfo.
type StorageKeyInfo struct {
	Key        string    `json:"key"`
	Modified   time.Time `json:"modified"`
	Size       int64     `json:"size"`
	IsTerminal bool      `json:"is_terminal"`
}

// CleanStorageKey normalises a key or list prefix the way certmagic's file
// storage does (path cleaning, no leading or trailing slash). The root is "".
func CleanStorageKey(k string) string {
	k = strings.Trim(path.Clean("/"+k), "/")
	return k
}

// ValidateStorageKey rejects keys the panel will not store.
func ValidateStorageKey(k string) error {
	switch {
	case k == "":
		return errors.New("empty key")
	case len(k) > StorageMaxKey:
		return errors.New("key too long")
	case strings.ContainsAny(k, "\x00\\"):
		return errors.New("key contains an invalid character")
	case k != CleanStorageKey(k):
		return errors.New("key is not a clean path")
	}
	return nil
}

// StorageListKeys implements certmagic file-storage List semantics over a set
// of stored (terminal) keys: everything strictly below prefix, as full keys.
// Non-recursive lists the direct children (files and "directories");
// recursive lists every descendant, intermediate directories included, as
// filepath.Walk does. ok is false when prefix neither exists as a key nor
// has anything below it (certmagic expects fs.ErrNotExist then).
func StorageListKeys(keys []string, prefix string, recursive bool) (out []string, ok bool) {
	prefix = CleanStorageKey(prefix)
	under := ""
	if prefix != "" {
		under = prefix + "/"
	}
	ok = prefix == ""
	seen := map[string]bool{}
	for _, k := range keys {
		if k == prefix {
			ok = true
			continue
		}
		if !strings.HasPrefix(k, under) {
			continue
		}
		ok = true
		rest := strings.Split(k[len(under):], "/")
		if !recursive {
			seen[under+rest[0]] = true
			continue
		}
		for i := range rest {
			seen[under+strings.Join(rest[:i+1], "/")] = true
		}
	}
	out = make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	slices.Sort(out)
	return out, ok
}

// StorageHasChildren reports whether any key lies below dir (dir is then a
// "directory" for stat and exists).
func StorageHasChildren(keys []string, dir string) bool {
	dir = CleanStorageKey(dir)
	if dir == "" {
		return len(keys) > 0
	}
	for _, k := range keys {
		if strings.HasPrefix(k, dir+"/") {
			return true
		}
	}
	return false
}

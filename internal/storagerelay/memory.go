// SPDX-License-Identifier: Apache-2.0

package storagerelay

import (
	"context"
	"maps"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/ingressd/ingressd/pkg/nodeproto"
)

// Memory is an in-memory implementation of the panel side of shared
// storage, with the panel's semantics (list/stat over keys, lock expiry,
// owners scoped per node). The fake panel uses it, and tests use it as a
// relay backend. Safe for concurrent use.
type Memory struct {
	// Now is the clock (tests); default time.Now.
	Now func() time.Time

	mu    sync.Mutex
	vals  map[string]memValue
	locks map[string]memLock
}

type memValue struct {
	v   []byte
	mod time.Time
}

type memLock struct {
	owner   string
	expires time.Time
}

// NewMemory returns an empty store.
func NewMemory() *Memory {
	return &Memory{vals: map[string]memValue{}, locks: map[string]memLock{}}
}

func (m *Memory) now() time.Time {
	if m.Now != nil {
		return m.Now()
	}
	return time.Now()
}

// Keys returns all stored keys, sorted (tests).
func (m *Memory) Keys() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return slices.Sorted(maps.Keys(m.vals))
}

// Handle answers one request from the node identified by scope.
func (m *Memory) Handle(scope string, req nodeproto.StorageRequest) nodeproto.StorageResponse {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := nodeproto.CleanStorageKey(req.Key)
	switch req.Op {
	case nodeproto.StorageLoad:
		v, ok := m.vals[key]
		if !ok {
			return nodeproto.StorageResponse{NotExist: true}
		}
		return nodeproto.StorageResponse{Value: slices.Clone(v.v)}
	case nodeproto.StorageStore:
		if err := nodeproto.ValidateStorageKey(req.Key); err != nil {
			return nodeproto.StorageResponse{Error: err.Error()}
		}
		if len(req.Value) > nodeproto.StorageMaxValue {
			return nodeproto.StorageResponse{Error: "value too large"}
		}
		m.vals[key] = memValue{v: slices.Clone(req.Value), mod: m.now()}
		return nodeproto.StorageResponse{}
	case nodeproto.StorageDelete:
		if key == "" {
			return nodeproto.StorageResponse{Error: "refusing to delete the storage root"}
		}
		for k := range m.vals {
			if k == key || strings.HasPrefix(k, key+"/") {
				delete(m.vals, k)
			}
		}
		return nodeproto.StorageResponse{}
	case nodeproto.StorageExists:
		_, ok := m.vals[key]
		return nodeproto.StorageResponse{Exists: ok || nodeproto.StorageHasChildren(m.keys(), key)}
	case nodeproto.StorageList:
		keys, ok := nodeproto.StorageListKeys(m.keys(), key, req.Recursive)
		if !ok {
			return nodeproto.StorageResponse{NotExist: true}
		}
		return nodeproto.StorageResponse{Keys: keys}
	case nodeproto.StorageStat:
		if v, ok := m.vals[key]; ok {
			return nodeproto.StorageResponse{Info: &nodeproto.StorageKeyInfo{Key: key, Modified: v.mod, Size: int64(len(v.v)), IsTerminal: true}}
		}
		if nodeproto.StorageHasChildren(m.keys(), key) {
			return nodeproto.StorageResponse{Info: &nodeproto.StorageKeyInfo{Key: key}}
		}
		return nodeproto.StorageResponse{NotExist: true}
	case nodeproto.StorageLock:
		if req.Name == "" || req.Owner == "" {
			return nodeproto.StorageResponse{Error: "lock needs a name and an owner"}
		}
		owner := scope + "/" + req.Owner
		now := m.now()
		if l, held := m.locks[req.Name]; held && l.owner != owner && now.Before(l.expires) {
			return nodeproto.StorageResponse{}
		}
		m.locks[req.Name] = memLock{owner: owner, expires: now.Add(nodeproto.StorageLockTTL)}
		return nodeproto.StorageResponse{Acquired: true}
	case nodeproto.StorageUnlock:
		if l, held := m.locks[req.Name]; held && l.owner == scope+"/"+req.Owner {
			delete(m.locks, req.Name)
		}
		return nodeproto.StorageResponse{}
	}
	return nodeproto.StorageResponse{Error: "unknown storage operation " + req.Op}
}

func (m *Memory) keys() []string { return slices.Collect(maps.Keys(m.vals)) }

// Backend returns a relay Backend that talks to m as the node scope.
func (m *Memory) Backend(scope string) Backend {
	return BackendFunc(func(_ context.Context, req nodeproto.StorageRequest) (nodeproto.StorageResponse, error) {
		return m.Handle(scope, req), nil
	})
}

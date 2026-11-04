// SPDX-License-Identifier: Apache-2.0

package nodeagent

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"

	"github.com/ingressd/ingressd/pkg/nodeproto"
)

// Shared certificate storage: node → panel requests (storage_request) whose
// replies (storage_response) carry the same envelope id. The storage relay
// (internal/storagerelay) uses the Agent as its Backend.

// pendingCalls correlates node-initiated requests with panel replies. The
// zero value is ready to use.
type pendingCalls struct {
	mu sync.Mutex
	m  map[string]chan nodeproto.Envelope
}

func (p *pendingCalls) add(id string) chan nodeproto.Envelope {
	ch := make(chan nodeproto.Envelope, 1)
	p.mu.Lock()
	if p.m == nil {
		p.m = map[string]chan nodeproto.Envelope{}
	}
	p.m[id] = ch
	p.mu.Unlock()
	return ch
}

func (p *pendingCalls) remove(id string) {
	p.mu.Lock()
	delete(p.m, id)
	p.mu.Unlock()
}

// resolve delivers a reply; it reports whether anyone was waiting.
func (p *pendingCalls) resolve(env nodeproto.Envelope) bool {
	p.mu.Lock()
	ch := p.m[env.ID]
	delete(p.m, env.ID)
	p.mu.Unlock()
	if ch == nil {
		return false
	}
	ch <- env
	return true
}

// ErrPanelOffline is returned by Storage while the agent is not connected.
var ErrPanelOffline = errors.New("not connected to the panel")

// Storage forwards one storage operation to the panel and waits for its
// answer (until ctx ends or the connection drops). It implements
// storagerelay.Backend.
func (a *Agent) Storage(ctx context.Context, req nodeproto.StorageRequest) (nodeproto.StorageResponse, error) {
	a.mu.Lock()
	s := a.sess
	a.mu.Unlock()
	if s == nil {
		return nodeproto.StorageResponse{}, ErrPanelOffline
	}
	var b [9]byte
	_, _ = rand.Read(b[:])
	id := "sto_" + hex.EncodeToString(b[:])
	ch := a.storageCalls.add(id)
	defer a.storageCalls.remove(id)
	if err := a.sendOn(s, nodeproto.TypeStorageRequest, id, req); err != nil {
		return nodeproto.StorageResponse{}, err
	}
	select {
	case env := <-ch:
		var res nodeproto.StorageResponse
		if err := env.Decode(&res); err != nil {
			return res, fmt.Errorf("bad storage response: %w", err)
		}
		return res, nil
	case <-s.ctx.Done():
		return nodeproto.StorageResponse{}, errors.New("panel connection closed")
	case <-ctx.Done():
		return nodeproto.StorageResponse{}, ctx.Err()
	}
}

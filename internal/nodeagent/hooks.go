// SPDX-License-Identifier: Apache-2.0

package nodeagent

import (
	"sync"

	"github.com/ingressd/ingressd/pkg/nodeproto"
)

// Smart DNS hooks: the node exit and the node mesh run in serve
// (cmd/ingressd/cmd_smartdns.go), outside the agent, and register here.
// Connectors' Smart DNS state comes from the connector store instead.

// ExitReporter reports the node exit.
type ExitReporter interface {
	Exits() []nodeproto.ExitStatus
}

// MeshReporter reports the node mesh peers.
type MeshReporter interface {
	MeshPeers() []nodeproto.MeshPeer
}

// Capability adds capabilities to hello.
type Capability interface {
	Capabilities() []string
}

var (
	hooksMu sync.RWMutex
	hooks   any
)

// SetSmartDNS registers the Smart DNS runtime (any of the interfaces above).
func SetSmartDNS(v any) {
	hooksMu.Lock()
	hooks = v
	hooksMu.Unlock()
}

func hook() any {
	hooksMu.RLock()
	defer hooksMu.RUnlock()
	return hooks
}

func hookExits() []nodeproto.ExitStatus {
	if h, ok := hook().(ExitReporter); ok {
		return h.Exits()
	}
	return nil
}

func hookMesh() []nodeproto.MeshPeer {
	if h, ok := hook().(MeshReporter); ok {
		return h.MeshPeers()
	}
	return nil
}

func hookCapabilities() []string {
	if h, ok := hook().(Capability); ok {
		return h.Capabilities()
	}
	return nil
}

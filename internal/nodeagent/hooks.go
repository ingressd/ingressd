// SPDX-License-Identifier: Apache-2.0

package nodeagent

import (
	"sync"

	"github.com/ingressd/ingressd/pkg/nodeproto"
)

// Smart DNS hooks. The Smart DNS stream (internal/smartdns, internal/mesh)
// runs in the same process and reports through these small interfaces, so
// it can plug in without editing this package:
//
//	nodeagent.SetSmartDNS(myResolver) // any value implementing some of them
//
// Each interface is optional; anything not implemented falls back to a
// no-op (empty) default. Implementations must be safe for concurrent use
// and return quickly (they are called from the status and usage loops).

// ExitReporter reports the Smart DNS exits hosted on this node (status.exits).
type ExitReporter interface {
	Exits() []nodeproto.ExitStatus
}

// ServiceReporter reports the Smart DNS services and the exit each uses
// (status.smartdns_services).
type ServiceReporter interface {
	Services() []nodeproto.ServiceStatus
}

// MeshReporter reports the node mesh peers (status.mesh).
type MeshReporter interface {
	MeshPeers() []nodeproto.MeshPeer
}

// ServiceUsageReporter returns Smart DNS relay usage per service accumulated
// since the previous call, and resets it (usage.smartdns). The agent
// persists what it takes, so returned deltas are never lost or counted twice.
type ServiceUsageReporter interface {
	TakeServiceUsage() []nodeproto.ServiceUsage
}

// RecentLookupReporter returns up to limit recent DNS lookups, newest first
// (answers smartdns_recent_request).
type RecentLookupReporter interface {
	RecentLookups(limit int) []nodeproto.RecentLookup
}

// Capability reports extra capabilities for hello (e.g. "smartdns", "mesh").
type Capability interface {
	Capabilities() []string
}

var (
	hooksMu sync.RWMutex
	hooks   any
)

// SetSmartDNS registers the Smart DNS implementation (nil unregisters). It
// may implement any subset of ExitReporter, ServiceReporter, MeshReporter,
// ServiceUsageReporter, RecentLookupReporter and Capability.
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

func hookServices() []nodeproto.ServiceStatus {
	if h, ok := hook().(ServiceReporter); ok {
		return h.Services()
	}
	return nil
}

func hookMesh() []nodeproto.MeshPeer {
	if h, ok := hook().(MeshReporter); ok {
		return h.MeshPeers()
	}
	return nil
}

func hookServiceUsage() []nodeproto.ServiceUsage {
	if h, ok := hook().(ServiceUsageReporter); ok {
		return h.TakeServiceUsage()
	}
	return nil
}

func hookRecent(limit int) []nodeproto.RecentLookup {
	if h, ok := hook().(RecentLookupReporter); ok {
		return h.RecentLookups(limit)
	}
	return nil
}

func hookCapabilities() []string {
	if h, ok := hook().(Capability); ok {
		return h.Capabilities()
	}
	return nil
}

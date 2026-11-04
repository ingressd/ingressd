// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/ingressd/ingressd/internal/connector/proto"
)

// Edge side of LAN service discovery (see proto/discovery.go): a pending
// request per connector in connector.json, delivered on the connector's next
// poll, and the report endpoint that stores the latest result.
//
// In managed mode the node agent calls Server.RequestDiscovery for a panel
// discover_request and forwards reports through Server.OnDiscovery. In
// standalone mode `ingressd tunnel discover` drives it.

// maxDiscoveredServices bounds a stored report.
const maxDiscoveredServices = 1024

// ErrDiscoveryUnsupported means the connector's last health report says it
// does not accept discovery requests (old version or --no-discovery).
var ErrDiscoveryUnsupported = errors.New("the connector does not accept discovery requests (old version or started with --no-discovery)")

// Discovery is the discovery state of one connector, kept in connector.json.
type Discovery struct {
	// Pending is the id of a request not yet answered.
	Pending     string    `json:"pending,omitempty"`
	RequestedAt time.Time `json:"requested_at,omitempty"`
	// Last is the most recent report.
	Last *proto.DiscoveryReport `json:"last,omitempty"`
	// ReceivedAt is when Last arrived (edge clock).
	ReceivedAt time.Time `json:"received_at,omitempty"`
}

// RequestDiscovery records a new discovery request for a tunnel's connector
// and returns its id. A newer request replaces an unanswered one.
func (s *Store) RequestDiscovery(tunnel string, now time.Time) (string, error) {
	id, err := randomSecret()
	if err != nil {
		return "", err
	}
	id = "dsc_" + id[:16]
	err = s.Update(func(st *State) error {
		c := st.Connectors[tunnel]
		if c == nil {
			return fmt.Errorf("no connector enrolled for tunnel %q", tunnel)
		}
		if c.Health != nil && !c.Health.Discovery {
			return ErrDiscoveryUnsupported
		}
		if c.Discovery == nil {
			c.Discovery = &Discovery{}
		}
		c.Discovery.Pending, c.Discovery.RequestedAt = id, now.UTC()
		return nil
	})
	return id, err
}

// DiscoveryState returns a tunnel's discovery state (nil when none).
func (s *Store) DiscoveryState(tunnel string) (*Discovery, error) {
	st, err := s.Load()
	if err != nil {
		return nil, err
	}
	if c := st.Connectors[tunnel]; c != nil {
		return c.Discovery, nil
	}
	return nil, fmt.Errorf("no connector enrolled for tunnel %q", tunnel)
}

// SaveDiscovery stores a report and clears the pending request it answers.
func (s *Store) SaveDiscovery(tunnel string, rep proto.DiscoveryReport, now time.Time) error {
	return s.Update(func(st *State) error {
		c := st.Connectors[tunnel]
		if c == nil {
			return fmt.Errorf("no connector enrolled for tunnel %q", tunnel)
		}
		if c.Discovery == nil {
			c.Discovery = &Discovery{}
		}
		if c.Discovery.Pending == rep.ID {
			c.Discovery.Pending = ""
		}
		c.Discovery.Last, c.Discovery.ReceivedAt = &rep, now.UTC()
		return nil
	})
}

// RequestDiscovery asks a tunnel's connector to scan its LAN and wakes its
// waiting poll so the request is delivered at once. It returns the request
// id; the report arrives later through OnDiscovery and the store.
func (s *Server) RequestDiscovery(tunnel string) (string, error) {
	id, err := s.Store.RequestDiscovery(tunnel, s.now())
	if err != nil {
		return "", err
	}
	s.wake()
	return id, nil
}

// wake releases waiting polls without changing the config.
func (s *Server) wake() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.changed != nil {
		close(s.changed)
	}
	s.changed = make(chan struct{})
}

// pendingDiscovery returns the discovery request id to deliver on this poll,
// or "". Only connectors that send the discover parameter get requests, and
// only ones they have not seen yet.
func (s *Server) pendingDiscovery(r *http.Request, tunnel string) string {
	q := r.URL.Query()
	if !q.Has(proto.DiscoverParam) {
		return ""
	}
	d, err := s.Store.DiscoveryState(tunnel)
	if err != nil || d == nil || d.Pending == "" || d.Pending == q.Get(proto.DiscoverParam) {
		return ""
	}
	return d.Pending
}

// discovery receives a connector's DiscoveryReport.
func (s *Server) discovery(w http.ResponseWriter, r *http.Request) {
	tunnel, ok := s.authorize(w, r)
	if !ok {
		return
	}
	var rep proto.DiscoveryReport
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&rep); err != nil {
		http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
		return
	}
	if len(rep.Services) > maxDiscoveredServices {
		rep.Services = rep.Services[:maxDiscoveredServices]
	}
	if err := s.Store.SaveDiscovery(tunnel, rep, s.now()); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.log().Info("connector discovery report", "tunnel", tunnel, "id", rep.ID, "services", len(rep.Services), "error", rep.Error)
	if s.OnDiscovery != nil {
		s.OnDiscovery(tunnel, rep)
	}
	w.WriteHeader(http.StatusNoContent)
}

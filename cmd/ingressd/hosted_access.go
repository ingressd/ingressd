// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/ingressd/ingressd/internal/auth"
	"github.com/ingressd/ingressd/internal/l4"
	"github.com/ingressd/ingressd/internal/nodeagent"
	"github.com/ingressd/ingressd/pkg/config"
	"github.com/ingressd/ingressd/pkg/nodeproto"
)

// Hosted Access wiring for managed mode (docs: provider "panel"): the
// running node agent is the Access service's panel connection, sign-outs
// and login-to-play allowlist entries are reported to the panel, and what
// the panel relays from the org's other nodes is applied here.

var (
	managedMu    sync.Mutex
	managedAgent *nodeagent.Agent
)

// setManagedAgent registers (or, with nil, unregisters) the running agent.
func setManagedAgent(e *env, a *nodeagent.Agent) {
	managedMu.Lock()
	managedAgent = a
	managedMu.Unlock()
	if a == nil {
		auth.SetPanel(nil)
		nodeagent.SetAccess(nil)
		return
	}
	auth.SetPanel(a)
	nodeagent.SetAccess(accessRelay{e})
}

func currentAgent() *nodeagent.Agent {
	managedMu.Lock()
	defer managedMu.Unlock()
	return managedAgent
}

// reportL4Allow tells the panel about an entry a player added through
// login-to-play, so the org's other nodes serving the service allow the
// player too (standalone nodes: no-op).
func reportL4Allow(en l4.Entry) {
	a := currentAgent()
	if a == nil {
		return
	}
	if err := a.ReportL4Allow(nodeproto.L4Allow{Service: en.Service, IP: en.IP, Email: en.Email, Expires: en.Expires}); err != nil {
		slog.Warn("l4: could not report the allowlist entry to the panel; other nodes do not know it", "service", en.Service, "ip", en.IP, "err", err)
	}
}

// accessRelay applies relayed revocations and allowlist entries.
type accessRelay struct{ e *env }

func (r accessRelay) ApplyRemoteRevoke(ctx context.Context, rv nodeproto.AuthRevoke) error {
	svc, err := accessService(r.e)
	if err != nil {
		return err
	}
	return svc.ApplyRemoteRevoke(ctx, rv)
}

func (r accessRelay) ApplyRemoteL4Allow(ctx context.Context, al nodeproto.L4Allow) error {
	var ttl time.Duration
	if !al.Expires.IsZero() {
		if ttl = time.Until(al.Expires); ttl <= 0 {
			return nil // already expired
		}
	}
	cfg, err := r.e.loadConfig()
	if err != nil {
		return err
	}
	svc4, ok := cfg.L4[al.Service]
	if !ok {
		return nil // this node does not serve the service
	}
	// Entries come from a player who signed in on the panel's portal or on
	// another node; this node still checks the service's policy for the
	// player's email and address before opening the port.
	if svc4.Access != config.L4AccessLoginToPlay || svc4.LoginToPlay == nil || al.Email == "" {
		slog.Warn("l4: ignoring a relayed allowlist entry for a service without login to play", "service", al.Service, "ip", al.IP)
		return nil
	}
	svc, err := accessService(r.e)
	if err != nil {
		return err
	}
	d, err := svc.Evaluate([]string{svc4.LoginToPlay.Policy}, al.Email, al.IP)
	if err != nil {
		return err
	}
	if d.Action != config.ActionAllow {
		slog.Warn("l4: relayed allowlist entry refused by the service's policy", "service", al.Service, "email", al.Email, "ip", al.IP)
		return nil
	}
	_, err = r.e.l4Manager(cfg).Allow(ctx, al.Service, al.IP, al.Email, ttl)
	return err
}

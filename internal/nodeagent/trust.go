// SPDX-License-Identifier: Apache-2.0

package nodeagent

import (
	"sync"
	"time"

	"github.com/ingressd/ingressd/pkg/nodeproto"
)

// Panel → node trust (docs/rev1/NODE-AGENT.md "Trust model"): snapshots
// must carry a v2 org signature bound to this node, its org and a short
// validity window; the request types nodeproto.RequiresSignature lists must
// carry an org-signed Envelope.Auth. Neither accepts the legacy unsigned /
// v1 forms: an agent that advertises the capabilities never downgrades.

// trustCapabilities are advertised in hello.
var trustCapabilities = []string{nodeproto.CapabilitySnapshotV2, nodeproto.CapabilitySignedRequests}

// replayCache remembers signed nonces until their signature expires, so a
// captured request (or forced snapshot) cannot be replayed within its
// validity window.
type replayCache struct {
	mu   sync.Mutex
	seen map[string]time.Time // key → forget after
}

// add records key until 'until' and reports whether it was new.
func (c *replayCache) add(key string, until, now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.seen == nil {
		c.seen = map[string]time.Time{}
	}
	for k, t := range c.seen {
		if now.After(t) {
			delete(c.seen, k)
		}
	}
	if _, dup := c.seen[key]; dup {
		return false
	}
	// Keep it past the expiry plus the clock skew the check tolerates.
	c.seen[key] = until.Add(nodeproto.MaxClockSkew)
	return true
}

// verifyRequest checks a signed panel request against the pinned org key,
// this node's identity and the replay cache.
func (a *Agent) verifyRequest(env nodeproto.Envelope, now time.Time) error {
	st := a.State()
	if err := env.VerifyAuth(st.OrgSigningKey, st.NodeID, st.OrgID, now); err != nil {
		return err
	}
	if !a.replay.add("req:"+env.Auth.Nonce, env.Auth.ExpiresAt, now) {
		return errReplayed(env.Type)
	}
	return nil
}

type errReplayed string

func (e errReplayed) Error() string { return string(e) + ": replayed request (nonce already used)" }

// rejectRequest answers a request that failed verification so the panel
// does not wait for a timeout, and reports it as an event.
func (a *Agent) rejectRequest(s *session, env nodeproto.Envelope, err error) {
	a.log.Warn("rejected panel request", "type", env.Type, "id", env.ID, "err", err)
	msg := "rejected: " + err.Error()
	switch env.Type {
	case nodeproto.TypeConnectorTokenRequest:
		var req nodeproto.ConnectorTokenRequest
		_ = env.Decode(&req)
		_ = a.sendOn(s, nodeproto.TypeConnectorToken, env.ID, nodeproto.ConnectorToken{Site: req.Site, Error: msg})
	case nodeproto.TypeSiteConfigRequest:
		var req nodeproto.SiteConfigRequest
		_ = env.Decode(&req)
		_ = a.sendOn(s, nodeproto.TypeSiteConfig, env.ID, nodeproto.SiteConfig{Site: req.Site, Error: msg})
	case nodeproto.TypeDiagRequest:
		var req nodeproto.DiagRequest
		_ = env.Decode(&req)
		_ = a.sendOn(s, nodeproto.TypeDiagResult, env.ID, nodeproto.DiagResult{RequestID: req.RequestID, Kind: req.Kind, Message: msg})
	}
	_ = a.sendOn(s, nodeproto.TypeEvent, "", nodeproto.Event{
		Kind: "request_rejected", Severity: "warning", Message: "node rejected a panel request: " + err.Error(),
		Fields: map[string]string{"type": env.Type, "id": env.ID}, Time: time.Now().UTC(),
	})
}

// SPDX-License-Identifier: Apache-2.0

package nodeagent

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/ingressd/ingressd/pkg/nodeproto"
)

// Hosted Access over the control channel (see docs/rev1/NODE-AGENT.md):
// the Agent implements auth.Panel (OTP requests the panel answers) and
// relays sign-outs and login-to-play allowlist entries both ways.

// AccessReceiver applies what the panel relays from the org's other nodes.
// serve registers one with SetAccess; implementations must not block long.
type AccessReceiver interface {
	ApplyRemoteRevoke(ctx context.Context, r nodeproto.AuthRevoke) error
	ApplyRemoteL4Allow(ctx context.Context, a nodeproto.L4Allow) error
}

var (
	accessMu sync.RWMutex
	accessRx AccessReceiver

	// pending OTP requests by envelope id (ids are random, so one map
	// serves every Agent in the process).
	authPending sync.Map // id → chan nodeproto.Envelope
)

// SetAccess registers the receiver for relayed revocations and allowlist
// entries (nil unregisters).
func SetAccess(r AccessReceiver) {
	accessMu.Lock()
	accessRx = r
	accessMu.Unlock()
}

func accessReceiver() AccessReceiver {
	accessMu.RLock()
	defer accessMu.RUnlock()
	return accessRx
}

// accessRequest sends typ and waits for the panel's reply with the same id.
func (a *Agent) accessRequest(ctx context.Context, typ string, v any) (nodeproto.Envelope, error) {
	id := "auth-" + accessRequestID()
	ch := make(chan nodeproto.Envelope, 1)
	authPending.Store(id, ch)
	defer authPending.Delete(id)
	if err := a.send(typ, id, v); err != nil {
		return nodeproto.Envelope{}, err
	}
	select {
	case env := <-ch:
		return env, nil
	case <-ctx.Done():
		return nodeproto.Envelope{}, fmt.Errorf("the panel did not answer %s: %w", typ, ctx.Err())
	}
}

// OTPStart asks the panel to email a sign-in code (auth.Panel).
func (a *Agent) OTPStart(ctx context.Context, req nodeproto.AuthOTPStart) (nodeproto.AuthOTPStartResult, error) {
	var res nodeproto.AuthOTPStartResult
	env, err := a.accessRequest(ctx, nodeproto.TypeAuthOTPStart, req)
	if err == nil {
		err = env.Decode(&res)
	}
	return res, err
}

// OTPVerify asks the panel to check a sign-in code (auth.Panel).
func (a *Agent) OTPVerify(ctx context.Context, req nodeproto.AuthOTPVerify) (nodeproto.AuthOTPVerifyResult, error) {
	var res nodeproto.AuthOTPVerifyResult
	env, err := a.accessRequest(ctx, nodeproto.TypeAuthOTPVerify, req)
	if err == nil {
		err = env.Decode(&res)
	}
	return res, err
}

// ReportRevoke tells the panel about a local sign-out (auth.Panel).
func (a *Agent) ReportRevoke(r nodeproto.AuthRevoke) error {
	return a.send(nodeproto.TypeAuthRevoke, "", r)
}

// ReportL4Allow tells the panel about an allowlist entry a player added.
func (a *Agent) ReportL4Allow(e nodeproto.L4Allow) error {
	return a.send(nodeproto.TypeL4Allow, "", e)
}

// onAccess handles the hosted-Access messages from the panel.
func (a *Agent) onAccess(env nodeproto.Envelope) {
	switch env.Type {
	case nodeproto.TypeAuthOTPStartResult, nodeproto.TypeAuthOTPVerifyResult:
		if ch, ok := authPending.Load(env.ID); ok {
			select {
			case ch.(chan nodeproto.Envelope) <- env:
			default:
			}
		}
	case nodeproto.TypeAuthRevoke:
		var r nodeproto.AuthRevoke
		if err := env.Decode(&r); err != nil {
			return
		}
		go a.applyRemote(func(ctx context.Context, rx AccessReceiver) error { return rx.ApplyRemoteRevoke(ctx, r) }, "revocation")
	case nodeproto.TypeL4Allow:
		var al nodeproto.L4Allow
		if err := env.Decode(&al); err != nil {
			return
		}
		go a.applyRemote(func(ctx context.Context, rx AccessReceiver) error { return rx.ApplyRemoteL4Allow(ctx, al) }, "l4 allowlist entry")
	}
}

func (a *Agent) applyRemote(fn func(context.Context, AccessReceiver) error, what string) {
	rx := accessReceiver()
	if rx == nil {
		a.log.Debug("no receiver for relayed "+what+"; ignored", "kind", what)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := fn(ctx, rx); err != nil && !errors.Is(err, context.Canceled) {
		a.log.Warn("applying relayed "+what+" failed", "err", err)
	}
}

func accessRequestID() string {
	b := make([]byte, 9)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

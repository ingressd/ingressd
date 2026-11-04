// SPDX-License-Identifier: Apache-2.0

package idp

import (
	"errors"
	"time"

	"aidanwoods.dev/go-paseto"
)

// FlowCookieName holds the sealed Flow between Start and the callback.
// Callers scope it to their callback path, HttpOnly, Secure and
// SameSite=Lax (the provider's redirect back is a top-level GET, which Lax
// cookies accompany).
const FlowCookieName = "__edge_idp"

var flowImplicit = []byte("ingressd-idp-flow")

// SealFlow encrypts a flow under key (32 bytes; access.Keys.IDPFlowKey).
func SealFlow(key []byte, f Flow) (string, error) {
	k, err := paseto.V4SymmetricKeyFromBytes(key)
	if err != nil {
		return "", err
	}
	t := paseto.NewToken()
	t.SetIssuedAt(time.Now())
	t.SetExpiration(f.Expires)
	if err := t.Set("flow", f); err != nil {
		return "", err
	}
	return t.V4Encrypt(k, flowImplicit), nil
}

// OpenFlow decrypts a sealed flow and checks its expiry.
func OpenFlow(key []byte, v string) (Flow, error) {
	var f Flow
	k, err := paseto.V4SymmetricKeyFromBytes(key)
	if err != nil {
		return f, err
	}
	t, err := paseto.NewParser().ParseV4Local(k, v, flowImplicit)
	if err != nil {
		return f, ErrState
	}
	if err := t.Get("flow", &f); err != nil || f.State == "" {
		return f, errors.Join(ErrState, err)
	}
	return f, nil
}

// SPDX-License-Identifier: Apache-2.0

// Package auth implements ingressd Access (PLAN §7): the policy engine,
// emailed one-time codes, sessions, the login portal and the shared pieces
// (keys, token formats) that the edge_auth Caddy module verifies offline.
// The key format, tokens and engine themselves live in pkg/access.
package auth

import "github.com/ingressd/ingressd/pkg/access"

// The key format, the sealed tokens and the policy engine live in
// pkg/access so the hosted panel (central sign-in portal) shares them with
// the node. These aliases keep the node's call sites unchanged.

type (
	Keys         = access.Keys
	JWK          = access.JWK
	AppClaims    = access.AppClaims
	PortalClaims = access.PortalClaims
	SealedCode   = access.SealedCode
	Identity     = access.Identity
	Decision     = access.Decision
	Engine       = access.Engine
)

const (
	PortalCookieName = access.PortalCookieName
	PlayCookieName   = access.PlayCookieName
)

var (
	ParseKeys      = access.ParseKeys
	KeyID          = access.KeyID
	AppCookieName  = access.AppCookieName
	NewEngine      = access.NewEngine
	ListFor        = access.ListFor
	AllLists       = access.AllLists
	PathMatch      = access.PathMatch
	CleanPath      = access.CleanPath
	NormalizeEmail = access.NormalizeEmail
	HostAllowed    = access.HostAllowed
	FlowNonceHash  = access.FlowNonceHash
	ValidFlowNonce = access.ValidFlowNonceHash
)

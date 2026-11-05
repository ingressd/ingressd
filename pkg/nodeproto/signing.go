// SPDX-License-Identifier: Apache-2.0

package nodeproto

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"slices"
	"time"
)

// Capabilities a node lists in Hello.Capabilities to opt into the
// org-key-bound message formats below. The panel uses them only for nodes
// that advertise them; a node that advertises them rejects the old formats
// (no downgrade).
const (
	// CapabilitySnapshotV2: snapshots are signed over
	// SnapshotSigningPayloadV2 (bound to node, org and a short validity).
	CapabilitySnapshotV2 = "snapshot-v2"
	// CapabilitySignedRequests: the panel signs every message type for
	// which RequiresSignature is true (Envelope.Auth).
	CapabilitySignedRequests = "signed-requests"
)

const (
	// SnapshotValidity is how long a v2 snapshot signature is valid. The
	// panel signs at delivery time (every send, including the resend on
	// reconnect), so it only has to cover transit and the node's queue.
	SnapshotValidity = 10 * time.Minute
	// RequestValidity is how long a signed request is valid.
	RequestValidity = 2 * time.Minute
	// MaxClockSkew is the clock difference between panel and node that
	// signature validity checks tolerate.
	MaxClockSkew = 2 * time.Minute
	// maxSignedValidity bounds ExpiresAt-IssuedAt the node accepts, so a
	// leaked signing call cannot mint long-lived messages.
	maxSignedValidity = 15 * time.Minute
)

// signedTypes are the panel → node messages that change node state, mint
// or return secrets, or reveal node-local data (connector enrolment
// tokens, router WireGuard configs, detach, L4 allowlist entries, session
// revocations, LAN discovery, Smart DNS lookups, live access logs, live
// metrics, diagnostics, updates). Replies to node-initiated requests
// (auth_otp_*_result, storage_response) and keepalives (ping, usage_ack,
// live_unsubscribe, metrics_ack, metrics_unsubscribe) are not in the set; snapshots carry their own signature.
var signedTypes = map[string]bool{
	TypeConnectorTokenRequest: true,
	TypeSiteConfigRequest:     true,
	TypeDetach:                true,
	TypeL4Allow:               true,
	TypeAuthRevoke:            true,
	TypeDiscoverRequest:       true,
	TypeSmartDNSRecentRequest: true,
	TypeLiveSubscribe:         true,
	TypeMetricsSubscribe:      true,
	TypeDiagRequest:           true,
	TypeUpgradeRequest:        true,
	TypeConnectorUpdate:       true,
}

// RequiresSignature reports whether a node advertising
// CapabilitySignedRequests accepts the panel → node message type typ only
// with a valid Envelope.Auth.
func RequiresSignature(typ string) bool { return signedTypes[typ] }

// SignedTypes lists the types for which RequiresSignature is true (sorted).
func SignedTypes() []string {
	out := make([]string, 0, len(signedTypes))
	for t := range signedTypes {
		out = append(out, t)
	}
	slices.Sort(out)
	return out
}

// RequestAuth is the org-key signature of a panel → node envelope.
type RequestAuth struct {
	NodeID    string    `json:"node_id"`
	OrgID     string    `json:"org_id"`
	Nonce     string    `json:"nonce"` // random; the node rejects repeats within the validity window
	IssuedAt  time.Time `json:"issued_at"`
	ExpiresAt time.Time `json:"expires_at"`
	// Signature is base64 ed25519 over RequestSigningPayload.
	Signature string `json:"sig"`
}

func writeField(h hash.Hash, s string) {
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(s)))
	h.Write(n[:])
	h.Write([]byte(s))
}

func writeInt(h hash.Hash, v int64) {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(v))
	h.Write(b[:])
}

// RequestSigningPayload is the byte string the org key signs for a
// request: a domain separator, the message type, envelope ID, node, org,
// nonce, validity (Unix seconds) and the SHA-256 of the envelope's data
// bytes exactly as sent.
func RequestSigningPayload(typ, id string, data []byte, a RequestAuth) []byte {
	h := sha256.New()
	h.Write([]byte("ingressd-request-v1\x00"))
	writeField(h, typ)
	writeField(h, id)
	writeField(h, a.NodeID)
	writeField(h, a.OrgID)
	writeField(h, a.Nonce)
	writeInt(h, a.IssuedAt.Unix())
	writeInt(h, a.ExpiresAt.Unix())
	d := sha256.Sum256(data)
	h.Write(d[:])
	return h.Sum(nil)
}

func newNonce() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// EncodeSigned is Encode plus an org-key signature binding the message to
// nodeID and orgID for RequestValidity from now.
func EncodeSigned(typ, id string, v any, nodeID, orgID string, now time.Time, key ed25519.PrivateKey) ([]byte, error) {
	if len(key) != ed25519.PrivateKeySize {
		return nil, errors.New("no org signing key")
	}
	var data json.RawMessage
	if v != nil {
		b, err := json.Marshal(v)
		if err != nil {
			return nil, err
		}
		data = b
	}
	now = now.UTC().Truncate(time.Second)
	a := &RequestAuth{NodeID: nodeID, OrgID: orgID, Nonce: newNonce(), IssuedAt: now, ExpiresAt: now.Add(RequestValidity)}
	a.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(key, RequestSigningPayload(typ, id, data, *a)))
	return json.Marshal(Envelope{Type: typ, ID: id, Data: data, Auth: a})
}

func parseOrgKey(orgPublicKey string) (ed25519.PublicKey, error) {
	pub, err := base64.StdEncoding.DecodeString(orgPublicKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return nil, errors.New("invalid org signing key")
	}
	return ed25519.PublicKey(pub), nil
}

// checkBinding validates the node/org binding and validity window shared by
// signed requests and v2 snapshots.
func checkBinding(gotNode, gotOrg, wantNode, wantOrg string, issued, expires, now time.Time) error {
	if gotNode == "" || gotNode != wantNode {
		return fmt.Errorf("signed for node %q, not this node (%s)", gotNode, wantNode)
	}
	// The org key is per org already; the org ID check is defence in depth
	// (node.json from very early releases may not record the org).
	if wantOrg != "" && gotOrg != wantOrg {
		return fmt.Errorf("signed for org %q, not this node's org (%s)", gotOrg, wantOrg)
	}
	if issued.IsZero() || expires.IsZero() || !expires.After(issued) || expires.Sub(issued) > maxSignedValidity {
		return errors.New("invalid signature validity window")
	}
	if issued.After(now.Add(MaxClockSkew)) {
		return fmt.Errorf("issued in the future (%s; check the node's clock)", issued.Format(time.RFC3339))
	}
	if !now.Before(expires.Add(MaxClockSkew)) {
		return fmt.Errorf("expired at %s (replayed, or the node's clock is wrong)", expires.Format(time.RFC3339))
	}
	return nil
}

// VerifyAuth checks the envelope's org-key signature and its binding to
// nodeID and orgID at time now. Replay of a nonce within its validity is
// the caller's to reject (see ReplayCache).
func (e Envelope) VerifyAuth(orgPublicKey, nodeID, orgID string, now time.Time) error {
	if e.Auth == nil {
		return fmt.Errorf("%s: unsigned (this node requires org-signed requests)", e.Type)
	}
	pub, err := parseOrgKey(orgPublicKey)
	if err != nil {
		return err
	}
	a := *e.Auth
	if a.Nonce == "" {
		return fmt.Errorf("%s: signature without a nonce", e.Type)
	}
	sig, err := base64.StdEncoding.DecodeString(a.Signature)
	if err != nil || !ed25519.Verify(pub, RequestSigningPayload(e.Type, e.ID, e.Data, a), sig) {
		return fmt.Errorf("%s: signature does not match the org key", e.Type)
	}
	if err := checkBinding(a.NodeID, a.OrgID, nodeID, orgID, a.IssuedAt, a.ExpiresAt, now); err != nil {
		return fmt.Errorf("%s: %w", e.Type, err)
	}
	return nil
}

// --- Snapshot v2 ---

// SnapshotSigningPayloadV2 is what the org key signs for a v2 snapshot:
// a new domain separator, the node and org it is for, revision, force flag,
// validity (Unix seconds), the SHA-256 of the config, and every secret and
// removal in sorted order.
func SnapshotSigningPayloadV2(s Snapshot) []byte {
	h := sha256.New()
	h.Write([]byte("ingressd-snapshot-v2\x00"))
	writeField(h, s.NodeID)
	writeField(h, s.OrgID)
	writeInt(h, s.Revision)
	if s.Force {
		h.Write([]byte{1})
	} else {
		h.Write([]byte{0})
	}
	writeInt(h, s.IssuedAt.Unix())
	writeInt(h, s.ExpiresAt.Unix())
	cfg := sha256.Sum256([]byte(s.ConfigYAML))
	h.Write(cfg[:])
	names := make([]string, 0, len(s.Secrets))
	for n := range s.Secrets {
		names = append(names, n)
	}
	slices.Sort(names)
	writeInt(h, int64(len(names)))
	for _, n := range names {
		writeField(h, n)
		writeField(h, s.Secrets[n])
	}
	removed := slices.Clone(s.RemoveSecrets)
	slices.Sort(removed)
	writeInt(h, int64(len(removed)))
	for _, n := range removed {
		writeField(h, n)
	}
	return h.Sum(nil)
}

// SignV2 binds s to nodeID and orgID for SnapshotValidity from now and
// signs it (SignedAt = IssuedAt). Callers sign at delivery time, never
// reuse a stored v2 signature.
func SignV2(s *Snapshot, nodeID, orgID string, now time.Time, key ed25519.PrivateKey) {
	now = now.UTC().Truncate(time.Second)
	s.NodeID, s.OrgID = nodeID, orgID
	s.IssuedAt, s.ExpiresAt, s.SignedAt = now, now.Add(SnapshotValidity), now
	s.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(key, SnapshotSigningPayloadV2(*s)))
}

// VerifyV2 checks a v2 snapshot: the org signature over
// SnapshotSigningPayloadV2, that it is for nodeID (and orgID when known),
// and that it is within its validity window at now. A v1 snapshot (no
// node binding) is rejected.
func VerifyV2(s Snapshot, orgPublicKey, nodeID, orgID string, now time.Time) error {
	pub, err := parseOrgKey(orgPublicKey)
	if err != nil {
		return err
	}
	if s.NodeID == "" || s.IssuedAt.IsZero() || s.ExpiresAt.IsZero() {
		return errors.New("legacy (v1) snapshot signature; this node requires snapshot-v2")
	}
	sig, err := base64.StdEncoding.DecodeString(s.Signature)
	if err != nil {
		return errors.New("invalid snapshot signature encoding")
	}
	if !ed25519.Verify(pub, SnapshotSigningPayloadV2(s), sig) {
		return errors.New("snapshot signature does not match the org key")
	}
	if err := checkBinding(s.NodeID, s.OrgID, nodeID, orgID, s.IssuedAt, s.ExpiresAt, now); err != nil {
		return fmt.Errorf("snapshot %w", err)
	}
	return nil
}

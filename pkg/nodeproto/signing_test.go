// SPDX-License-Identifier: Apache-2.0

package nodeproto

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func testKey(t *testing.T) (string, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(pub), priv
}

func TestSnapshotV2RoundTrip(t *testing.T) {
	pub, priv := testKey(t)
	now := time.Now()
	s := Snapshot{Revision: 7, ConfigYAML: "version: 1\n", Secrets: map[string]string{"a": "ct-a", "b": "ct-b"}, RemoveSecrets: []string{"old"}, Force: true}
	SignV2(&s, "nod_a", "org_a", now, priv)
	// Through JSON, as on the wire.
	b, _ := json.Marshal(s)
	var got Snapshot
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if err := VerifyV2(got, pub, "nod_a", "org_a", now); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if err := VerifyV2(got, pub, "nod_a", "", now); err != nil {
		t.Fatalf("verify without pinned org: %v", err)
	}
	if got.ExpiresAt.Sub(got.IssuedAt) != SnapshotValidity {
		t.Errorf("validity = %v", got.ExpiresAt.Sub(got.IssuedAt))
	}

	cases := map[string]struct {
		mut  func(*Snapshot)
		node string
		org  string
		at   time.Time
		want string
	}{
		"other node":       {node: "nod_b", org: "org_a", at: now, want: "not this node"},
		"other org":        {node: "nod_a", org: "org_b", at: now, want: "not this node's org"},
		"expired":          {node: "nod_a", org: "org_a", at: now.Add(SnapshotValidity + MaxClockSkew + time.Second), want: "expired"},
		"future":           {node: "nod_a", org: "org_a", at: now.Add(-MaxClockSkew - 2*time.Second), want: "future"},
		"force flipped":    {mut: func(s *Snapshot) { s.Force = false }, node: "nod_a", org: "org_a", at: now, want: "does not match"},
		"node rewritten":   {mut: func(s *Snapshot) { s.NodeID = "nod_b" }, node: "nod_b", org: "org_a", at: now, want: "does not match"},
		"expiry extended":  {mut: func(s *Snapshot) { s.ExpiresAt = s.ExpiresAt.Add(time.Hour) }, node: "nod_a", org: "org_a", at: now, want: "does not match"},
		"secret removed":   {mut: func(s *Snapshot) { delete(s.Secrets, "b") }, node: "nod_a", org: "org_a", at: now, want: "does not match"},
		"removal dropped":  {mut: func(s *Snapshot) { s.RemoveSecrets = nil }, node: "nod_a", org: "org_a", at: now, want: "does not match"},
		"config tampered":  {mut: func(s *Snapshot) { s.ConfigYAML += "#" }, node: "nod_a", org: "org_a", at: now, want: "does not match"},
		"revision changed": {mut: func(s *Snapshot) { s.Revision++ }, node: "nod_a", org: "org_a", at: now, want: "does not match"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			s := got
			s.Secrets = map[string]string{"a": "ct-a", "b": "ct-b"}
			if c.mut != nil {
				c.mut(&s)
			}
			err := VerifyV2(s, pub, c.node, c.org, c.at)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want %q", err, c.want)
			}
		})
	}
}

func TestSnapshotV2RejectsLegacy(t *testing.T) {
	pub, priv := testKey(t)
	s := Snapshot{Revision: 1, ConfigYAML: "version: 1\n", Force: true, SignedAt: time.Now()}
	Sign(&s, priv) // v1: valid for Verify, never for VerifyV2
	if err := Verify(s, pub); err != nil {
		t.Fatal(err)
	}
	if err := VerifyV2(s, pub, "nod_a", "org_a", time.Now()); err == nil || !strings.Contains(err.Error(), "legacy") {
		t.Fatalf("v1 snapshot accepted by VerifyV2: %v", err)
	}
	// A v1 signature with v2 fields bolted on does not verify either.
	s.NodeID, s.OrgID, s.IssuedAt, s.ExpiresAt = "nod_a", "org_a", time.Now(), time.Now().Add(time.Minute)
	if err := VerifyV2(s, pub, "nod_a", "org_a", time.Now()); err == nil {
		t.Fatal("v1 signature accepted as v2")
	}
	// And a v2 signature is not a valid v1 one (domain separation).
	SignV2(&s, "nod_a", "org_a", time.Now(), priv)
	if err := Verify(s, pub); err == nil {
		t.Fatal("v2 signature verified as v1")
	}
}

func TestSnapshotV2ValidityWindowBounded(t *testing.T) {
	pub, priv := testKey(t)
	now := time.Now().UTC().Truncate(time.Second)
	s := Snapshot{Revision: 1, ConfigYAML: "x", NodeID: "nod_a", OrgID: "org_a", IssuedAt: now, ExpiresAt: now.Add(24 * time.Hour)}
	s.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, SnapshotSigningPayloadV2(s)))
	if err := VerifyV2(s, pub, "nod_a", "org_a", now); err == nil || !strings.Contains(err.Error(), "validity") {
		t.Fatalf("long-lived snapshot accepted: %v", err)
	}
}

func TestSignedRequestRoundTrip(t *testing.T) {
	pub, priv := testKey(t)
	now := time.Now()
	b, err := EncodeSigned(TypeSiteConfigRequest, "req1", SiteConfigRequest{Site: "home"}, "nod_a", "org_a", now, priv)
	if err != nil {
		t.Fatal(err)
	}
	var env Envelope
	if err := json.Unmarshal(b, &env); err != nil {
		t.Fatal(err)
	}
	if err := env.VerifyAuth(pub, "nod_a", "org_a", now); err != nil {
		t.Fatalf("verify: %v", err)
	}
	var req SiteConfigRequest
	if err := env.Decode(&req); err != nil || req.Site != "home" {
		t.Fatalf("decode: %v %+v", err, req)
	}

	reject := func(name string, e Envelope, node, org string, at time.Time, want string) {
		t.Helper()
		if err := e.VerifyAuth(pub, node, org, at); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: err = %v, want %q", name, err, want)
		}
	}
	reject("wrong node", env, "nod_b", "org_a", now, "not this node")
	reject("wrong org", env, "nod_a", "org_b", now, "org")
	reject("expired", env, "nod_a", "org_a", now.Add(RequestValidity+MaxClockSkew+time.Second), "expired")

	e := env
	e.Type = TypeConnectorTokenRequest // same data, other type
	reject("type swapped", e, "nod_a", "org_a", now, "does not match")
	e = env
	e.ID = "req2"
	reject("id swapped", e, "nod_a", "org_a", now, "does not match")
	e = env
	e.Data = json.RawMessage(`{"site":"other"}`)
	reject("data swapped", e, "nod_a", "org_a", now, "does not match")
	e = env
	a := *env.Auth
	a.NodeID = "nod_b"
	e.Auth = &a
	reject("node rewritten", e, "nod_b", "org_a", now, "does not match")
	e = env
	e.Auth = nil
	reject("unsigned", e, "nod_a", "org_a", now, "unsigned")

	otherPub, _ := testKey(t)
	if err := env.VerifyAuth(otherPub, "nod_a", "org_a", now); err == nil {
		t.Error("verified with another org's key")
	}
}

func TestSignedRequestNoncesDiffer(t *testing.T) {
	_, priv := testKey(t)
	var a, b Envelope
	x, _ := EncodeSigned(TypeDetach, "", Detach{}, "n", "o", time.Now(), priv)
	y, _ := EncodeSigned(TypeDetach, "", Detach{}, "n", "o", time.Now(), priv)
	_ = json.Unmarshal(x, &a)
	_ = json.Unmarshal(y, &b)
	if a.Auth.Nonce == "" || a.Auth.Nonce == b.Auth.Nonce {
		t.Fatalf("nonces %q %q", a.Auth.Nonce, b.Auth.Nonce)
	}
}

func TestRequiresSignature(t *testing.T) {
	for _, typ := range []string{TypeConnectorTokenRequest, TypeSiteConfigRequest, TypeDetach, TypeL4Allow, TypeAuthRevoke, TypeUpgradeRequest} {
		if !RequiresSignature(typ) {
			t.Errorf("%s must require a signature", typ)
		}
	}
	for _, typ := range []string{TypePing, TypeUsageAck, TypeSnapshot, TypeAuthOTPVerifyResult, TypeStorageResponse, TypeLiveUnsubscribe} {
		if RequiresSignature(typ) {
			t.Errorf("%s must not require a request signature", typ)
		}
	}
}

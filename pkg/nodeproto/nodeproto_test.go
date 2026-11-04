// SPDX-License-Identifier: Apache-2.0

package nodeproto

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"testing"
)

func TestSignVerify(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pubB64 := base64.StdEncoding.EncodeToString(pub)
	s := Snapshot{
		Revision:      7,
		ConfigYAML:    "version: 1\n",
		Secrets:       map[string]string{"b": "cipher-b", "a": "cipher-a"},
		RemoveSecrets: []string{"old"},
	}
	Sign(&s, priv)
	if err := Verify(s, pubB64); err != nil {
		t.Fatalf("Verify: %v", err)
	}

	for name, mutate := range map[string]func(*Snapshot){
		"revision": func(s *Snapshot) { s.Revision = 8 },
		"config":   func(s *Snapshot) { s.ConfigYAML = "version: 2\n" },
		"secret":   func(s *Snapshot) { s.Secrets["a"] = "other" },
		"added":    func(s *Snapshot) { s.Secrets["c"] = "new" },
		"removal":  func(s *Snapshot) { s.RemoveSecrets = nil },
		"force":    func(s *Snapshot) { s.Force = true },
	} {
		c := s
		c.Secrets = map[string]string{}
		for k, v := range s.Secrets {
			c.Secrets[k] = v
		}
		c.RemoveSecrets = append([]string(nil), s.RemoveSecrets...)
		mutate(&c)
		if Verify(c, pubB64) == nil {
			t.Errorf("tampered %s still verifies", name)
		}
	}

	other, _, _ := ed25519.GenerateKey(rand.Reader)
	if Verify(s, base64.StdEncoding.EncodeToString(other)) == nil {
		t.Error("verified against the wrong key")
	}
}

func TestPayloadIndependentOfMapOrder(t *testing.T) {
	a := Snapshot{Revision: 1, Secrets: map[string]string{"x": "1", "y": "2", "z": "3"}}
	b := Snapshot{Revision: 1, Secrets: map[string]string{"z": "3", "x": "1", "y": "2"}}
	if string(SnapshotSigningPayload(a)) != string(SnapshotSigningPayload(b)) {
		t.Fatal("payload depends on map iteration order")
	}
}

func TestEnvelopeRoundTrip(t *testing.T) {
	b, err := Encode(TypeApplied, "42", Applied{Revision: 3, OK: true})
	if err != nil {
		t.Fatal(err)
	}
	var env Envelope
	if err := json.Unmarshal(b, &env); err != nil {
		t.Fatal(err)
	}
	var got Applied
	if env.Type != TypeApplied || env.ID != "42" || env.Decode(&got) != nil || got.Revision != 3 || !got.OK {
		t.Fatalf("round trip = %+v %+v", env, got)
	}
}

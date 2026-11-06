// SPDX-License-Identifier: Apache-2.0

package nodeproto

import (
	"crypto/ed25519"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// The connector stores the envelope inside an indented state file.
func TestSignedSmartDNSSurvivesReencoding(t *testing.T) {
	_, key, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	env := SignedSmartDNS{Connector: "conn", Issued: time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC), Config: json.RawMessage(`{"listen":"192.168.1.5","services":{"a b":{"domains":["x.example"]}}}`)}
	SignSmartDNS(&env, key)
	b, err := json.MarshalIndent(struct {
		Blob json.RawMessage `json:"blob"`
	}{mustJSON(t, env)}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	var back struct {
		Blob SignedSmartDNS `json:"blob"`
	}
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(back.Blob.Config), "\n") {
		t.Fatal("test needs an indented config")
	}
	if err := back.Blob.Verify("conn"); err != nil {
		t.Fatalf("reformatted config: %v", err)
	}
	// Whitespace inside a string is content, not formatting.
	back.Blob.Config = json.RawMessage(strings.Replace(string(back.Blob.Config), "a b", "a  b", 1))
	if err := back.Blob.Verify("conn"); err == nil {
		t.Fatal("changed config verified")
	}
}

func mustJSON(t *testing.T, v any) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

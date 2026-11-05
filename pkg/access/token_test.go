// SPDX-License-Identifier: Apache-2.0

package access

import (
	"testing"
	"time"
)

// Shared vector with edge/modules/edgeauth (TestNonceHashVector): the
// portal seals what edge_auth puts in the login URL.
func TestFlowNonceHashVector(t *testing.T) {
	if got := FlowNonceHash("abc"); got != "ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0" {
		t.Fatalf("FlowNonceHash = %s", got)
	}
	if !ValidFlowNonceHash(FlowNonceHash("x")) || ValidFlowNonceHash("abc") || ValidFlowNonceHash("") {
		t.Fatal("ValidFlowNonceHash")
	}
}

// A realm's app cookie never opens in another realm or without realms, even
// under the same master key and app name.
func TestRealmAppCookies(t *testing.T) {
	k, err := ParseKeys(testSession, testJWT)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	tok, err := k.ForRealm("ra").SealApp(AppClaims{SID: "s", Email: "a@example.com", App: "nas", IssuedAt: now, Expires: now.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if c, err := k.ForRealm("ra").OpenApp("nas", tok); err != nil || c.Email != "a@example.com" {
		t.Fatalf("same realm: %+v %v", c, err)
	}
	if _, err := k.ForRealm("rb").OpenApp("nas", tok); err == nil {
		t.Error("cookie opened in another realm")
	}
	if _, err := k.OpenApp("nas", tok); err == nil {
		t.Error("realm cookie opened without a realm")
	}
	if k.Realm() != "" || k.ForRealm("ra").Realm() != "ra" {
		t.Error("ForRealm changed the original keys")
	}
}

const (
	testSession = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="
	testJWT     = "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgTohYiduqGv16hl2T1vP3fOGtzle8cig/IqJUnUji592hRANCAARzf4dSjgQn+UtYdnN/pJeuiukBdj4m7d+AQ5fTv+kfhbWMH/F35YYwI9jL+P5riaGOtLY/QewPMEufozI2EXZf"
)

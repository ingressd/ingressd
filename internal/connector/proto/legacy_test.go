// SPDX-License-Identifier: Apache-2.0

package proto

import (
	"crypto/ecdh"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestServeLegacyPrefix(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+PollPath, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(r.URL.Path + "?" + r.URL.RawQuery)) //nolint:gosec // G705: test handler echoing the request URL to the test
	})
	mux.Handle(LegacyMachinePrefix, ServeLegacyPrefix(mux))
	for _, p := range []string{PollPath, LegacyMachinePrefix + "connector/poll"} {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest("GET", p+"?rev=3", nil))
		if rec.Code != 200 || rec.Body.String() != PollPath+"?rev=3" {
			t.Errorf("%s: %d %q", p, rec.Code, rec.Body.String())
		}
	}
	if !strings.HasPrefix(PollPath, MachinePrefix) {
		t.Fatalf("PollPath %q outside %q", PollPath, MachinePrefix)
	}
}

func TestLegacyKeyAuthScheme(t *testing.T) {
	priv := make([]byte, 32)
	priv[0] = 1
	peerPriv := make([]byte, 32)
	peerPriv[0] = 2
	pub := x25519Pub(t, peerPriv)
	now := time.Unix(1_800_000_000, 0)
	h, err := KeyAuth("home", priv, pub, now)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h, KeyAuthScheme+" ") {
		t.Fatalf("new scheme not used: %q", h)
	}
	old := LegacyKeyAuthScheme + strings.TrimPrefix(h, KeyAuthScheme)
	if tn, ok := ParseKeyAuth(old); !ok || tn != "home" {
		t.Fatalf("legacy header not parsed: %q %v", tn, ok)
	}
	if err := CheckKeyAuth(old, peerPriv, x25519Pub(t, priv), now); err != nil {
		t.Fatalf("legacy header rejected: %v", err)
	}
}

func x25519Pub(t *testing.T, priv []byte) []byte {
	t.Helper()
	k, err := ecdh.X25519().NewPrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return k.PublicKey().Bytes()
}

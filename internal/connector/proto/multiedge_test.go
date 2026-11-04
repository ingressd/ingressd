// SPDX-License-Identifier: Apache-2.0

package proto

import (
	"crypto/ecdh"
	"crypto/rand"
	"testing"
	"time"
)

func TestKeyAuth(t *testing.T) {
	site, _ := ecdh.X25519().GenerateKey(rand.Reader)
	edge, _ := ecdh.X25519().GenerateKey(rand.Reader)
	other, _ := ecdh.X25519().GenerateKey(rand.Reader)
	now := time.Unix(1_800_000_000, 0)
	h, err := KeyAuth("home", site.Bytes(), edge.PublicKey().Bytes(), now)
	if err != nil {
		t.Fatal(err)
	}
	if tun, ok := ParseKeyAuth(h); !ok || tun != "home" {
		t.Fatalf("ParseKeyAuth(%q) = %q, %v", h, tun, ok)
	}
	if err := CheckKeyAuth(h, edge.Bytes(), site.PublicKey().Bytes(), now.Add(time.Minute)); err != nil {
		t.Errorf("valid header rejected: %v", err)
	}
	if err := CheckKeyAuth(h, edge.Bytes(), other.PublicKey().Bytes(), now); err == nil {
		t.Error("accepted for the wrong site key")
	}
	if err := CheckKeyAuth(h, edge.Bytes(), site.PublicKey().Bytes(), now.Add(10*time.Minute)); err == nil {
		t.Error("accepted a stale timestamp")
	}
	forged := "IngressdKey lab" + h[len("IngressdKey home"):]
	if err := CheckKeyAuth(forged, edge.Bytes(), site.PublicKey().Bytes(), now); err == nil {
		t.Error("accepted a header moved to another tunnel")
	}
	if _, ok := ParseKeyAuth("Bearer home.x"); ok {
		t.Error("parsed a bearer header")
	}
}

func TestKeyAuthV2(t *testing.T) {
	site, _ := ecdh.X25519().GenerateKey(rand.Reader)
	edge, _ := ecdh.X25519().GenerateKey(rand.Reader)
	now := time.Unix(1_800_000_000, 0)
	priv, pub := edge.Bytes(), site.PublicKey().Bytes()
	body := []byte(`{"mode":"tun"}`)
	h, err := KeyAuthRequest("home", site.Bytes(), edge.PublicKey().Bytes(), now, "POST", ReportPath, body)
	if err != nil {
		t.Fatal(err)
	}
	if tun, ok := ParseKeyAuth(h); !ok || tun != "home" || KeyAuthVersion(h) != KeyAuthV2 {
		t.Fatalf("ParseKeyAuth(%q) = %q, %v (version %d)", h, tun, ok, KeyAuthVersion(h))
	}
	v, nonce, err := CheckKeyAuthRequest(h, priv, pub, now.Add(time.Minute), "POST", ReportPath, body)
	if err != nil || v != 2 || len(nonce) != 32 {
		t.Fatalf("valid header: v%d nonce %q err %v", v, nonce, err)
	}
	h2, _ := KeyAuthRequest("home", site.Bytes(), edge.PublicKey().Bytes(), now, "POST", ReportPath, body)
	if _, n2, _ := CheckKeyAuthRequest(h2, priv, pub, now, "POST", ReportPath, body); n2 == nonce {
		t.Error("two headers share a nonce")
	}
	for name, c := range map[string]struct {
		method, path string
		body         []byte
		now          time.Time
	}{
		"method": {"GET", ReportPath, body, now},
		"path":   {"POST", DiscoveryPath, body, now},
		"body":   {"POST", ReportPath, []byte(`{"mode":"netstack"}`), now},
		"stale":  {"POST", ReportPath, body, now.Add(10 * time.Minute)},
	} {
		if _, _, err := CheckKeyAuthRequest(h, priv, pub, c.now, c.method, c.path, c.body); err == nil {
			t.Errorf("accepted with another %s", name)
		}
	}
	if err := CheckKeyAuth(h, priv, pub, now); err == nil {
		t.Error("CheckKeyAuth accepted a v2 header without the request")
	}
	// v1 headers still verify through CheckKeyAuthRequest, with no nonce.
	h1, _ := KeyAuth("home", site.Bytes(), edge.PublicKey().Bytes(), now)
	if v, n, err := CheckKeyAuthRequest(h1, priv, pub, now, "GET", PollPath, nil); err != nil || v != 1 || n != "" {
		t.Errorf("v1 header: v%d %q %v", v, n, err)
	}
	// A tunnel named "v2" still parses as v1.
	hv, _ := KeyAuth("v2", site.Bytes(), edge.PublicKey().Bytes(), now)
	if tun, ok := ParseKeyAuth(hv); !ok || tun != "v2" || KeyAuthVersion(hv) != 1 {
		t.Errorf("v1 header for tunnel v2: %q %v", tun, ok)
	}
}

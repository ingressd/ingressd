// SPDX-License-Identifier: Apache-2.0

package mesh

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/ingressd/ingressd/internal/secrets"
	"github.com/ingressd/ingressd/pkg/config"
)

const key = "eEvqkSJVw/7cGUEcJXmeHiNFDLBGOz8GpScshecvNHU="

func testMesh(t *testing.T) *Mesh {
	m := New(slog.New(slog.NewTextHandler(io.Discard, nil)))
	m.Reconfigure(&config.Config{Mesh: &config.Mesh{Address: "10.255.0.1/16", Peers: map[string]config.MeshPeer{
		"nod_nl": {PublicKey: key, Address: "10.255.0.2/32"},
	}}})
	return m
}

func TestPeerOnly(t *testing.T) {
	m := testMesh(t)
	m.Handle("GET /v1/who", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, PeerID(r)) }))
	h := m.peerOnly(m.mux)
	for remote, want := range map[string]int{"10.255.0.2:4000": 200, "10.255.0.9:4000": 403, "192.168.0.17:1": 403} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/v1/who", nil)
		req.RemoteAddr = remote
		h.ServeHTTP(rec, req)
		if rec.Code != want {
			t.Errorf("%s: %d, want %d", remote, rec.Code, want)
		}
		if want == 200 && rec.Body.String() != "nod_nl" {
			t.Errorf("peer id %q", rec.Body.String())
		}
	}
}

func TestProbeAndStatus(t *testing.T) {
	m := testMesh(t)
	hs := time.Now().Add(-30 * time.Second)
	pk, _ := wgtypes.ParseKey(key)
	m.Device = func(string) (*wgtypes.Device, error) {
		return &wgtypes.Device{Peers: []wgtypes.Peer{{PublicKey: pk, LastHandshakeTime: hs}}}, nil
	}
	if m.Up("nod_nl") {
		t.Fatal("unprobed peer counted up")
	}
	// Serve the peer's API on a test server and point the probe at it.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, `{"ok":true}`) }))
	defer srv.Close()
	m.client.Transport = rewrite{srv.Listener.Addr().String()}
	m.probe(context.Background(), "nod_nl")
	if !m.Up("nod_nl") {
		t.Fatalf("peer down after successful probe: %s", m.LastError("nod_nl"))
	}
	st := m.Status()
	if len(st) != 1 || !st[0].Up || !st[0].LastHandshake.Equal(hs) || st[0].RTTMillis <= 0 {
		t.Errorf("status %+v", st)
	}
	m.MarkDown("nod_nl", nil)
	if m.Up("nod_nl") {
		t.Error("MarkDown ignored")
	}
	srv.Close()
	m.probe(context.Background(), "nod_nl")
	m.probe(context.Background(), "nod_nl")
	if m.Up("nod_nl") || m.Status()[0].Up {
		t.Error("peer up after failed probes")
	}
}

// rewrite sends every request to addr.
type rewrite struct{ addr string }

func (r rewrite) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	req.URL.Host = r.addr
	return http.DefaultTransport.RoundTrip(req)
}

func TestEnsureKey(t *testing.T) {
	st := secrets.NewMemory(nil)
	if _, err := PublicKey(st); err == nil {
		t.Fatal("public key without a private key")
	}
	ch, err := EnsureKey(st)
	if err != nil || !ch {
		t.Fatal(ch, err)
	}
	pub, err := PublicKey(st)
	if err != nil || len(pub) != 44 {
		t.Fatal(pub, err)
	}
	if ch, _ := EnsureKey(st); ch {
		t.Error("key regenerated")
	}
	if again, _ := PublicKey(st); again != pub {
		t.Error("public key changed")
	}
}

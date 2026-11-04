// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ingressd/ingressd/internal/connector/proto"
	"github.com/ingressd/ingressd/pkg/release"
)

func TestUpdateNoticeAndRelay(t *testing.T) {
	bin := []byte("connector v1.1.0")
	sum := sha256.Sum256(bin)
	fetches := 0
	src := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetches++
		if r.URL.Path != "/dl/ingressd-connector_linux_arm64" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(bin)
	}))
	defer src.Close()
	m := release.Manifest{Version: "v1.1.0", Channel: "stable", Assets: map[string]string{"ingressd-connector_linux_arm64": hex.EncodeToString(sum[:])}}
	s := &Server{Store: NewStore(t.TempDir())}
	if err := s.OfferUpdate("home", proto.UpdateNotice{ID: "upg_a", Version: "v1.1.0", Manifest: string(m.Encode()), Sources: []string{src.URL + "/dl"}}); err != nil {
		t.Fatal(err)
	}

	poll := func(q string) *proto.UpdateNotice {
		return s.pendingUpdate(httptest.NewRequest("GET", proto.PollPath+q, nil), "home")
	}
	if poll("?rev=1") != nil {
		t.Error("notice sent to a connector without update support")
	}
	if n := poll("?rev=1&upd="); n == nil || n.ID != "upg_a" {
		t.Errorf("notice not delivered: %+v", n)
	}
	if poll("?upd=upg_a") != nil {
		t.Error("handled notice delivered again")
	}
	if s.pendingUpdate(httptest.NewRequest("GET", proto.PollPath+"?upd=", nil), "other") != nil {
		t.Error("notice delivered to another tunnel")
	}

	get := func(asset string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", proto.ReleasePathPrefix+asset, nil)
		r = r.WithContext(context.WithValue(r.Context(), tunnelPeerKey{}, "home"))
		w := httptest.NewRecorder()
		s.serveRelease(w, r)
		return w
	}
	for i := 0; i < 2; i++ {
		if w := get("ingressd-connector_linux_arm64"); w.Code != 200 || w.Body.String() != string(bin) {
			t.Fatalf("relay: %d %q", w.Code, w.Body.String())
		}
	}
	if fetches != 1 {
		t.Errorf("relay fetched %d times, want 1 (cached)", fetches)
	}
	if w := get("ingressd_linux_amd64"); w.Code != 404 {
		t.Errorf("asset outside the manifest: %d", w.Code)
	}
	// A source serving other bytes is refused.
	m.Assets["ingressd-connector_darwin_arm64"] = hex.EncodeToString(sum[:])
	_ = s.OfferUpdate("home", proto.UpdateNotice{ID: "upg_b", Version: "v1.1.0", Manifest: string(m.Encode()), Sources: []string{src.URL + "/nope"}})
	if w := get("ingressd-connector_darwin_arm64"); w.Code != http.StatusBadGateway {
		t.Errorf("bad source: %d", w.Code)
	}
}

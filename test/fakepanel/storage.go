// SPDX-License-Identifier: Apache-2.0

package fakepanel

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/coder/websocket"

	"github.com/ingressd/ingressd/internal/storagerelay"
	"github.com/ingressd/ingressd/pkg/nodeproto"
)

// Shared certificate storage: the fake panel answers storage_request from
// memory with the panel's semantics, so managed-mode e2e suites (whose
// Caddy uses caddy.storage.ingressd) keep obtaining certificates.

// Storage is the fake panel's shared certificate store (all nodes share it,
// as nodes of one org do).
func (s *Server) Storage() *storagerelay.Memory { return s.storage }

func (s *Server) handleStorage(ctx context.Context, c *websocket.Conn, env nodeproto.Envelope, scope string) {
	var req nodeproto.StorageRequest
	res := nodeproto.StorageResponse{Error: "bad storage request"}
	if env.Decode(&req) == nil {
		res = s.storage.Handle(scope, req)
	}
	b, err := nodeproto.Encode(nodeproto.TypeStorageResponse, env.ID, res)
	if err != nil {
		return
	}
	go func() { _ = c.Write(ctx, websocket.MessageText, b) }()
}

// storageAPI adds GET /test/storage (stored keys, for assertions).
func (s *Server) storageAPI(mux *http.ServeMux) {
	mux.HandleFunc("GET /test/storage", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string][]string{"keys": s.storage.Keys()})
	})
}

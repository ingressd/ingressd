// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"log/slog"
	"path/filepath"

	"github.com/ingressd/ingressd/internal/controlsrv"
	"github.com/ingressd/ingressd/internal/nodeagent"
	"github.com/ingressd/ingressd/internal/render"
	"github.com/ingressd/ingressd/internal/storagerelay"
)

// Shared certificate storage (docs/rev1/CERT-STORAGE.md): in managed mode
// Caddy stores certificates in the panel through the relay on
// storage.sock; standalone nodes keep file_system storage.

func (e *env) storageSocket() string { return filepath.Join(e.runDir, "storage.sock") }
func (e *env) caddyStorageDir() string {
	return filepath.Join(e.stateDir, "caddy")
}

// managedStorageSocket is the render option for the current mode: the
// relay socket while node.json exists, "" (file_system) otherwise.
func (e *env) managedStorageSocket() string {
	if nodeagent.Managed(e.stateDir) {
		return e.storageSocket()
	}
	return ""
}

// startStorageRelay serves the storage relay. It answers 503 until managed
// mode sets the agent as its backend.
func startStorageRelay(ctx context.Context, e *env, log *slog.Logger) *storagerelay.Server {
	s := &storagerelay.Server{
		CacheDir:      e.caddyStorageDir(),
		LocalPrefixes: render.StorageLocalPrefixes,
		MarkerPath:    filepath.Join(e.stateDir, "caddy-storage-uploaded"),
		Log:           log.With("component", "storage"),
	}
	go func() {
		if err := controlsrv.Serve(ctx, e.storageSocket(), s); err != nil {
			log.Error("storage relay", "err", err)
		}
	}()
	return s
}

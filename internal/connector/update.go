// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/ingressd/ingressd/internal/connector/proto"
	"github.com/ingressd/ingressd/internal/upgrade"
	"github.com/ingressd/ingressd/pkg/release"
)

// Connector self-update, edge side (proto/update.go): the node keeps the
// panel's update notice per tunnel in connector.json, hands it to the
// connector on its next poll and relays release downloads for it.

// ReleaseCacheDir holds binaries relayed to connectors, per version.
const ReleaseCacheDir = "connector-releases"

// SetUpdateNotice stores (or with nil clears) a tunnel's update notice.
func (s *Store) SetUpdateNotice(tunnel string, n *proto.UpdateNotice) error {
	return s.Update(func(st *State) error {
		if n == nil {
			delete(st.Updates, tunnel)
			return nil
		}
		if st.Updates == nil {
			st.Updates = map[string]*proto.UpdateNotice{}
		}
		st.Updates[tunnel] = n
		return nil
	})
}

// UpdateNotice returns a tunnel's update notice, or nil.
func (s *Store) UpdateNotice(tunnel string) *proto.UpdateNotice {
	st, err := s.Load()
	if err != nil || st.Updates == nil {
		return nil
	}
	return st.Updates[tunnel]
}

// OfferUpdate stores a notice (already verified by the caller) and wakes
// the tunnel's polls so the connector sees it now.
func (s *Server) OfferUpdate(tunnel string, n proto.UpdateNotice) error {
	if err := s.Store.SetUpdateNotice(tunnel, &n); err != nil {
		return err
	}
	s.wake()
	return nil
}

// pendingUpdate returns the notice to deliver on this poll: only to
// connectors that send the update parameter, and only one they have not
// handled yet.
func (s *Server) pendingUpdate(r *http.Request, tunnel string) *proto.UpdateNotice {
	q := r.URL.Query()
	if !q.Has(proto.UpdateParam) {
		return nil
	}
	n := s.Store.UpdateNotice(tunnel)
	if n == nil || n.ID == q.Get(proto.UpdateParam) {
		return nil
	}
	return n
}

// serveRelease relays a release asset of the tunnel's current notice: fetched
// once from the notice's sources into the cache and checked against the
// manifest (the node verified the manifest's signature when the notice
// arrived), so a connector that cannot reach the download sources itself
// still updates.
func (s *Server) serveRelease(w http.ResponseWriter, r *http.Request) {
	tunnel, ok := s.authorize(w, r)
	if !ok {
		return
	}
	asset := strings.TrimPrefix(r.URL.Path, proto.ReleasePathPrefix)
	n := s.Store.UpdateNotice(tunnel)
	if n == nil || asset == "" || strings.ContainsAny(asset, `/\`) || strings.HasPrefix(asset, ".") {
		http.NotFound(w, r)
		return
	}
	var m release.Manifest
	if err := json.Unmarshal([]byte(n.Manifest), &m); err != nil {
		http.Error(w, "bad manifest", http.StatusInternalServerError)
		return
	}
	sum, ok := m.Asset(asset)
	if !ok {
		http.NotFound(w, r)
		return
	}
	dir := filepath.Join(filepath.Dir(s.Store.Path), ReleaseCacheDir, filepath.Base(m.Version))
	path := filepath.Join(dir, asset)
	if err := s.fetchRelease(r.Context(), n.Sources, asset, sum, dir, path); err != nil {
		s.log().Warn("connector release relay", "tunnel", tunnel, "asset", asset, "err", err)
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	f, err := os.Open(path) //nolint:gosec // G703: asset is a bare name (no separators or leading dot) listed in the signed manifest
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer f.Close()
	if fi, err := f.Stat(); err == nil {
		w.Header().Set("Content-Length", strconv.FormatInt(fi.Size(), 10))
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	_, _ = io.Copy(w, f)
}

func (s *Server) fetchRelease(ctx context.Context, sources []string, asset, sum, dir, path string) error {
	s.relMu.Lock()
	defer s.relMu.Unlock()
	if _, err := os.Stat(path); err == nil { //nolint:gosec // G703: asset is a bare name (no separators or leading dot) listed in the signed manifest
		return nil // verified when it was cached
	}
	if len(sources) == 0 {
		return errors.New("the update notice has no download sources")
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	tmp := path + ".part"
	if err := upgrade.FetchVerified(ctx, nil, sources, asset, sum, tmp, 0); err != nil {
		return err
	}
	return os.Rename(tmp, path) //nolint:gosec // G703: asset is a bare name (no separators or leading dot) listed in the signed manifest
}

// PruneReleaseCache removes cached releases other than keep.
func (s *Server) PruneReleaseCache(keep map[string]bool) {
	dir := filepath.Join(filepath.Dir(s.Store.Path), ReleaseCacheDir)
	ents, _ := os.ReadDir(dir)
	for _, e := range ents {
		if !keep[e.Name()] {
			_ = os.RemoveAll(filepath.Join(dir, e.Name()))
		}
	}
}

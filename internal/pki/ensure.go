// SPDX-License-Identifier: Apache-2.0

package pki

import (
	"bytes"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/ingressd/ingressd/internal/secrets"
	"github.com/ingressd/ingressd/pkg/config"
)

// EnsureOptions locates the files Ensure maintains.
type EnsureOptions struct {
	// ConfigDir holds the git-tracked inventory (InventoryFile).
	ConfigDir string
	// StateDir gets pki/edge-client-<serial>.{crt,key} for the edge's mTLS
	// client certificate (Caddy only loads client certificates from files).
	StateDir string
	// DryRun generates missing material in memory only.
	DryRun bool
}

// Ensure prepares everything the renderer needs for origin TLS and stores
// it in cfg.Certificates.OriginCA.Runtime: when the Origin CA is enabled it
// generates the CA on first use, issues or rotates the edge client
// certificate and writes it for the edge; it also resolves custom CA
// secrets. Changed secrets are saved and the inventory updated (not in a
// dry run).
func Ensure(cfg *config.Config, st *secrets.Store, o EnsureOptions) error {
	rt := &config.OriginTLSRuntime{CustomCAs: map[string]string{}}
	cfg.Certificates.OriginCA.Runtime = rt
	for _, name := range sortedApps(cfg) {
		t := cfg.EffectiveOriginTLS(cfg.Apps[name])
		sec, ok := t.CustomCASecret()
		if t.Origin != config.OriginTLSStrict || !ok {
			continue
		}
		v, err := st.Resolve(secrets.RefPrefix + sec)
		if err != nil {
			return fmt.Errorf("apps.%s.tls.verify_with: %w", name, err)
		}
		if _, err := ParseCertsPEM([]byte(v)); err != nil {
			return fmt.Errorf("apps.%s.tls.verify_with: secret %q: %w", name, sec, err)
		}
		rt.CustomCAs[sec] = v
	}
	if !cfg.Certificates.OriginCA.Enabled {
		return nil
	}

	now := time.Now()
	ca, created, err := LoadOrInit(st, cfg.Certificates.OriginCA.CommonName)
	if err != nil {
		return err
	}
	rotated, err := ca.EnsureEdgeClient(st, cfg.Edge.Name, now)
	if err != nil {
		return err
	}
	rt.TrustPEM = string(ca.OriginTrustPEM())
	chain, key, err := ca.EdgeClientPEM()
	if err != nil {
		return err
	}
	dir := filepath.Join(o.StateDir, "pki")
	base := filepath.Join(dir, "edge-client-"+SerialHex(ca.EdgeClient.SerialNumber))
	rt.ClientCertFile, rt.ClientKeyFile = base+".crt", base+".key"
	if o.DryRun {
		return nil
	}

	if created || rotated {
		if err := st.Save(); err != nil {
			return err
		}
	}
	inv, err := LoadInventory(o.ConfigDir)
	if err != nil {
		return err
	}
	if inv.SyncCA(ca) {
		if err := inv.Save(o.ConfigDir); err != nil {
			return err
		}
	}
	return writeClientFiles(dir, o.StateDir, rt.ClientCertFile, rt.ClientKeyFile, chain, key, now)
}

// writeClientFiles writes the edge client certificate for the edge process,
// owned like <state-dir>/caddy so the edge user can read it, and removes
// files of expired certificates.
func writeClientFiles(dir, stateDir, certFile, keyFile string, chain, key []byte, now time.Time) error {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	owner := filepath.Join(stateDir, "caddy")
	if err := copyOwner(owner, dir); err != nil {
		return err
	}
	for _, f := range []struct {
		path string
		data []byte
	}{{certFile, chain}, {keyFile, key}} {
		if cur, err := os.ReadFile(f.path); err == nil && bytes.Equal(cur, f.data) {
			continue
		}
		tmp := f.path + ".tmp"
		if err := os.WriteFile(tmp, f.data, 0o640); err != nil {
			return err
		}
		if err := copyOwner(owner, tmp); err != nil {
			return err
		}
		if err := os.Rename(tmp, f.path); err != nil {
			return err
		}
	}
	// Keep superseded certificates until they expire: the last applied
	// Caddy config (used for rollback) may still reference them.
	old, _ := filepath.Glob(filepath.Join(dir, "edge-client-*.crt"))
	for _, p := range old {
		if p == certFile {
			continue
		}
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		if cs, err := ParseCertsPEM(b); err == nil && now.After(cs[0].NotAfter) {
			_ = os.Remove(p)
			_ = os.Remove(strings.TrimSuffix(p, ".crt") + ".key")
		}
	}
	return nil
}

func sortedApps(cfg *config.Config) []string { return slices.Sorted(maps.Keys(cfg.Apps)) }

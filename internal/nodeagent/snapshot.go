// SPDX-License-Identifier: Apache-2.0

package nodeagent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"filippo.io/age"
	"filippo.io/age/armor"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"gopkg.in/yaml.v3"

	"github.com/ingressd/ingressd/internal/pipeline"
	"github.com/ingressd/ingressd/internal/secrets"
	"github.com/ingressd/ingressd/pkg/config"
	"github.com/ingressd/ingressd/pkg/nodeproto"
)

// MeshKeyName is the secret holding the node's WireGuard mesh private key
// (consumed by internal/mesh; its public key goes into hello).
const MeshKeyName = "wg-mesh-node"

// reservedSecret reports names a snapshot may not set or remove: keys the
// node generates itself.
func reservedSecret(name string) bool {
	return name == MeshKeyName || (strings.HasPrefix(name, "wg-") && (strings.HasSuffix(name, "-edge") || strings.HasSuffix(name, "-site")))
}

func configSHA(yaml string) string {
	h := sha256.Sum256([]byte(yaml))
	return hex.EncodeToString(h[:])
}

// dropNodeOnly removes settings the panel never compiles from a snapshot's
// config and names them: the node's own backups, alerts, CrowdSec and mail
// delivery, which send node data to destinations named in the config and
// are not the panel's to choose. Mail falls back to the panel provider,
// which is what the panel compiles. A config without them comes back
// byte for byte.
func dropNodeOnly(y string) (string, []string) {
	var doc yaml.Node
	if yaml.Unmarshal([]byte(y), &doc) != nil || len(doc.Content) != 1 || doc.Content[0].Kind != yaml.MappingNode {
		return y, nil // validation reports it
	}
	root := doc.Content[0]
	var dropped []string
	remove := func(m *yaml.Node, key, path string) {
		for i := 0; i+1 < len(m.Content); i += 2 {
			if m.Content[i].Value == key {
				m.Content = slices.Delete(m.Content, i, i+2)
				dropped = append(dropped, path)
				return
			}
		}
	}
	lookup := func(m *yaml.Node, key string) *yaml.Node {
		for i := 0; i+1 < len(m.Content); i += 2 {
			if m.Content[i].Value == key && m.Content[i+1].Kind == yaml.MappingNode {
				return m.Content[i+1]
			}
		}
		return nil
	}
	remove(root, "backups", "backups")
	remove(root, "alerts", "alerts")
	if e := lookup(root, "edge"); e != nil {
		remove(e, "crowdsec", "edge.crowdsec")
	}
	if e := lookup(root, "email"); e != nil {
		for i := 0; i+1 < len(e.Content); i += 2 {
			if v := e.Content[i+1].Value; e.Content[i].Value == "provider" && (v == config.EmailSES || v == config.EmailSMTP) {
				e.Content = []*yaml.Node{
					{Kind: yaml.ScalarNode, Value: "provider"},
					{Kind: yaml.ScalarNode, Value: config.EmailPanel},
				}
				dropped = append(dropped, "email")
				break
			}
		}
	}
	if len(dropped) == 0 {
		return y, nil
	}
	b, err := yaml.Marshal(&doc)
	if err != nil {
		return y, nil
	}
	return string(b), dropped
}

// hasNodeOnly reports settings dropNodeOnly should have removed, for config
// that reaches them some other way than a plain key (YAML merges).
func hasNodeOnly(c *config.Config) bool {
	b := c.Backups
	return b.Schedule != "" || b.LocalDir != "" || b.Passphrase != "" || b.S3 != nil || b.GitRemote != "" ||
		len(c.Alerts.Channels) > 0 || c.Edge.CrowdSec != nil ||
		c.Email.Provider == config.EmailSES || c.Email.Provider == config.EmailSMTP
}

func (a *Agent) snapshotWorker(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case job := <-a.snapshots:
			res := a.applySnapshot(ctx, job.s, job.received)
			if err := a.send(nodeproto.TypeApplied, job.id, res); err != nil {
				a.log.Warn("could not report applied", "revision", res.Revision, "err", err)
			}
			a.nudgeStatus()
		}
	}
}

// ApplySnapshot verifies and applies one snapshot. On any failure the
// previous config and secrets stay in effect (the pipeline restores the
// files and the apply engine rolls the system back).
func (a *Agent) ApplySnapshot(ctx context.Context, s nodeproto.Snapshot) nodeproto.Applied {
	return a.applySnapshot(ctx, s, time.Now())
}

// applySnapshot is ApplySnapshot with the signature validity checked at
// received (when the snapshot arrived).
func (a *Agent) applySnapshot(ctx context.Context, s nodeproto.Snapshot, received time.Time) nodeproto.Applied {
	res := nodeproto.Applied{Revision: s.Revision}
	fail := func(format string, args ...any) nodeproto.Applied {
		res.Error = fmt.Sprintf(format, args...)
		a.log.Warn("snapshot rejected", "revision", s.Revision, "err", res.Error)
		return res
	}
	st := a.State()
	// v2 only: bound to this node and org, within its validity window. The
	// legacy v1 signature (replayable anywhere, any time) is never accepted.
	if err := nodeproto.VerifyV2(s, st.OrgSigningKey, st.NodeID, st.OrgID, received); err != nil {
		return fail("rejected: %v", err)
	}
	// A forced snapshot bypasses the revision check, so it must not be
	// applied twice (replay within its validity window).
	if s.Force && !a.replay.add("snap:"+s.Signature, s.ExpiresAt, time.Now()) {
		return fail("rejected: replayed forced snapshot (revision %d)", s.Revision)
	}
	if !s.Force && s.Revision <= st.AppliedRevision {
		if s.Revision == st.AppliedRevision && snapshotSHA(s) == st.AppliedSnapshotSHA {
			res.OK = true // redelivery of what is already applied
			return res
		}
		return fail("rejected: revision %d is not newer than the applied revision %d", s.Revision, st.AppliedRevision)
	}
	id, err := secrets.LoadIdentity(a.o.KeyPath)
	if err != nil {
		return fail("%v", err)
	}
	plain := make(map[string]string, len(s.Secrets))
	for name, ct := range s.Secrets {
		if reservedSecret(name) {
			return fail("secret %q is generated by the node and cannot be set by the panel", name)
		}
		if !secrets.ValidName(name) {
			return fail("invalid secret name %q", name)
		}
		v, err := DecryptSecret(ct, id)
		if err != nil {
			return fail("secret %q: %v", name, err)
		}
		plain[name] = v
	}
	for _, name := range s.RemoveSecrets {
		if reservedSecret(name) {
			return fail("secret %q is generated by the node and cannot be removed by the panel", name)
		}
	}
	configYAML, dropped := dropNodeOnly(s.ConfigYAML)
	if len(dropped) > 0 {
		a.log.Warn("snapshot: ignoring settings the panel does not manage", "revision", s.Revision, "settings", dropped)
	}
	cfg, err := pipeline.Validate([]byte(configYAML))
	if err != nil {
		return fail("%v", err)
	}
	if hasNodeOnly(cfg) {
		return fail("rejected: config sets node-only settings (backups, alerts, edge.crowdsec or email delivery)")
	}
	// Never let the panel firewall off this node's SSH port (lockout).
	if st.SSHPort != 0 && (cfg.Edge.ManageFirewall == nil || *cfg.Edge.ManageFirewall) && cfg.Edge.SSHPort != st.SSHPort {
		return fail("rejected: edge.ssh_port is %d but sshd on this node listens on %d; the managed firewall would lock you out", cfg.Edge.SSHPort, st.SSHPort)
	}
	actx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	r, err := a.o.Pipeline.Apply(actx, pipeline.Change{
		Edit: func([]byte) ([]byte, error) { return []byte(configYAML), nil },
		Secrets: func(st *secrets.Store) error {
			for name, v := range plain {
				if err := st.Set(name, v); err != nil {
					return err
				}
			}
			for _, name := range s.RemoveSecrets {
				st.Delete(name)
			}
			return nil
		},
		Author:  "panel",
		Message: fmt.Sprintf("Apply panel revision %d", s.Revision),
		Force:   s.Force,
	})
	if err != nil {
		return fail("apply failed, previous configuration kept: %v", err)
	}
	a.mu.Lock()
	a.state.AppliedRevision = s.Revision
	a.state.AppliedConfigSHA = configSHA(configYAML)
	a.state.AppliedSnapshotSHA = snapshotSHA(s)
	cp := *a.state
	a.mu.Unlock()
	if Managed(a.o.StateDir) {
		if err := SaveState(a.o.StateDir, &cp); err != nil {
			a.log.Error("saving node.json", "err", err)
		}
	}
	_ = writeFileAtomic(filepath.Join(a.o.StateDir, SnapshotFile), []byte(configYAML), 0o600)
	a.log.Info("applied panel snapshot", "revision", s.Revision, "changed", r.Applied)
	if a.o.OnApplied != nil && r.Config != nil {
		a.o.OnApplied(r.Config)
	}
	res.OK = true
	return res
}

// DecryptSecret decrypts an age ciphertext (armored, or binary) with the
// node's identity.
func DecryptSecret(ct string, id age.Identity) (string, error) {
	var src io.Reader = strings.NewReader(ct)
	if strings.HasPrefix(strings.TrimSpace(ct), armor.Header) {
		src = armor.NewReader(strings.NewReader(strings.TrimSpace(ct)))
	}
	r, err := age.Decrypt(src, id)
	if err != nil {
		return "", err
	}
	b, err := io.ReadAll(io.LimitReader(r, 1<<20))
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// EncryptSecret encrypts plaintext to an age recipient, armored (what the
// panel's browser code produces; used by tests and the fake panel).
func EncryptSecret(plaintext, recipient string) (string, error) {
	rcpt, err := age.ParseX25519Recipient(recipient)
	if err != nil {
		return "", err
	}
	var buf bytes.Buffer
	aw := armor.NewWriter(&buf)
	w, err := age.Encrypt(aw, rcpt)
	if err != nil {
		return "", err
	}
	if _, err := io.WriteString(w, plaintext); err != nil {
		return "", err
	}
	if err := w.Close(); err != nil {
		return "", err
	}
	if err := aw.Close(); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// ensureMeshKey returns the mesh public key, generating the private key in
// the secrets store on first use.
func (a *Agent) ensureMeshKey() (string, error) {
	if a.o.Pipeline == nil {
		return "", errors.New("no pipeline")
	}
	var pub string
	err := a.o.Pipeline.WithSecrets(func(st *secrets.Store) error {
		if v, ok := st.Get(MeshKeyName); ok {
			k, err := wgtypes.ParseKey(v)
			if err != nil {
				return err
			}
			pub = k.PublicKey().String()
		}
		return nil
	})
	if err != nil || pub != "" {
		return pub, err
	}
	_, err = a.o.Pipeline.UpdateSecrets("ingressd", "Generate node mesh key", func(st *secrets.Store) error {
		if v, ok := st.Get(MeshKeyName); ok { // raced with another writer
			k, err := wgtypes.ParseKey(v)
			if err != nil {
				return err
			}
			pub = k.PublicKey().String()
			return nil
		}
		k, err := wgtypes.GeneratePrivateKey()
		if err != nil {
			return err
		}
		pub = k.PublicKey().String()
		return st.Set(MeshKeyName, k.String())
	})
	return pub, err
}

// RestoreSnapshotConfig puts the last applied snapshot's config back if
// config.yaml was edited locally while managed (the panel is the source of
// truth). It reports whether it restored the file.
func RestoreSnapshotConfig(stateDir, configPath string) (bool, error) {
	st, err := LoadState(stateDir)
	if err != nil || st.AppliedConfigSHA == "" {
		return false, err
	}
	snap, err := os.ReadFile(filepath.Join(stateDir, SnapshotFile))
	if err != nil || configSHA(string(snap)) != st.AppliedConfigSHA {
		return false, nil
	}
	cur, err := os.ReadFile(configPath)
	if err == nil && configSHA(string(cur)) == st.AppliedConfigSHA {
		return false, nil
	}
	return true, writeFileAtomic(configPath, snap, 0o640)
}

// snapshotSHA identifies a snapshot's content (revision, config, secrets
// and removals; not the force flag or signature time).
func snapshotSHA(s nodeproto.Snapshot) string {
	s.Force = false
	return hex.EncodeToString(nodeproto.SnapshotSigningPayload(s))
}

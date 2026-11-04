// SPDX-License-Identifier: Apache-2.0

// Package backup exports the edge's configuration, secrets and history to
// a .tar.gz archive, restores it onto a fresh machine, and runs scheduled
// backups (local rotation, S3-compatible storage, git remote) — PLAN §4.5.
//
// Archive layout:
//
//	manifest.json    Manifest (format, version, secrets mode, SHA-256 of each file)
//	config.yaml      the live config file
//	secrets.age      secrets, encrypted to the edge key ("key" mode) or to a
//	                 passphrase ("passphrase" mode); absent with --no-secrets
//	history.bundle   git bundle of the config repository (all refs)
package backup

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"filippo.io/age"

	"github.com/ingressd/ingressd/internal/safefs"
	"github.com/ingressd/ingressd/internal/secrets"
)

const (
	ManifestFile = "manifest.json"
	ConfigFile   = "config.yaml"
	SecretsFile  = "secrets.age"
	BundleFile   = "history.bundle"

	// FormatVersion is the archive format written by Export.
	FormatVersion = 1
	maxArchive    = 512 << 20
)

// Secrets modes recorded in the manifest.
const (
	SecretsKey        = "key"        // encrypted to the edge's age key; restore needs that key file
	SecretsPassphrase = "passphrase" // encrypted to a passphrase (age scrypt)
	SecretsNone       = "none"       // config-only export
)

// Manifest describes an archive.
type Manifest struct {
	Format  int       `json:"format"`
	Created time.Time `json:"created"`
	Version string    `json:"ingressd_version"`
	// LegacyVersion is the version key of archives made before the rename.
	LegacyVersion string            `json:"homeedge_version,omitempty"` // legacy homeedge name, remove after 2027-01
	Edge          string            `json:"edge,omitempty"`
	Secrets       string            `json:"secrets"`
	Head          string            `json:"head,omitempty"` // config repo HEAD at export time
	Files         map[string]string `json:"files"`          // name → SHA-256 (hex)
}

// ExportOptions select what goes into an archive.
type ExportOptions struct {
	ConfigDir string
	KeyPath   string
	// Passphrase re-encrypts the secrets to an age scrypt recipient so the
	// archive restores without the key file.
	Passphrase string
	NoSecrets  bool
	Version    string
	Edge       string
	Now        time.Time
}

// Export writes an archive to w.
func Export(w io.Writer, o ExportOptions) (*Manifest, error) {
	if o.Now.IsZero() {
		o.Now = time.Now()
	}
	m := &Manifest{Format: FormatVersion, Created: o.Now.UTC(), Version: o.Version, Edge: o.Edge,
		Secrets: SecretsNone, Files: map[string]string{}}
	files := map[string][]byte{}

	cfg, err := os.ReadFile(filepath.Join(o.ConfigDir, ConfigFile))
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	files[ConfigFile] = cfg

	if !o.NoSecrets {
		sec, err := os.ReadFile(filepath.Join(o.ConfigDir, SecretsFile))
		switch {
		case errors.Is(err, fs.ErrNotExist):
			// No secrets yet: nothing to include.
		case err != nil:
			return nil, err
		case o.Passphrase != "":
			if sec, err = reencryptToPassphrase(sec, o.KeyPath, o.Passphrase); err != nil {
				return nil, err
			}
			files[SecretsFile], m.Secrets = sec, SecretsPassphrase
		default:
			files[SecretsFile], m.Secrets = sec, SecretsKey
		}
	}

	if b, head, err := gitBundle(o.ConfigDir); err != nil {
		return nil, err
	} else if b != nil {
		files[BundleFile], m.Head = b, head
	}

	for name, b := range files {
		sum := sha256.Sum256(b)
		m.Files[name] = hex.EncodeToString(sum[:])
	}
	mb, _ := json.MarshalIndent(m, "", "  ")

	gz := gzip.NewWriter(w)
	tw := tar.NewWriter(gz)
	add := func(name string, b []byte) error {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: int64(len(b)), ModTime: o.Now, Typeflag: tar.TypeReg}); err != nil {
			return err
		}
		_, err := tw.Write(b)
		return err
	}
	if err := add(ManifestFile, mb); err != nil {
		return nil, err
	}
	for _, name := range []string{ConfigFile, SecretsFile, BundleFile} {
		if b, ok := files[name]; ok {
			if err := add(name, b); err != nil {
				return nil, err
			}
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	return m, gz.Close()
}

func reencryptToPassphrase(sec []byte, keyPath, passphrase string) ([]byte, error) {
	id, err := secrets.LoadIdentity(keyPath)
	if err != nil {
		return nil, err
	}
	r, err := age.Decrypt(bytes.NewReader(sec), id)
	if err != nil {
		return nil, fmt.Errorf("decrypt secrets: %w", err)
	}
	plain, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	rcp, err := age.NewScryptRecipient(passphrase)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, rcp)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(plain); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func git(dir string, args ...string) (string, error) {
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0", "LC_ALL=C")
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		return out.String(), fmt.Errorf("git %s: %w: %s", args[0], err, strings.TrimSpace(errb.String()))
	}
	return strings.TrimSpace(out.String()), nil
}

// gitBundle bundles all refs of the repo in dir; nil if there is no repo
// or no commit yet.
func gitBundle(dir string) ([]byte, string, error) {
	if _, err := os.Stat(filepath.Join(dir, ".git")); err != nil {
		return nil, "", nil
	}
	head, err := git(dir, "rev-parse", "HEAD")
	if err != nil {
		return nil, "", nil // no commits
	}
	tmp, err := os.MkdirTemp("", "ingressd-bundle-")
	if err != nil {
		return nil, "", err
	}
	defer os.RemoveAll(tmp)
	p := filepath.Join(tmp, BundleFile)
	if _, err := git(dir, "bundle", "create", "-q", p, "--all"); err != nil {
		return nil, "", err
	}
	b, err := os.ReadFile(p)
	return b, head, err
}

// Archive is a parsed, verified archive.
type Archive struct {
	Manifest Manifest
	Files    map[string][]byte
}

// ReadArchive parses an archive and verifies every file against the
// manifest's checksums.
func ReadArchive(r io.Reader) (*Archive, error) {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return nil, fmt.Errorf("not an ingressd backup (gzip): %w", err)
	}
	tr := tar.NewReader(io.LimitReader(gz, maxArchive))
	a := &Archive{Files: map[string][]byte{}}
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read archive: %w", err)
		}
		if h.Typeflag != tar.TypeReg {
			continue
		}
		b, err := io.ReadAll(tr)
		if err != nil {
			return nil, err
		}
		a.Files[h.Name] = b
	}
	mb, ok := a.Files[ManifestFile]
	if !ok {
		return nil, errors.New("not an ingressd backup: no manifest.json")
	}
	if err := json.Unmarshal(mb, &a.Manifest); err != nil {
		return nil, fmt.Errorf("manifest: %w", err)
	}
	if a.Manifest.Version == "" {
		a.Manifest.Version, a.Manifest.LegacyVersion = a.Manifest.LegacyVersion, ""
	}
	if a.Manifest.Format != FormatVersion {
		return nil, fmt.Errorf("unsupported backup format %d (this ingressd reads %d)", a.Manifest.Format, FormatVersion)
	}
	if _, ok := a.Files[ConfigFile]; !ok {
		return nil, errors.New("backup has no config.yaml")
	}
	for name, want := range a.Manifest.Files {
		b, ok := a.Files[name]
		if !ok {
			return nil, fmt.Errorf("backup is missing %s", name)
		}
		sum := sha256.Sum256(b)
		if hex.EncodeToString(sum[:]) != want {
			return nil, fmt.Errorf("checksum mismatch for %s: the backup is corrupt", name)
		}
	}
	for name := range a.Files {
		if name != ManifestFile && a.Manifest.Files[name] == "" {
			return nil, fmt.Errorf("unexpected file %s not listed in the manifest", name)
		}
	}
	return a, nil
}

// RestoreOptions control Restore.
type RestoreOptions struct {
	ConfigDir string
	KeyPath   string
	// Passphrase decrypts "passphrase"-mode secrets.
	Passphrase string
	// Force overwrites an existing config.yaml, secrets.age and history.
	Force bool
}

// RestoreResult reports what Restore did.
type RestoreResult struct {
	Manifest     Manifest
	KeyGenerated bool // a new key file was created
	Secrets      int  // number of secrets restored
}

// Restore unpacks an archive into the config directory: history from the
// bundle, the config file and the secrets (re-encrypted to the key at
// KeyPath when the archive used a passphrase). The caller applies the
// config afterwards.
func Restore(r io.Reader, o RestoreOptions) (*RestoreResult, error) {
	a, err := ReadArchive(r)
	if err != nil {
		return nil, err
	}
	res := &RestoreResult{Manifest: a.Manifest}

	if !o.Force {
		for _, name := range []string{ConfigFile, SecretsFile, ".git"} {
			if _, err := os.Stat(filepath.Join(o.ConfigDir, name)); err == nil {
				return nil, fmt.Errorf("%s already exists in %s; restore onto an empty directory or pass --force", name, o.ConfigDir)
			}
		}
	}

	// Decide on secrets before touching anything.
	var plainSecrets map[string]string
	_, keyErr := os.Stat(o.KeyPath)
	haveKey := keyErr == nil
	switch a.Manifest.Secrets {
	case SecretsKey:
		if !haveKey {
			return nil, fmt.Errorf("this backup's secrets are encrypted to the edge key, but %s does not exist: copy the original key file there (or use a backup exported with --passphrase)", o.KeyPath)
		}
		id, err := secrets.LoadIdentity(o.KeyPath)
		if err != nil {
			return nil, err
		}
		if plainSecrets, err = decryptJSON(a.Files[SecretsFile], id); err != nil {
			return nil, fmt.Errorf("%s cannot decrypt this backup's secrets (wrong key?): %w", o.KeyPath, err)
		}
	case SecretsPassphrase:
		if o.Passphrase == "" {
			return nil, errors.New("this backup's secrets are protected by a passphrase: pass --passphrase")
		}
		id, err := age.NewScryptIdentity(o.Passphrase)
		if err != nil {
			return nil, err
		}
		if plainSecrets, err = decryptJSON(a.Files[SecretsFile], id); err != nil {
			return nil, fmt.Errorf("wrong passphrase: %w", err)
		}
	case SecretsNone:
	default:
		return nil, fmt.Errorf("unknown secrets mode %q", a.Manifest.Secrets)
	}

	if err := os.MkdirAll(o.ConfigDir, 0o750); err != nil {
		return nil, err
	}
	if o.Force {
		for _, name := range []string{ConfigFile, SecretsFile, ".git"} {
			if err := os.RemoveAll(filepath.Join(o.ConfigDir, name)); err != nil {
				return nil, err
			}
		}
	}

	if err := initRepo(o.ConfigDir, a.Files[BundleFile]); err != nil {
		return nil, err
	}
	// safefs.WriteFile refuses a symlink (or other non-regular file) at the
	// path and writes via rename, never through a link.
	if err := safefs.WriteFile(filepath.Join(o.ConfigDir, ConfigFile), a.Files[ConfigFile], 0o640); err != nil {
		return nil, err
	}

	if !haveKey {
		if err := secrets.GenerateIdentity(o.KeyPath); err != nil {
			return nil, err
		}
		res.KeyGenerated = true
	}
	secPath := filepath.Join(o.ConfigDir, SecretsFile)
	switch a.Manifest.Secrets {
	case SecretsKey:
		// Keep the original ciphertext (and any extra recipients).
		if err := safefs.WriteFile(secPath, a.Files[SecretsFile], 0o600); err != nil {
			return nil, err
		}
	case SecretsPassphrase:
		id, err := secrets.LoadIdentity(o.KeyPath)
		if err != nil {
			return nil, err
		}
		_ = os.Remove(secPath)
		st, err := secrets.Open(secPath, id)
		if err != nil {
			return nil, err
		}
		for k, v := range plainSecrets {
			if err := st.Set(k, v); err != nil {
				return nil, err
			}
		}
		if err := st.Save(); err != nil {
			return nil, err
		}
	}
	res.Secrets = len(plainSecrets)

	paths := []string{ConfigFile}
	if _, err := os.Stat(secPath); err == nil {
		paths = append(paths, SecretsFile)
	}
	if _, err := git(o.ConfigDir, append([]string{"add", "--"}, paths...)...); err != nil {
		return nil, err
	}
	if _, err := git(o.ConfigDir, "diff", "--cached", "--quiet"); err != nil {
		msg := "Restore from backup of " + a.Manifest.Created.Format(time.RFC3339)
		if _, err := git(o.ConfigDir, "commit", "-q", "--author", "ingressd <ingressd@ingressd.local>", "-m", msg); err != nil {
			return nil, err
		}
	}
	return res, nil
}

func decryptJSON(ciphertext []byte, id age.Identity) (map[string]string, error) {
	if ciphertext == nil {
		return nil, errors.New("backup has no secrets.age")
	}
	r, err := age.Decrypt(bytes.NewReader(ciphertext), id)
	if err != nil {
		return nil, err
	}
	b, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	m := map[string]string{}
	return m, json.Unmarshal(b, &m)
}

// initRepo creates the config repository, importing history from bundle.
func initRepo(dir string, bundle []byte) error {
	if _, err := git(dir, "init", "-q", "-b", "main"); err != nil {
		return err
	}
	// The bundle is untrusted: core.symlinks=false checks symlinks out as
	// plain files holding the target, so a restored tree never redirects
	// root's later writes (config.yaml, secrets.age) out of the directory.
	for _, kv := range [][2]string{{"user.name", "ingressd"}, {"user.email", "ingressd@localhost"}, {"core.symlinks", "false"}} {
		if _, err := git(dir, "config", kv[0], kv[1]); err != nil {
			return err
		}
	}
	if bundle == nil {
		return nil
	}
	tmp, err := os.MkdirTemp("", "ingressd-restore-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	p := filepath.Join(tmp, BundleFile)
	if err := os.WriteFile(p, bundle, 0o600); err != nil {
		return err
	}
	if _, err := git(dir, "bundle", "verify", "-q", p); err != nil {
		return err
	}
	heads, err := git(dir, "bundle", "list-heads", p)
	if err != nil {
		return err
	}
	if _, err := git(dir, "fetch", "-q", "--update-head-ok", p, "refs/heads/*:refs/heads/*"); err != nil {
		return err
	}
	// Check out the bundle's branch (main normally; else the first one).
	branch := "main"
	var branches []string
	for _, l := range strings.Split(heads, "\n") {
		if _, ref, ok := strings.Cut(l, " "); ok && strings.HasPrefix(ref, "refs/heads/") {
			branches = append(branches, strings.TrimPrefix(ref, "refs/heads/"))
		}
	}
	if len(branches) > 0 && !slices.Contains(branches, "main") {
		branch = branches[0]
		if _, err := git(dir, "symbolic-ref", "HEAD", "refs/heads/"+branch); err != nil {
			return err
		}
	}
	_, err = git(dir, "reset", "-q", "--hard", branch)
	return err
}

// SPDX-License-Identifier: Apache-2.0

package backup

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/ingressd/ingressd/internal/alerts"
	"github.com/ingressd/ingressd/internal/gitstore"
	"github.com/ingressd/ingressd/internal/secrets"
	"github.com/ingressd/ingressd/pkg/config"
)

const testConfig = "version: 1\nedge: { name: lab, acme: { ca: internal } }\n"

// setupEdge creates a config dir with history and secrets.
func setupEdge(t *testing.T) (confDir, keyPath string) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	root := t.TempDir()
	confDir, keyPath = filepath.Join(root, "conf"), filepath.Join(root, "keys", "age.key")
	repo := gitstore.Repo{Dir: confDir}
	if err := repo.Init(); err != nil {
		t.Fatal(err)
	}
	if err := secrets.GenerateIdentity(keyPath); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(confDir, "config.yaml"), []byte(testConfig), 0o640)
	if _, err := repo.Commit("test", "First", "config.yaml"); err != nil {
		t.Fatal(err)
	}
	id, _ := secrets.LoadIdentity(keyPath)
	st, _ := secrets.Open(filepath.Join(confDir, "secrets.age"), id)
	st.Set("wg-home-edge", "PRIVATE-KEY-VALUE")
	st.Set("discord", "https://discord.example/hook")
	if err := st.Save(); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(confDir, "config.yaml"), []byte(testConfig+"# second\n"), 0o640)
	if _, err := repo.Commit("test", "Second", "config.yaml", "secrets.age"); err != nil {
		t.Fatal(err)
	}
	return confDir, keyPath
}

func export(t *testing.T, o ExportOptions) []byte {
	t.Helper()
	var buf bytes.Buffer
	if _, err := Export(&buf, o); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func readSecret(t *testing.T, confDir, keyPath, name string) string {
	t.Helper()
	id, err := secrets.LoadIdentity(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	st, err := secrets.Open(filepath.Join(confDir, "secrets.age"), id)
	if err != nil {
		t.Fatal(err)
	}
	v, _ := st.Get(name)
	return v
}

func TestExportRestoreWithKey(t *testing.T) {
	confDir, keyPath := setupEdge(t)
	arc := export(t, ExportOptions{ConfigDir: confDir, KeyPath: keyPath, Version: "test", Edge: "lab"})

	a, err := ReadArchive(bytes.NewReader(arc))
	if err != nil {
		t.Fatal(err)
	}
	if a.Manifest.Secrets != SecretsKey || a.Manifest.Head == "" || a.Files[BundleFile] == nil || a.Manifest.Edge != "lab" {
		t.Fatalf("manifest = %+v", a.Manifest)
	}

	// Restoring without the key file is refused with a clear message.
	dst := filepath.Join(t.TempDir(), "conf")
	_, err = Restore(bytes.NewReader(arc), RestoreOptions{ConfigDir: dst, KeyPath: filepath.Join(t.TempDir(), "none.key")})
	if err == nil || !strings.Contains(err.Error(), "encrypted to the edge key") {
		t.Fatalf("restore without key: %v", err)
	}

	res, err := Restore(bytes.NewReader(arc), RestoreOptions{ConfigDir: dst, KeyPath: keyPath})
	if err != nil {
		t.Fatal(err)
	}
	if res.KeyGenerated || res.Secrets != 2 {
		t.Fatalf("result = %+v", res)
	}
	if b, _ := os.ReadFile(filepath.Join(dst, "config.yaml")); !strings.HasSuffix(string(b), "# second\n") {
		t.Fatalf("config = %q", b)
	}
	if v := readSecret(t, dst, keyPath, "wg-home-edge"); v != "PRIVATE-KEY-VALUE" {
		t.Fatalf("secret = %q", v)
	}
	log, err := gitstore.Repo{Dir: dst}.Log(10)
	if err != nil || len(log) != 2 || log[0].Subject != "Second" {
		t.Fatalf("history = %+v, %v", log, err)
	}

	// A second restore onto the same directory needs --force.
	if _, err := Restore(bytes.NewReader(arc), RestoreOptions{ConfigDir: dst, KeyPath: keyPath}); err == nil || !strings.Contains(err.Error(), "--force") {
		t.Fatalf("overwrite: %v", err)
	}
	if _, err := Restore(bytes.NewReader(arc), RestoreOptions{ConfigDir: dst, KeyPath: keyPath, Force: true}); err != nil {
		t.Fatalf("force: %v", err)
	}
}

// A bundle whose history checks out config.yaml and secrets.age as symlinks
// must not redirect the restore's writes out of the config directory.
func TestRestoreDoesNotFollowBundleSymlinks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks need privileges")
	}
	confDir, keyPath := setupEdge(t)
	victim := filepath.Join(t.TempDir(), "victim")
	os.WriteFile(victim, []byte("victim\n"), 0o600)
	for _, name := range []string{"config.yaml", "secrets.age"} {
		os.Remove(filepath.Join(confDir, name))
		if err := os.Symlink(victim, filepath.Join(confDir, name)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := (gitstore.Repo{Dir: confDir}).Commit("test", "Evil", "config.yaml", "secrets.age"); err != nil {
		t.Fatal(err)
	}
	a, err := ReadArchive(bytes.NewReader(export(t, ExportOptions{ConfigDir: confDir, KeyPath: keyPath, NoSecrets: true})))
	if err != nil {
		t.Fatal(err)
	}
	a.Files[ConfigFile] = []byte(testConfig + "# restored\n")
	dst := filepath.Join(t.TempDir(), "conf")
	if _, err := Restore(bytes.NewReader(rewrite(t, a)), RestoreOptions{ConfigDir: dst, KeyPath: keyPath}); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(victim); string(b) != "victim\n" {
		t.Fatalf("victim overwritten: %q", b)
	}
	fi, err := os.Lstat(filepath.Join(dst, "config.yaml"))
	if err != nil || !fi.Mode().IsRegular() {
		t.Fatalf("config.yaml: %v %v", fi, err)
	}
}

// rewrite re-packs a with a manifest matching its (modified) files.
func rewrite(t *testing.T, a *Archive) []byte {
	t.Helper()
	for name, b := range a.Files {
		if name != ManifestFile {
			sum := sha256.Sum256(b)
			a.Manifest.Files[name] = hex.EncodeToString(sum[:])
		}
	}
	mb, err := json.Marshal(a.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	a.Files[ManifestFile] = mb
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, b := range a.Files {
		tw.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: int64(len(b)), Typeflag: tar.TypeReg})
		tw.Write(b)
	}
	tw.Close()
	gz.Close()
	return buf.Bytes()
}

func TestExportRestoreWithPassphrase(t *testing.T) {
	confDir, keyPath := setupEdge(t)
	arc := export(t, ExportOptions{ConfigDir: confDir, KeyPath: keyPath, Passphrase: "correct horse"})
	a, _ := ReadArchive(bytes.NewReader(arc))
	if a.Manifest.Secrets != SecretsPassphrase {
		t.Fatalf("mode %s", a.Manifest.Secrets)
	}
	root := t.TempDir()
	dst, newKey := filepath.Join(root, "conf"), filepath.Join(root, "keys", "age.key")
	if _, err := Restore(bytes.NewReader(arc), RestoreOptions{ConfigDir: dst, KeyPath: newKey}); err == nil || !strings.Contains(err.Error(), "--passphrase") {
		t.Fatalf("no passphrase: %v", err)
	}
	if _, err := Restore(bytes.NewReader(arc), RestoreOptions{ConfigDir: dst, KeyPath: newKey, Passphrase: "wrong"}); err == nil || !strings.Contains(err.Error(), "wrong passphrase") {
		t.Fatalf("wrong passphrase: %v", err)
	}
	if _, err := os.Stat(dst); err == nil {
		t.Fatal("failed restore left files behind")
	}
	res, err := Restore(bytes.NewReader(arc), RestoreOptions{ConfigDir: dst, KeyPath: newKey, Passphrase: "correct horse"})
	if err != nil {
		t.Fatal(err)
	}
	if !res.KeyGenerated || res.Secrets != 2 {
		t.Fatalf("result = %+v", res)
	}
	if v := readSecret(t, dst, newKey, "wg-home-edge"); v != "PRIVATE-KEY-VALUE" {
		t.Fatalf("secret = %q", v)
	}
	log, _ := gitstore.Repo{Dir: dst}.Log(10)
	if len(log) != 3 || !strings.HasPrefix(log[0].Subject, "Restore from backup") {
		t.Fatalf("history = %+v", log)
	}
}

func TestExportNoSecretsAndCorruption(t *testing.T) {
	confDir, keyPath := setupEdge(t)
	arc := export(t, ExportOptions{ConfigDir: confDir, KeyPath: keyPath, NoSecrets: true})
	a, err := ReadArchive(bytes.NewReader(arc))
	if err != nil || a.Manifest.Secrets != SecretsNone || a.Files[SecretsFile] != nil {
		t.Fatalf("no-secrets: %+v %v", a, err)
	}
	if bytes.Contains(arc, []byte("PRIVATE-KEY-VALUE")) {
		t.Fatal("plaintext secret in archive")
	}

	// Tamper with config.yaml inside the archive: the checksum catches it.
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, name := range []string{ManifestFile, ConfigFile, BundleFile} {
		b := a.Files[name]
		if name == ConfigFile {
			b = []byte("version: 1\nedge: { name: evil }\n")
		}
		tw.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: int64(len(b)), Typeflag: tar.TypeReg})
		tw.Write(b)
	}
	tw.Close()
	gz.Close()
	if _, err := ReadArchive(&buf); err == nil || !strings.Contains(err.Error(), "checksum mismatch for config.yaml") {
		t.Fatalf("tampered archive: %v", err)
	}
	if _, err := ReadArchive(bytes.NewReader([]byte("garbage"))); err == nil {
		t.Fatal("garbage accepted")
	}
}

func TestSchedule(t *testing.T) {
	loc := time.UTC
	at := func(s string) time.Time { tt, _ := time.ParseInLocation("2006-01-02 15:04", s, loc); return tt }
	tests := []struct{ expr, from, want string }{
		{"0 3 * * *", "2026-11-02 12:00", "2026-11-03 03:00"},
		{"0 3 * * *", "2026-11-02 02:59", "2026-11-02 03:00"},
		{"*/15 * * * *", "2026-11-02 12:07", "2026-11-02 12:15"},
		{"30 2 * * 0", "2026-11-02 12:00", "2026-11-08 02:30"}, // next Sunday
		{"0 0 1 * *", "2026-11-02 12:00", "2026-12-01 00:00"},
		{"@daily", "2026-11-02 12:00", "2026-11-03 00:00"},
		{"@hourly", "2026-11-02 12:00", "2026-11-02 13:00"},
		{"@every 6h", "2026-11-02 13:00", "2026-11-02 18:00"},
		{"0 4 29 2 *", "2026-11-02 12:00", "2028-02-29 04:00"},
	}
	for _, tt := range tests {
		s, err := ParseSchedule(tt.expr)
		if err != nil {
			t.Fatalf("%s: %v", tt.expr, err)
		}
		if got := s.Next(at(tt.from)); !got.Equal(at(tt.want)) {
			t.Errorf("%s from %s = %s, want %s", tt.expr, tt.from, got.Format("2006-01-02 15:04"), tt.want)
		}
	}
}

func TestSchedulerRunOnce(t *testing.T) {
	confDir, keyPath := setupEdge(t)
	state := t.TempDir()
	cfg, err := config.Parse([]byte(testConfig + "backups: { schedule: '@daily', keep: 2, passphrase: secret://discord }\n"))
	if err != nil {
		t.Fatal(err)
	}
	var events []alerts.Event
	now := time.Date(2026, 11, 2, 3, 0, 0, 0, time.UTC)
	s := &Scheduler{
		Config: func() *config.Config { return cfg },
		OpenSecrets: func() (*secrets.Store, error) {
			id, _ := secrets.LoadIdentity(keyPath)
			return secrets.Open(filepath.Join(confDir, "secrets.age"), id)
		},
		ConfigDir: confDir, KeyPath: keyPath, StateDir: state,
		Publish: func(e alerts.Event) { events = append(events, e) },
		Now:     func() time.Time { return now },
	}
	for i := 0; i < 3; i++ {
		if _, err := s.RunOnce(context.Background()); err != nil {
			t.Fatal(err)
		}
		now = now.Add(24 * time.Hour)
	}
	ents, _ := os.ReadDir(filepath.Join(state, "backups"))
	if len(ents) != 2 || ents[0].Name() != "ingressd-lab-20261103T030000Z.tar.gz" {
		t.Fatalf("rotation kept %v", ents)
	}
	st, _ := ReadStatus(state)
	if st.LastError != "" || !st.LastSuccess.Equal(time.Date(2026, 11, 4, 3, 0, 0, 0, time.UTC)) {
		t.Fatalf("status = %+v", st)
	}
	f, _ := os.Open(st.LastFile)
	a, err := ReadArchive(f)
	f.Close()
	if err != nil || a.Manifest.Secrets != SecretsPassphrase {
		t.Fatalf("archive: %+v %v", a, err)
	}

	// A failing git push reports backup_failed (without the remote URL).
	cfg.Backups.GitRemote = "https://user:token123@127.0.0.1:1/x.git"
	_, err = s.RunOnce(context.Background())
	if err == nil || strings.Contains(err.Error(), "token123") {
		t.Fatalf("git push error = %v", err)
	}
	last := events[len(events)-1]
	if last.Kind != alerts.BackupFailed || last.Resolved || strings.Contains(last.Message, "token123") {
		t.Fatalf("event = %+v", last)
	}
	// A remote git would read as an option is refused before pushing.
	cfg.Backups.GitRemote = "--upload-pack=touch /tmp/pwned"
	if _, err = s.RunOnce(context.Background()); err == nil || !strings.Contains(err.Error(), "must be an https/ssh URL") {
		t.Fatalf("option-like remote: %v", err)
	}
	cfg.Backups.GitRemote = ""
	if _, err := s.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if last := events[len(events)-1]; !last.Resolved {
		t.Fatalf("recovery = %+v", last)
	}
}

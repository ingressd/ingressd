// SPDX-License-Identifier: Apache-2.0

package upgrade

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/blake2b"
)

// signer produces minisign keys and signatures.
type signer struct {
	id   [8]byte
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
}

func newSigner(t *testing.T) signer {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s := signer{priv: priv, pub: pub}
	rand.Read(s.id[:])
	return s
}

func (s signer) publicKey() string {
	return "untrusted comment: minisign public key\n" +
		base64.StdEncoding.EncodeToString(append(append([]byte("Ed"), s.id[:]...), s.pub...)) + "\n"
}

func (s signer) sign(msg []byte, prehash bool, trusted string) []byte {
	alg, m := "Ed", msg
	if prehash {
		h := blake2b.Sum512(msg)
		alg, m = "ED", h[:]
	}
	sig := ed25519.Sign(s.priv, m)
	global := ed25519.Sign(s.priv, append(append([]byte{}, sig...), trusted...))
	return []byte("untrusted comment: signature from minisign secret key\n" +
		base64.StdEncoding.EncodeToString(append(append([]byte(alg), s.id[:]...), sig...)) + "\n" +
		"trusted comment: " + trusted + "\n" +
		base64.StdEncoding.EncodeToString(global) + "\n")
}

func TestMinisign(t *testing.T) {
	s := newSigner(t)
	pk, err := ParsePublicKey(s.publicKey())
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("hello")
	for _, prehash := range []bool{false, true} {
		tc, err := pk.Verify(msg, s.sign(msg, prehash, "ingressd v1.2.3"))
		if err != nil || tc != "ingressd v1.2.3" {
			t.Fatalf("prehash=%v: %q %v", prehash, tc, err)
		}
	}
	if _, err := pk.Verify([]byte("tampered"), s.sign(msg, true, "x")); err == nil {
		t.Error("tampered message verified")
	}
	sig := s.sign(msg, true, "x")
	bad := strings.Replace(string(sig), "trusted comment: x", "trusted comment: y", 1)
	if _, err := pk.Verify(msg, []byte(bad)); err == nil {
		t.Error("tampered trusted comment verified")
	}
	other := newSigner(t)
	if _, err := pk.Verify(msg, other.sign(msg, true, "x")); err == nil {
		t.Error("signature by another key verified")
	}
	if _, err := ParsePublicKey(ReleasePublicKey); err != nil {
		t.Errorf("embedded key does not parse: %v", err)
	}
}

// fakeRelease serves a release under /download/<tag>/ and /latest/download/.
type fakeRelease struct {
	assets map[string][]byte
}

func (f *fakeRelease) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	name := filepath.Base(r.URL.Path)
	if !strings.HasPrefix(r.URL.Path, "/latest/download/") && !strings.HasPrefix(r.URL.Path, "/download/v2.0.0/") {
		http.NotFound(w, r)
		return
	}
	b, ok := f.assets[name]
	if !ok {
		http.NotFound(w, r)
		return
	}
	w.Write(b)
}

func newRelease(t *testing.T, s signer, bins map[string]string) *fakeRelease {
	f := &fakeRelease{assets: map[string][]byte{}}
	var sums strings.Builder
	for bin, content := range bins {
		name := AssetName(bin, "linux", "amd64")
		f.assets[name] = []byte(content)
		h := sha256.Sum256([]byte(content))
		fmt.Fprintf(&sums, "%s  %s\n", hex.EncodeToString(h[:]), name)
	}
	f.assets[SumsAsset] = []byte(sums.String())
	f.assets[SigAsset] = s.sign([]byte(sums.String()), true, "ingressd v2.0.0")
	return f
}

func setup(t *testing.T) (signer, *fakeRelease, *httptest.Server, string) {
	s := newSigner(t)
	rel := newRelease(t, s, map[string]string{"ingressd": "NEW-CP", "ingressd-edge": "NEW-EDGE"})
	srv := httptest.NewServer(rel)
	t.Cleanup(srv.Close)
	dir := t.TempDir()
	for name, body := range map[string]string{"ingressd": "OLD-CP", "ingressd-edge": "OLD-EDGE"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o755); err != nil { //nolint:gosec // G306: stands in for an executable
			t.Fatal(err)
		}
	}
	return s, rel, srv, dir
}

func read(t *testing.T, dir, name string) string {
	b, _ := os.ReadFile(filepath.Join(dir, name))
	return string(b)
}

func opts(s signer, srv *httptest.Server, dir string) (Options, *[]string) {
	var restarts []string
	return Options{
		BaseURL: srv.URL, PublicKey: s.publicKey(), BinDir: dir, OS: "linux", Arch: "amd64",
		Units: []string{"ingressd-edge.service", "ingressd.service"},
		Restart: func(_ context.Context, units []string) error {
			restarts = append(restarts, strings.Join(units, ","))
			return nil
		},
		HealthTimeout: 100 * time.Millisecond,
	}, &restarts
}

func TestUpgradeSuccess(t *testing.T) {
	s, _, srv, dir := setup(t)
	o, restarts := opts(s, srv, dir)
	doctorRan := false
	o.Doctor = func(context.Context) error {
		doctorRan = true
		if read(t, dir, "ingressd") != "NEW-CP" {
			return errors.New("doctor ran before the swap")
		}
		return nil
	}
	o.Version = "v2.0.0"
	res, err := Run(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	if res.Version != "ingressd v2.0.0" || !doctorRan || len(*restarts) != 1 {
		t.Fatalf("res=%+v doctor=%v restarts=%v", res, doctorRan, *restarts)
	}
	if read(t, dir, "ingressd") != "NEW-CP" || read(t, dir, "ingressd-edge") != "NEW-EDGE" || read(t, dir, "ingressd.old") != "OLD-CP" {
		t.Fatal("binaries not swapped")
	}
	if fi, _ := os.Stat(filepath.Join(dir, "ingressd")); fi.Mode().Perm()&0o111 == 0 {
		t.Fatal("new binary not executable")
	}
}

func TestUpgradeRollsBackWhenDoctorFails(t *testing.T) {
	s, _, srv, dir := setup(t)
	o, restarts := opts(s, srv, dir)
	o.Doctor = func(context.Context) error { return errors.New("ingressd-edge not reachable") }
	_, err := Run(context.Background(), o)
	if err == nil || !strings.Contains(err.Error(), "rolled back") {
		t.Fatalf("err = %v", err)
	}
	if read(t, dir, "ingressd") != "OLD-CP" || read(t, dir, "ingressd-edge") != "OLD-EDGE" {
		t.Fatal("binaries not rolled back")
	}
	if len(*restarts) != 2 {
		t.Fatalf("restarts = %v (want restart after swap and after rollback)", *restarts)
	}
}

func TestUpgradeRejectsBadReleases(t *testing.T) {
	t.Run("bad signature", func(t *testing.T) {
		s, rel, srv, dir := setup(t)
		rel.assets[SigAsset] = newSigner(t).sign(rel.assets[SumsAsset], true, "evil")
		o, _ := opts(s, srv, dir)
		if _, err := Run(context.Background(), o); err == nil || !strings.Contains(err.Error(), "signature") {
			t.Fatalf("err = %v", err)
		}
		if read(t, dir, "ingressd") != "OLD-CP" {
			t.Fatal("binary replaced")
		}
	})
	t.Run("checksum mismatch", func(t *testing.T) {
		s, rel, srv, dir := setup(t)
		rel.assets[AssetName("ingressd-edge", "linux", "amd64")] = []byte("TAMPERED")
		o, _ := opts(s, srv, dir)
		if _, err := Run(context.Background(), o); err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
			t.Fatalf("err = %v", err)
		}
		if read(t, dir, "ingressd") != "OLD-CP" {
			t.Fatal("binary replaced before all downloads were verified")
		}
		if _, err := os.Stat(filepath.Join(dir, ".ingressd.new")); err == nil {
			t.Fatal("staged file left behind")
		}
	})
	t.Run("missing asset", func(t *testing.T) {
		s, _, srv, dir := setup(t)
		o, _ := opts(s, srv, dir)
		o.Arch = "riscv64"
		if _, err := Run(context.Background(), o); err == nil || !strings.Contains(err.Error(), "release has no") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("unknown version", func(t *testing.T) {
		s, _, srv, dir := setup(t)
		o, _ := opts(s, srv, dir)
		o.Version = "v9.9.9"
		if _, err := Run(context.Background(), o); err == nil || !strings.Contains(err.Error(), "HTTP 404") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("placeholder key rejects", func(t *testing.T) {
		_, _, srv, dir := setup(t)
		o, _ := opts(signer{}, srv, dir)
		o.PublicKey = ""
		if _, err := Run(context.Background(), o); err == nil {
			t.Fatal("release verified against the placeholder key")
		}
	})
}

// withManifest adds a release.json for version (listed in SHA256SUMS when
// inSums) and its signature, re-signing the sums as "ingressd <signedAs>".
func withManifest(t *testing.T, s signer, rel *fakeRelease, version, minSupported, signedAs string, inSums bool) {
	t.Helper()
	m := fmt.Sprintf(`{"version":%q,"channel":"stable","min_supported":%q,"assets":{"x":"%s"}}`,
		version, minSupported, strings.Repeat("ab", 32))
	rel.assets["release.json"] = []byte(m)
	rel.assets["release.json.minisig"] = s.sign([]byte(m), true, "ingressd "+version)
	sums := string(rel.assets[SumsAsset])
	if inSums {
		h := sha256.Sum256([]byte(m))
		sums += hex.EncodeToString(h[:]) + "  release.json\n"
	}
	rel.assets[SumsAsset] = []byte(sums)
	rel.assets[SigAsset] = s.sign([]byte(sums), true, "ingressd "+signedAs)
}

func TestUpgradeVersionChecks(t *testing.T) {
	ok := func(context.Context) error { return nil }
	t.Run("signature for another release", func(t *testing.T) {
		s, rel, srv, dir := setup(t)
		rel.assets[SigAsset] = s.sign(rel.assets[SumsAsset], true, "ingressd v1.0.0")
		o, _ := opts(s, srv, dir)
		o.Version = "v2.0.0"
		if _, err := Run(context.Background(), o); err == nil || !strings.Contains(err.Error(), "not the requested v2.0.0") {
			t.Fatalf("err = %v", err)
		}
		if read(t, dir, "ingressd") != "OLD-CP" {
			t.Fatal("binary replaced")
		}
	})
	t.Run("staging note after the version", func(t *testing.T) {
		s, rel, srv, dir := setup(t)
		rel.assets[SigAsset] = s.sign(rel.assets[SumsAsset], true, "ingressd v2.0.0 (staging)")
		o, _ := opts(s, srv, dir)
		o.Version = "v2.0.0"
		if _, err := Run(context.Background(), o); err != nil {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("trusted comment without a version", func(t *testing.T) {
		s, rel, srv, dir := setup(t)
		rel.assets[SigAsset] = s.sign(rel.assets[SumsAsset], true, "SHA256SUMS")
		o, _ := opts(s, srv, dir)
		if _, err := Run(context.Background(), o); err == nil || !strings.Contains(err.Error(), "does not name") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("manifest disagrees", func(t *testing.T) {
		s, rel, srv, dir := setup(t)
		withManifest(t, s, rel, "v1.0.0", "", "v2.0.0", true)
		o, _ := opts(s, srv, dir)
		if _, err := Run(context.Background(), o); err == nil || !strings.Contains(err.Error(), "release.json is for v1.0.0") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("downgrade refused", func(t *testing.T) {
		s, _, srv, dir := setup(t)
		o, _ := opts(s, srv, dir)
		o.Current = "v3.0.0 (abc1234)"
		if _, err := Run(context.Background(), o); err == nil || !strings.Contains(err.Error(), "--allow-downgrade") {
			t.Fatalf("err = %v", err)
		}
		if read(t, dir, "ingressd") != "OLD-CP" {
			t.Fatal("binary replaced")
		}
	})
	t.Run("downgrade below min supported", func(t *testing.T) {
		s, rel, srv, dir := setup(t)
		withManifest(t, s, rel, "v2.0.0", "v2.5.0", "v2.0.0", true)
		o, _ := opts(s, srv, dir)
		o.Current, o.AllowDowngrade = "v3.0.0", true
		if _, err := Run(context.Background(), o); err == nil || !strings.Contains(err.Error(), "minimum supported version v2.5.0") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("downgrade without a latest manifest", func(t *testing.T) {
		s, _, srv, dir := setup(t)
		o, _ := opts(s, srv, dir)
		o.Current, o.AllowDowngrade = "v3.0.0", true
		if _, err := Run(context.Background(), o); err == nil || !strings.Contains(err.Error(), "minimum supported") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("downgrade allowed", func(t *testing.T) {
		s, rel, srv, dir := setup(t)
		withManifest(t, s, rel, "v2.0.0", "v1.0.0", "v2.0.0", true)
		o, _ := opts(s, srv, dir)
		o.Current, o.AllowDowngrade, o.Doctor = "v3.0.0", true, ok
		if _, err := Run(context.Background(), o); err != nil {
			t.Fatal(err)
		}
		if read(t, dir, "ingressd") != "NEW-CP" {
			t.Fatal("binary not replaced")
		}
	})
	t.Run("upgrade from a dev build", func(t *testing.T) {
		s, _, srv, dir := setup(t)
		o, _ := opts(s, srv, dir)
		o.Current, o.Doctor = "dev", ok
		if _, err := Run(context.Background(), o); err != nil {
			t.Fatal(err)
		}
	})
}

// SPDX-License-Identifier: Apache-2.0

package release

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseCompare(t *testing.T) {
	order := []string{"v0.9.0", "v1.0.0-alpha", "v1.0.0-alpha.1", "v1.0.0-alpha.beta", "v1.0.0-beta.2", "v1.0.0-beta.11", "v1.0.0-rc.1", "v1.0.0", "1.0.1", "v1.2.0 (abc1234)", "v1.10.0", "v2.0.0+build.7"}
	for i := range order {
		for j := range order {
			c, ok := CompareStrings(order[i], order[j])
			want := sign(i - j)
			if !ok || c != want {
				t.Errorf("Compare(%q, %q) = %d, %v; want %d", order[i], order[j], c, ok, want)
			}
		}
	}
	if v, ok := Parse("v1.2.3-rc.1"); !ok || v.String() != "v1.2.3-rc.1" {
		t.Errorf("Parse round trip: %v %v", v, ok)
	}
}

func TestDevBuildsAreNotComparable(t *testing.T) {
	for _, s := range []string{"dev", "dev (none)", "", "v1.2.3-4-gabc1234", "v1.2.3-4-gabc1234-dirty", "v1.2.3-dirty", "abc1234", "v1.2", "v01.2.3", "1.2.3.4", "v1.2.3-"} {
		if Comparable(s) {
			t.Errorf("%q is comparable", s)
		}
		if Older(s, "v9.9.9") {
			t.Errorf("Older(%q, v9.9.9): a dev build must never be outdated", s)
		}
	}
	if !Older("v1.0.0 (abc)", "v1.0.1") || Older("v1.0.1", "v1.0.1") || Older("v1.1.0", "v1.0.9") {
		t.Error("Older")
	}
}

func TestDevBuild(t *testing.T) {
	for s, want := range map[string]bool{
		"dev": true, "dev (none)": true, "v1.2.3-4-gabc1234": true, "v1.2.3-4-gabc1234-dirty": true,
		"v1.2.3-dirty": true, "abc1234": true, "abc1234 (abc1234)": true,
		"v1.2.3": false, "v1.2.3-rc.1": false, "": false, "v1.2": false, "v01.2.3": false,
		"1.2.3.4": false, "v1.2.3-": false, "garbage": false, "v1.2-4-gabc1234": false,
	} {
		if got := DevBuild(s); got != want {
			t.Errorf("DevBuild(%q) = %v, want %v", s, got, want)
		}
	}
}

func TestVerifySums(t *testing.T) {
	pub, sec, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	sk, err := ParseSecretKey(sec)
	if err != nil {
		t.Fatal(err)
	}
	sums := []byte("0000  ingressd_linux_amd64\n")
	sig := sk.Sign(sums, "ingressd v1.2.3")
	t.Setenv(PublicKeyEnv, pub)
	if c, err := VerifySums(sums, sig); err != nil || c != "ingressd v1.2.3" {
		t.Fatalf("VerifySums = %q, %v", c, err)
	}
	if _, err := VerifySums([]byte("1111  ingressd_linux_amd64\n"), sig); err == nil {
		t.Fatal("tampered SHA256SUMS verified")
	}
	t.Setenv(PublicKeyEnv, PlaceholderPublicKey)
	if _, err := VerifySums(sums, sig); !errors.Is(err, ErrNoSigningKey) {
		t.Fatalf("placeholder key: %v", err)
	}
}

func writeAssets(t *testing.T, dir string) {
	t.Helper()
	for name, body := range map[string]string{"ingressd_linux_amd64": "node", "ingressd-connector_windows_amd64.exe": "conn", "install-node.sh": "#!/bin/sh"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o755); err != nil { //nolint:gosec // G306: stands in for an executable
			t.Fatal(err)
		}
	}
}

func TestManifestSignVerify(t *testing.T) {
	pub, sec, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	sk, err := ParseSecretKey(sec)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(pub, sk.PublicKey()) {
		t.Fatalf("public key mismatch")
	}
	dir := t.TempDir()
	writeAssets(t, dir)
	m, err := BuildManifest(dir, BuildOptions{Version: "v1.2.0", MinSupported: "v1.0.0", Security: true, NotesURL: "https://example.com/n"})
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Assets) != 3 || m.Channel != ChannelStable {
		t.Fatalf("manifest %+v", m)
	}
	if err := WriteRelease(dir, m, &sk); err != nil {
		t.Fatal(err)
	}
	// Rebuilding ignores the manifest, sums and signatures.
	if m2, _ := BuildManifest(dir, BuildOptions{Version: "v1.2.0"}); len(m2.Assets) != 3 {
		t.Errorf("rebuild picked up release files: %v", m2.Assets)
	}
	read := func(n string) []byte {
		b, err := os.ReadFile(filepath.Join(dir, n))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	mb, sig := read(ManifestFile), read(ManifestSigFile)
	got, err := VerifyManifest(pub, mb, sig)
	if err != nil {
		t.Fatal(err)
	}
	if got.Version != "v1.2.0" || !got.Security || got.MinSupported != "v1.0.0" || got.Supports("v0.9.0") || !got.Supports("v1.0.0") {
		t.Errorf("verified manifest %+v", got)
	}
	// SHA256SUMS covers release.json and is signed too.
	pk, _ := ParsePublicKey(pub)
	if tc, err := pk.Verify(read(SumsFile), read(SumsSigFile)); err != nil || tc != "ingressd v1.2.0" {
		t.Errorf("SHA256SUMS signature: %q %v", tc, err)
	}
	if !strings.Contains(string(read(SumsFile)), "  release.json\n") {
		t.Error("SHA256SUMS does not list release.json")
	}

	tampered := []byte(strings.Replace(string(mb), `"security": true`, `"security": false`, 1))
	if _, err := VerifyManifest(pub, tampered, sig); err == nil {
		t.Error("tampered manifest verified")
	}
	if _, err := VerifyManifest(pub, mb, nil); err == nil {
		t.Error("unsigned manifest verified")
	}
	other, _, _ := GenerateKey()
	if _, err := VerifyManifest(other, mb, sig); err == nil {
		t.Error("manifest verified with another key")
	}
	if _, err := VerifyManifest(PlaceholderPublicKey, mb, sig); !errors.Is(err, ErrNoSigningKey) {
		t.Errorf("placeholder key: %v", err)
	}
}

func TestManifestValidate(t *testing.T) {
	good := "0000000000000000000000000000000000000000000000000000000000000000"
	for name, m := range map[string]Manifest{
		"dev version": {Version: "dev", Channel: "stable", Assets: map[string]string{"a": good}},
		"no channel":  {Version: "v1.0.0", Assets: map[string]string{"a": good}},
		"no assets":   {Version: "v1.0.0", Channel: "stable"},
		"bad sum":     {Version: "v1.0.0", Channel: "stable", Assets: map[string]string{"a": "xyz"}},
		"bad name":    {Version: "v1.0.0", Channel: "stable", Assets: map[string]string{"../a": good}},
		"bad min":     {Version: "v1.0.0", Channel: "stable", MinSupported: "latest", Assets: map[string]string{"a": good}},
	} {
		if err := m.Validate(); err == nil {
			t.Errorf("%s: valid", name)
		}
	}
}

func TestTrustedPublicKeyOverride(t *testing.T) {
	if !IsPlaceholderKey(TrustedPublicKey()) {
		t.Skip("a real release key is configured")
	}
	pub, _, _ := GenerateKey()
	t.Setenv(PublicKeyEnv, pub)
	if TrustedPublicKey() != strings.TrimSpace(pub) || IsPlaceholderKey(TrustedPublicKey()) {
		t.Error("override not used")
	}
}

func TestInstall(t *testing.T) {
	if !SelfUpdatable(InstallSystemd) || SelfUpdatable(InstallDocker) || SelfUpdatable(InstallManual) {
		t.Error("SelfUpdatable")
	}
	if got := DockerPullCommand("v1.2.3"); got != "docker pull ghcr.io/ingressd/ingressd-connector:1.2.3" {
		t.Error(got)
	}
	if AssetName("ingressd-connector", "windows", "amd64") != "ingressd-connector_windows_amd64.exe" || AssetName("ingressd", "linux", "arm64") != "ingressd_linux_arm64" {
		t.Error("AssetName")
	}
}

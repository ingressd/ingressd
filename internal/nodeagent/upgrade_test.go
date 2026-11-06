// SPDX-License-Identifier: Apache-2.0

package nodeagent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ingressd/ingressd/internal/upgrade"
	"github.com/ingressd/ingressd/pkg/nodeproto"
	"github.com/ingressd/ingressd/pkg/release"
)

// signedRelease returns an upgrade_request for version signed with sk.
func signedRelease(t *testing.T, sk release.SecretKey, version, minSupported string) nodeproto.UpgradeRequest {
	t.Helper()
	return signedChannelRelease(t, sk, version, minSupported, "")
}

func signedChannelRelease(t *testing.T, sk release.SecretKey, version, minSupported, channel string) nodeproto.UpgradeRequest {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "ingressd_linux_amd64"), []byte(version), 0o755); err != nil { //nolint:gosec // G306: stands in for an executable
		t.Fatal(err)
	}
	m, err := release.BuildManifest(dir, release.BuildOptions{Version: version, MinSupported: minSupported, Channel: channel})
	if err != nil {
		t.Fatal(err)
	}
	if err := release.WriteRelease(dir, m, &sk); err != nil {
		t.Fatal(err)
	}
	mb, _ := os.ReadFile(filepath.Join(dir, release.ManifestFile))
	sig, _ := os.ReadFile(filepath.Join(dir, release.ManifestSigFile))
	return nodeproto.UpgradeRequest{ID: "upg_1", Version: version, Manifest: string(mb), Signature: string(sig)}
}

func TestCheckUpgrade(t *testing.T) {
	pub, sec, err := release.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	sk, _ := release.ParseSecretKey(sec)
	agent := func(cur, install string) *Agent {
		a := &Agent{o: Options{StateDir: t.TempDir(), Upgrade: UpgradeOptions{PublicKey: pub, Version: cur, Install: install}}}
		a.upgradeDefaults()
		return a
	}
	a := agent("v1.0.0", release.InstallSystemd)
	if _, err := a.checkUpgrade(signedRelease(t, sk, "v1.1.0", "")); err != nil {
		t.Errorf("upgrade refused: %v", err)
	}
	devAgent := agent("dev", release.InstallManual)
	if _, err := devAgent.checkUpgrade(signedRelease(t, sk, "v1.1.0", "")); err != nil {
		t.Errorf("dev build may install a release: %v", err)
	}

	refuse := func(name string, a *Agent, req nodeproto.UpgradeRequest, want string) {
		t.Helper()
		if _, err := a.checkUpgrade(req); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: err = %v, want %q", name, err, want)
		}
	}
	unsigned := signedRelease(t, sk, "v1.1.0", "")
	unsigned.Signature = ""
	refuse("unsigned", a, unsigned, "not signed")
	_, otherSec, _ := release.GenerateKey()
	otherSK, _ := release.ParseSecretKey(otherSec)
	refuse("other key", a, signedRelease(t, otherSK, "v1.1.0", ""), "signature")
	tampered := signedRelease(t, sk, "v1.1.0", "")
	tampered.Manifest = strings.Replace(tampered.Manifest, "v1.1.0", "v1.9.0", 1)
	refuse("tampered", a, tampered, "signature")
	mismatch := signedRelease(t, sk, "v1.1.0", "")
	mismatch.Version = "v1.2.0"
	refuse("version mismatch", a, mismatch, "does not match")
	refuse("same version", a, signedRelease(t, sk, "v1.0.0", ""), "already running")
	refuse("downgrade", a, signedRelease(t, sk, "v0.9.0", ""), "must be forced")
	forced := signedRelease(t, sk, "v0.9.0", "")
	forced.Force = true
	if _, err := a.checkUpgrade(forced); err != nil {
		t.Errorf("forced downgrade: %v", err)
	}
	// A rollback needs no latest manifest: the panel omits it when the
	// target is its own latest release.
	beta := signedChannelRelease(t, sk, "v0.9.0", "", "beta")
	beta.Force = true
	refuse("forced downgrade off the stable channel", a, beta, "only stable releases")
	if _, err := a.checkUpgrade(signedChannelRelease(t, sk, "v1.1.0", "", "beta")); err != nil {
		t.Errorf("upgrade on another channel: %v", err)
	}
	refuse("container", agent("v1.0.0", release.InstallDocker), signedRelease(t, sk, "v1.1.0", ""), "pulling ghcr.io/ingressd/ingressd-node:1.1.0")
	refuse("placeholder key", &Agent{o: Options{StateDir: t.TempDir(), Upgrade: UpgradeOptions{PublicKey: release.PlaceholderPublicKey, Version: "v1.0.0", Install: "manual"}}},
		signedRelease(t, sk, "v1.1.0", ""), "no release signing key")

	// min_supported: the highest one seen sticks, even for forced installs
	// and when it came with the "latest" manifest.
	b := agent("v1.2.0", release.InstallSystemd)
	old := signedRelease(t, sk, "v1.0.5", "")
	latest := signedRelease(t, sk, "v1.3.0", "v1.1.0")
	old.Force, old.LatestManifest, old.LatestSignature = true, latest.Manifest, latest.Signature
	refuse("below min_supported (latest)", b, old, "below the minimum supported version v1.1.0")
	old.LatestManifest, old.LatestSignature = "", ""
	refuse("below min_supported (remembered)", b, old, "below the minimum supported version v1.1.0")

	// An unreadable record does not stop the floor from being learned.
	c := agent("v1.2.0", release.InstallSystemd)
	if err := os.MkdirAll(c.o.Upgrade.WorkDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(c.o.Upgrade.WorkDir, minSupportedFile), []byte("garbage\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if floor := c.minSupported(&release.Manifest{MinSupported: "v1.1.0"}); floor != "v1.1.0" {
		t.Errorf("floor = %q", floor)
	}
	if floor := c.minSupported(); floor != "v1.1.0" {
		t.Errorf("remembered floor = %q", floor)
	}

	// One update at a time.
	p := &upgrade.Plan{ID: "upg_busy", To: "v1.1.0", WorkDir: a.o.Upgrade.WorkDir, Created: time.Now()}
	if _, err := p.Save(); err != nil {
		t.Fatal(err)
	}
	refuse("busy", a, signedRelease(t, sk, "v1.1.0", ""), "in progress")
}

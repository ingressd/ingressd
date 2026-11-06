// SPDX-License-Identifier: Apache-2.0

package deploy

import (
	"os"
	"strings"
	"testing"

	"github.com/ingressd/ingressd/pkg/release"
)

// The installers verify SHA256SUMS.minisig with a copy of the release key.
func TestInstallersPinReleaseKey(t *testing.T) {
	for _, f := range []string{"install-node.sh", "install-connector.sh"} {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(b), "RELEASE_KEY=${INGRESSD_RELEASE_PUBLIC_KEY:-"+release.ReleasePublicKey+"}") {
			t.Errorf("%s does not pin release.ReleasePublicKey", f)
		}
		if strings.Contains(string(b), "http,") || strings.Contains(string(b), ",http'") {
			t.Errorf("%s allows plain http downloads", f)
		}
	}
}

// With a verifier that does not come from the download (minisign, or an
// earlier install), the signature is checked before the new binary first runs.
func TestInstallersVerifyBeforeRunning(t *testing.T) {
	for f, calls := range map[string][2]string{
		"install-node.sh":      {`[ -z "$SIGNED" ] || verify_sums "$SIGNED"`, `"$WORK/ingressd" version`},
		"install-connector.sh": {`[ -z "$SIG" ] || verify_sig "$SUMS" "$SIG" "$NEW"`, `"$NEW" version`},
	} {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		verify, run := strings.LastIndex(string(b), calls[0]), strings.LastIndex(string(b), calls[1])
		if verify < 0 || run < 0 || verify > run {
			t.Errorf("%s: verification at %d, first run at %d", f, verify, run)
		}
	}
}

// The connector installer sets up nft before the service first starts, and
// keeps the package manager off a piped script's standard input.
func TestConnectorInstallerAddsNFT(t *testing.T) {
	b, err := os.ReadFile("install-connector.sh")
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	guard := `if [ "$ROOT" -eq 1 ] && [ "$SYSTEMD" -eq 1 ] && ! have_nft; then`
	call := "install_nft </dev/null >/dev/null 2>&1 || true"
	service := `"$EXE" "$@" install-service`
	at, install, svc := strings.Index(s, guard), strings.Index(s, call), strings.Index(s, service)
	if at < 0 || install < at || svc < install {
		t.Errorf("guard at %d, install at %d, service at %d", at, install, svc)
	}
	for _, want := range []string{"apt-get install -y nftables", "dnf install -y nftables", "apk add --no-cache nftables"} {
		if !strings.Contains(s, want) {
			t.Errorf("no %q", want)
		}
	}
}

// install-node.sh embeds the control-plane unit: its sandbox must match
// deploy/systemd/ingressd.service.
func TestInstallNodeUnitMatches(t *testing.T) {
	unit, err := os.ReadFile("systemd/ingressd.service")
	if err != nil {
		t.Fatal(err)
	}
	script, err := os.ReadFile("install-node.sh")
	if err != nil {
		t.Fatal(err)
	}
	_, heredoc, _ := strings.Cut(string(script), "cat >/etc/systemd/system/ingressd.service <<'EOF'\n")
	heredoc, _, _ = strings.Cut(heredoc, "\nEOF\n")
	have := map[string]bool{}
	for _, l := range strings.Split(heredoc, "\n") {
		have[l] = true
	}
	for _, l := range strings.Split(string(unit), "\n") {
		if l == "" || strings.HasPrefix(l, "#") || strings.HasPrefix(l, "Description=") {
			continue
		}
		if !have[l] {
			t.Errorf("install-node.sh's ingressd.service lacks %q", l)
		}
	}
}

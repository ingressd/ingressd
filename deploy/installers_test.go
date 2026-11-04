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

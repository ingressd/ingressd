// SPDX-License-Identifier: Apache-2.0

package client

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

const systemdUnitPath = "/etc/systemd/system/" + ServiceName + ".service"

// SystemdUnit renders the unit file.
func SystemdUnit(exe string, args []string) string {
	q := make([]string, len(args))
	for i, a := range args {
		q[i] = strconv.Quote(a)
	}
	return fmt.Sprintf(`[Unit]
Description=ingressd site connector
Documentation=https://github.com/ingressd/ingressd
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=%s %s
Restart=always
RestartSec=5
StateDirectory=ingressd-connector
StateDirectoryMode=0700

[Install]
WantedBy=multi-user.target
`, strconv.Quote(exe), strings.Join(q, " "))
}

// InstallService writes and enables the systemd unit.
func InstallService(o ServiceOptions) (string, error) {
	exe, err := o.exe()
	if err != nil {
		return "", err
	}
	removeLegacyService()
	if err := os.WriteFile(systemdUnitPath, []byte(SystemdUnit(exe, o.args())), 0o644); err != nil {
		return "", err
	}
	cmds := [][]string{{"systemctl", "daemon-reload"}}
	if o.NoStart {
		cmds = append(cmds, []string{"systemctl", "enable", ServiceName})
	} else {
		cmds = append(cmds, []string{"systemctl", "enable", "--now", ServiceName})
	}
	for _, c := range cmds {
		if out, err := exec.Command(c[0], c[1:]...).CombinedOutput(); err != nil {
			return systemdUnitPath, fmt.Errorf("%s: %v: %s", strings.Join(c, " "), err, strings.TrimSpace(string(out)))
		}
	}
	return systemdUnitPath, nil
}

// removeLegacyService stops, disables and deletes a pre-rename unit.
func removeLegacyService() {
	old := "/etc/systemd/system/" + legacyServiceName + ".service"
	if _, err := os.Stat(old); err != nil {
		return
	}
	_ = exec.Command("systemctl", "disable", "--now", legacyServiceName).Run()
	_ = os.Remove(old)
}

func runService(func(context.Context) error) (bool, error) { return false, nil }

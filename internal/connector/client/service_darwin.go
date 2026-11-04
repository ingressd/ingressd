// SPDX-License-Identifier: Apache-2.0

package client

import (
	"context"
	"fmt"
	"html"
	"os"
	"os/exec"
	"strings"
)

const launchdLabel = "com.ingressd.connector"

var launchdPlistPath = "/Library/LaunchDaemons/" + launchdLabel + ".plist"

// InstallService writes and loads a launchd daemon.
func InstallService(o ServiceOptions) (string, error) {
	exe, err := o.exe()
	if err != nil {
		return "", err
	}
	var args strings.Builder
	for _, a := range append([]string{exe}, o.args()...) {
		fmt.Fprintf(&args, "\t\t<string>%s</string>\n", html.EscapeString(a))
	}
	plist := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>%s</string>
	<key>ProgramArguments</key>
	<array>
%s	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<true/>
</dict>
</plist>
`, launchdLabel, args.String())
	if old := "/Library/LaunchDaemons/" + legacyLaunchd + ".plist"; fileExists(old) {
		_ = exec.Command("launchctl", "unload", "-w", old).Run()
		_ = os.Remove(old)
	}
	if err := os.WriteFile(launchdPlistPath, []byte(plist), 0o644); err != nil {
		return "", err
	}
	if !o.NoStart {
		if out, err := exec.Command("launchctl", "load", "-w", launchdPlistPath).CombinedOutput(); err != nil {
			return launchdPlistPath, fmt.Errorf("launchctl load: %v: %s", err, strings.TrimSpace(string(out)))
		}
	}
	return launchdPlistPath, nil
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func runService(func(context.Context) error) (bool, error) { return false, nil }

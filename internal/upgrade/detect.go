// SPDX-License-Identifier: Apache-2.0

package upgrade

import (
	"os"
	"runtime"

	"github.com/ingressd/ingressd/pkg/release"
)

// InstallEnv overrides install-method detection (container images set it
// to "docker").
const InstallEnv = "INGRESSD_INSTALL"

// DetectInstall reports how the running process was installed: under
// systemd, launchd (label launchdLabel) or as a Windows service, in a
// container, or started by hand.
func DetectInstall(launchdLabel string) string {
	if v := os.Getenv(InstallEnv); v != "" {
		return v
	}
	if inContainer() {
		return release.InstallDocker
	}
	switch runtime.GOOS {
	case "linux":
		// systemd sets INVOCATION_ID for every unit it starts.
		if os.Getenv("INVOCATION_ID") != "" {
			if _, err := os.Stat("/run/systemd/system"); err == nil {
				return release.InstallSystemd
			}
		}
	case "darwin":
		if launchdLabel != "" && os.Getenv("XPC_SERVICE_NAME") == launchdLabel {
			return release.InstallLaunchd
		}
	case "windows":
		if isWindowsService() {
			return release.InstallWindowsService
		}
	}
	return release.InstallManual
}

func inContainer() bool {
	for _, p := range []string{"/.dockerenv", "/run/.containerenv"} {
		if _, err := os.Stat(p); err == nil {
			return true
		}
	}
	return false
}

// RestartMode maps an install method to how the helper restarts it.
func RestartMode(install string) string {
	switch install {
	case release.InstallSystemd:
		return RestartSystemd
	case release.InstallLaunchd:
		return RestartLaunchd
	case release.InstallWindowsService:
		return RestartWindows
	}
	return RestartExec
}

// ExecRestart describes restarting the current process as it was started.
func ExecRestart() Restart {
	exe, _ := os.Executable()
	argv := append([]string{exe}, os.Args[1:]...)
	dir, _ := os.Getwd()
	return Restart{Mode: RestartExec, PID: os.Getpid(), Argv: argv, Env: os.Environ(), Dir: dir}
}

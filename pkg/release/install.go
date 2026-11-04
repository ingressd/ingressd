// SPDX-License-Identifier: Apache-2.0

package release

import "strings"

// Install methods a node or connector reports (how it was installed, which
// decides how it can be updated).
const (
	InstallSystemd        = "systemd"
	InstallLaunchd        = "launchd"
	InstallWindowsService = "windows-service"
	InstallDocker         = "docker"
	InstallManual         = "manual"
)

// SelfUpdatable reports whether an installation of this kind replaces its
// own binary and restarts through its service manager. Docker images are
// updated by pulling a new image; manual installs by the user.
func SelfUpdatable(install string) bool {
	switch install {
	case InstallSystemd, InstallLaunchd, InstallWindowsService:
		return true
	}
	return false
}

// ConnectorImage is the connector's container image.
const ConnectorImage = "ghcr.io/ingressd/ingressd-connector"

// DockerPullCommand is what a Docker connector install runs to update.
func DockerPullCommand(version string) string {
	return "docker pull " + ConnectorImage + ":" + strings.TrimPrefix(version, "v")
}

// AssetName is a binary's release file: <bin>_<os>_<arch>, plus ".exe" on
// Windows (only the connector is built for Windows).
func AssetName(bin, goos, arch string) string {
	n := bin + "_" + goos + "_" + arch
	if goos == "windows" {
		n += ".exe"
	}
	return n
}

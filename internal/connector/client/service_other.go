// SPDX-License-Identifier: Apache-2.0

//go:build !linux && !darwin && !windows

package client

import (
	"context"
	"errors"
)

// InstallService is not supported on this platform.
func InstallService(ServiceOptions) (string, error) {
	return "", errors.New("install-service is supported on Linux (systemd), macOS (launchd) and Windows")
}

func runService(func(context.Context) error) (bool, error) { return false, nil }

// SPDX-License-Identifier: Apache-2.0

package client

import (
	"context"
	"os"
	"path/filepath"
)

// ServiceName is the systemd unit / Windows service / launchd label base.
const ServiceName = "ingressd-connector"

// ServiceOptions describe the installed service.
type ServiceOptions struct {
	StatePath string
	// Exe is the connector binary; defaults to the running executable.
	Exe string
	// NoStart only writes/registers the service without starting it.
	NoStart bool
}

func (o ServiceOptions) exe() (string, error) {
	if o.Exe != "" {
		return filepath.Abs(o.Exe)
	}
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(exe)
}

func (o ServiceOptions) args() []string {
	return []string{"run", "--state", o.StatePath}
}

// RunService runs fn under the platform's service manager when the process
// was started by it (Windows services); otherwise it reports false.
func RunService(fn func(ctx context.Context) error) (bool, error) {
	return runService(fn)
}

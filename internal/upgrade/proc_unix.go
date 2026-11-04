// SPDX-License-Identifier: Apache-2.0

//go:build unix

package upgrade

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"syscall"
	"time"
)

// detach starts cmd in its own session so it outlives its parent and is
// not hit by signals sent to the parent's process group.
func detach(cmd *exec.Cmd) { cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true} }

func terminate(p *os.Process) error { return p.Signal(syscall.SIGTERM) }

// stopPID sends SIGTERM and waits for the process to exit (SIGKILL after
// timeout).
func stopPID(pid int, timeout time.Duration) error {
	if err := syscall.Kill(pid, syscall.SIGTERM); err != nil {
		if errors.Is(err, syscall.ESRCH) {
			return nil
		}
		return err
	}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if syscall.Kill(pid, 0) != nil {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	_ = syscall.Kill(pid, syscall.SIGKILL)
	time.Sleep(200 * time.Millisecond)
	return nil
}

func restartWindowsService(context.Context, string) error {
	return errors.New("windows services exist only on Windows")
}

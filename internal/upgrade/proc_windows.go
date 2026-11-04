// SPDX-License-Identifier: Apache-2.0

package upgrade

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// detach starts cmd outside the parent's console and process group, so it
// survives the service stopping.
func detach(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.CREATE_NEW_PROCESS_GROUP | windows.DETACHED_PROCESS}
}

func terminate(p *os.Process) error { return p.Kill() }

func stopPID(pid int, _ time.Duration) error {
	p, err := os.FindProcess(pid)
	if err != nil {
		return nil
	}
	_ = p.Kill()
	_, _ = p.Wait()
	return nil
}

// restartWindowsService stops and starts a service.
func restartWindowsService(ctx context.Context, name string) error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(name)
	if err != nil {
		return err
	}
	defer s.Close()
	if st, err := s.Query(); err == nil && st.State != svc.Stopped {
		if _, err := s.Control(svc.Stop); err != nil {
			return fmt.Errorf("stop %s: %w", name, err)
		}
		for st.State != svc.Stopped {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(300 * time.Millisecond):
			}
			if st, err = s.Query(); err != nil {
				return err
			}
		}
	}
	return s.Start()
}

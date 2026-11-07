// SPDX-License-Identifier: Apache-2.0

package client

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// InstallService registers (and starts) a Windows service.
func InstallService(o ServiceOptions) (string, error) {
	exe, err := o.exe()
	if err != nil {
		return "", err
	}
	if err := checkServicePath(exe); err != nil {
		return "", err
	}
	m, err := mgr.Connect()
	if err != nil {
		return "", err
	}
	defer m.Disconnect()
	if s, err := m.OpenService(legacyServiceName); err == nil { // pre-rename service
		_, _ = s.Control(svc.Stop)
		_ = s.Delete()
		s.Close()
	}
	if s, err := m.OpenService(ServiceName); err == nil {
		s.Close()
		return "", fmt.Errorf("service %s already exists", ServiceName)
	}
	s, err := m.CreateService(ServiceName, exe, mgr.Config{
		DisplayName: "ingressd connector",
		Description: "Connects this site to an ingressd edge over WireGuard",
		StartType:   mgr.StartAutomatic,
	}, o.args()...)
	if err != nil {
		return "", err
	}
	defer s.Close()
	_ = s.SetRecoveryActions([]mgr.RecoveryAction{{Type: mgr.ServiceRestart, Delay: 5_000_000_000}}, 86400)
	if !o.NoStart {
		if err := s.Start(); err != nil {
			return ServiceName, err
		}
	}
	return ServiceName, nil
}

// checkServicePath refuses a binary ordinary users could replace, because
// the service runs it as SYSTEM.
func checkServicePath(exe string) error {
	const fix = `move it to a folder only administrators can write to, such as C:\Program Files\ingressd, then install the service`
	dirs := []string{os.Getenv("SystemDrive") + `\Users`}
	for _, v := range []string{"USERPROFILE", "LOCALAPPDATA", "APPDATA", "TEMP", "TMP", "PUBLIC"} {
		dirs = append(dirs, os.Getenv(v))
	}
	for _, d := range dirs {
		if d != "" && insideDir(exe, d) {
			return fmt.Errorf("%s is in a user folder: %s", exe, fix)
		}
	}
	for _, p := range []string{exe, filepath.Dir(exe)} {
		if usersCanWrite(p) {
			return fmt.Errorf("ordinary users can change %s: %s", p, fix)
		}
	}
	return nil
}

func insideDir(path, dir string) bool {
	rel, err := filepath.Rel(dir, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, `..\`)
}

// usersCanWrite reports whether path's DACL gives a broad group write
// access. A DACL that cannot be read reports false.
func usersCanWrite(path string) bool {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return false
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return false
	}
	if dacl == nil {
		return true
	}
	const write = windows.FILE_WRITE_DATA | windows.FILE_APPEND_DATA | windows.DELETE | windows.WRITE_DAC |
		windows.WRITE_OWNER | windows.GENERIC_WRITE | windows.GENERIC_ALL
	for i := range uint32(dacl.AceCount) {
		var ace *windows.ACCESS_ALLOWED_ACE
		if windows.GetAce(dacl, i, &ace) != nil || ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE ||
			ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 || ace.Mask&write == 0 {
			continue
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		for _, broad := range []windows.WELL_KNOWN_SID_TYPE{windows.WinWorldSid, windows.WinAuthenticatedUserSid, windows.WinBuiltinUsersSid, windows.WinInteractiveSid} {
			if sid.IsWellKnown(broad) {
				return true
			}
		}
	}
	return false
}

type winService struct {
	fn  func(context.Context) error
	err error
}

func (w *winService) Execute(_ []string, req <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- w.fn(ctx) }()
	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for {
		select {
		case err := <-done:
			cancel()
			w.err = err
			if err != nil {
				return true, 1
			}
			return false, 0
		case c := <-req:
			switch c.Cmd {
			case svc.Interrogate:
				status <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending}
				cancel()
				w.err = <-done
				return false, 0
			}
		}
	}
}

func runService(fn func(context.Context) error) (bool, error) {
	is, err := svc.IsWindowsService()
	if err != nil || !is {
		return false, err
	}
	w := &winService{fn: fn}
	if err := svc.Run(ServiceName, w); err != nil {
		return true, errors.Join(err, w.err)
	}
	return true, w.err
}

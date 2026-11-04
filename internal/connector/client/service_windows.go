// SPDX-License-Identifier: Apache-2.0

package client

import (
	"context"
	"errors"
	"fmt"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// InstallService registers (and starts) a Windows service.
func InstallService(o ServiceOptions) (string, error) {
	exe, err := o.exe()
	if err != nil {
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

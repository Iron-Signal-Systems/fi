// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package install

import (
	"fmt"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

func reconcileFIRuntimeServices(
	plan InstallPlan,
) (func() error, error) {
	manager, err := mgr.Connect()
	if err != nil {
		return nil, fmt.Errorf(
			"connect to service control manager for runtime reconciliation: %w",
			err,
		)
	}
	defer manager.Disconnect()

	type runtimeSnapshot struct {
		Name       string
		WasRunning bool
	}
	var snapshots []runtimeSnapshot

	for _, name := range []string{
		"FIUSNReader",
		"FIObjReader",
		"FICollector",
		"FICRLRefresher",
		"FISender",
	} {
		if !planTargetMutates(
			plan,
			"RUNTIME",
			name,
		) {
			continue
		}

		service, err := manager.OpenService(
			name,
		)
		if err != nil {
			return nil, fmt.Errorf(
				"open service %s for runtime reconciliation: %w",
				name,
				err,
			)
		}

		status, err := service.Query()
		if err != nil {
			service.Close()
			return nil, fmt.Errorf(
				"query service %s for runtime reconciliation: %w",
				name,
				err,
			)
		}

		wasRunning := status.State == svc.Running
		snapshots = append(
			snapshots,
			runtimeSnapshot{
				Name:       name,
				WasRunning: wasRunning,
			},
		)

		if !wasRunning {
			if err := service.Start(); err != nil {
				service.Close()
				return nil, fmt.Errorf(
					"start service %s: %w",
					name,
					err,
				)
			}
			if err := waitServiceState(
				service,
				svc.Running,
				serviceTransitionTimeout,
			); err != nil {
				service.Close()
				return nil, err
			}
		}
		service.Close()
	}

	rollback := func() error {
		manager, err := mgr.Connect()
		if err != nil {
			return err
		}
		defer manager.Disconnect()

		var first error
		for index := len(snapshots) - 1; index >= 0; index-- {
			snapshot := snapshots[index]
			if snapshot.WasRunning {
				continue
			}

			service, err := manager.OpenService(
				snapshot.Name,
			)
			if err != nil {
				if first == nil {
					first = err
				}
				continue
			}
			status, queryErr := service.Query()
			if queryErr == nil &&
				status.State != svc.Stopped {
				if status.State != svc.StopPending {
					_, queryErr = service.Control(
						svc.Stop,
					)
				}
				if queryErr == nil {
					queryErr = waitServiceState(
						service,
						svc.Stopped,
						serviceTransitionTimeout,
					)
				}
			}
			service.Close()
			if queryErr != nil &&
				first == nil {
				first = queryErr
			}
		}
		return first
	}

	return rollback, nil
}

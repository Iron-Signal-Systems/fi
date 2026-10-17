// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package main

import (
	"context"
	"fmt"

	"golang.org/x/sys/windows/svc"
)

const windowsCRLRefresherServiceName = "FICRLRefresher"

type fiCRLRefresherService struct {
	runRuntime func(
		context.Context,
	) error
}

func newFICRLRefresherService() *fiCRLRefresherService {
	return &fiCRLRefresherService{
		runRuntime: func(
			ctx context.Context,
		) error {
			return runRefreshLoop(
				ctx,
				defaultRuntimeConfig(),
				defaultRuntimeDependencies(),
			)
		},
	}
}

func runWindowsCRLRefresherServiceIfNeeded() (
	bool,
	error,
) {
	isService, err :=
		svc.IsWindowsService()
	if err != nil {
		return false, fmt.Errorf(
			"detect FI CRL refresher Windows service context: %w",
			err,
		)
	}

	if !isService {
		return false, nil
	}

	if err :=
		svc.Run(
			windowsCRLRefresherServiceName,
			newFICRLRefresherService(),
		); err != nil {
		return true, fmt.Errorf(
			"run FI CRL refresher Windows service: %w",
			err,
		)
	}

	return true, nil
}

func (
	service *fiCRLRefresherService,
) Execute(
	_ []string,
	requests <-chan svc.ChangeRequest,
	statuses chan<- svc.Status,
) (
	bool,
	uint32,
) {
	statuses <- svc.Status{
		State: svc.StartPending,
	}

	if service == nil ||
		service.runRuntime == nil {
		return false, 1
	}

	ctx, cancel :=
		context.WithCancel(
			context.Background(),
		)
	defer cancel()

	done :=
		make(
			chan error,
			1,
		)

	go func() {
		done <- service.runRuntime(
			ctx,
		)
	}()

	running :=
		svc.Status{
			State: svc.Running,
			Accepts: svc.AcceptStop |
				svc.AcceptShutdown,
		}

	statuses <- running

	for {
		select {
		case err := <-done:
			statuses <- svc.Status{
				State: svc.StopPending,
			}

			if err != nil {
				return false, 1
			}

			return false, 0

		case request := <-requests:
			switch request.Cmd {
			case svc.Interrogate:
				statuses <- running

			case svc.Stop, svc.Shutdown:
				statuses <- svc.Status{
					State: svc.StopPending,
				}

				cancel()

				err := <-done

				if err != nil {
					return false, 1
				}

				return false, 0
			}
		}
	}
}

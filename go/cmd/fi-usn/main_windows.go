// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package main

import (
	"context"
	"os"

	"github.com/Iron-Signal-Systems/fi/go/internal/windows/usnbroker"
	"golang.org/x/sys/windows/svc"
)

type fiUSNReaderService struct{}

func main() {
	if err := svc.Run(usnbroker.HelperServiceName, &fiUSNReaderService{}); err != nil {
		os.Exit(1)
	}
}

func (service *fiUSNReaderService) Execute(
	_ []string,
	requests <-chan svc.ChangeRequest,
	statuses chan<- svc.Status,
) (bool, uint32) {
	statuses <- svc.Status{State: svc.StartPending}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- usnbroker.Serve(ctx)
	}()

	running := svc.Status{
		State:   svc.Running,
		Accepts: svc.AcceptStop | svc.AcceptShutdown,
	}
	statuses <- running

	for {
		select {
		case err := <-done:
			statuses <- svc.Status{State: svc.StopPending}
			if err != nil {
				return false, 1
			}
			return false, 0

		case request, ok := <-requests:
			if !ok {
				cancel()
				usnbroker.Wake()
				err := <-done
				if err != nil {
					return false, 1
				}
				return false, 0
			}

			switch request.Cmd {
			case svc.Interrogate:
				statuses <- running

			case svc.Stop, svc.Shutdown:
				statuses <- svc.Status{State: svc.StopPending}
				cancel()
				usnbroker.Wake()
				err := <-done
				if err != nil {
					return false, 1
				}
				return false, 0
			}
		}
	}
}

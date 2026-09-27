// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package main

import (
	"context"
	"errors"
	"fmt"

	"github.com/Iron-Signal-Systems/fi/go/internal/windows/runtimeowner"
	"golang.org/x/sys/windows/svc"
)

const windowsSenderServiceName = "FISender"

type fiSenderService struct {
	loadConfig func() (senderConfig, error)
	runRuntime func(context.Context, senderConfig) error
}

func newFISenderService() *fiSenderService {
	return &fiSenderService{
		loadConfig: parseSenderConfig,
		runRuntime: runSenderRuntimeOwned,
	}
}

func runSenderRuntime(
	ctx context.Context,
	config senderConfig,
) error {
	if ctx == nil {
		return errors.New("context is required")
	}

	ownership, err := runtimeowner.AcquireSender()
	if err != nil {
		return fmt.Errorf(
			"acquire FI sender runtime ownership: %w",
			err,
		)
	}

	runtimeErr := runSenderRuntimeOwned(
		ctx,
		config,
	)

	closeErr := ownership.Close()
	if closeErr != nil {
		closeErr = fmt.Errorf(
			"release FI sender runtime ownership: %w",
			closeErr,
		)
	}

	return errors.Join(
		runtimeErr,
		closeErr,
	)
}

func runSenderRuntimeOwned(
	ctx context.Context,
	config senderConfig,
) error {
	if ctx == nil {
		return errors.New("context is required")
	}

	if config.SpoolDir != "" {
		return runSenderQueue(
			ctx,
			config,
		)
	}

	attemptContext, cancel := context.WithTimeout(
		ctx,
		config.Timeout,
	)
	defer cancel()

	result, err := runSender(
		attemptContext,
		config,
	)
	printSenderResult(result)

	return err
}

func runWindowsSenderServiceIfNeeded() (bool, error) {
	isService, err := svc.IsWindowsService()
	if err != nil {
		return false, fmt.Errorf(
			"detect FI sender Windows service context: %w",
			err,
		)
	}

	if !isService {
		return false, nil
	}

	if err := svc.Run(
		windowsSenderServiceName,
		newFISenderService(),
	); err != nil {
		return true, fmt.Errorf(
			"run FI sender Windows service: %w",
			err,
		)
	}

	return true, nil
}

func (service *fiSenderService) Execute(
	_ []string,
	requests <-chan svc.ChangeRequest,
	statuses chan<- svc.Status,
) (bool, uint32) {
	statuses <- svc.Status{State: svc.StartPending}

	if service == nil ||
		service.loadConfig == nil ||
		service.runRuntime == nil {
		return false, 1
	}

	config, err := service.loadConfig()
	if err != nil {
		return false, 1
	}

	ownership, err := runtimeowner.AcquireSender()
	if err != nil {
		return false, 1
	}

	finish := func(runtimeErr error) (bool, uint32) {
		closeErr := ownership.Close()

		if runtimeErr != nil ||
			closeErr != nil {
			return false, 1
		}

		return false, 0
	}

	ctx, cancel := context.WithCancel(
		context.Background(),
	)
	defer cancel()

	done := make(chan error, 1)

	go func() {
		done <- service.runRuntime(
			ctx,
			config,
		)
	}()

	running := svc.Status{
		State:   svc.Running,
		Accepts: svc.AcceptStop | svc.AcceptShutdown,
	}
	statuses <- running

	for {
		select {
		case err := <-done:
			statuses <- svc.Status{
				State: svc.StopPending,
			}

			return finish(err)

		case request, ok := <-requests:
			if !ok {
				statuses <- svc.Status{
					State: svc.StopPending,
				}

				cancel()

				return finish(<-done)
			}

			switch request.Cmd {
			case svc.Interrogate:
				statuses <- running

			case svc.Stop, svc.Shutdown:
				statuses <- svc.Status{
					State: svc.StopPending,
				}

				cancel()

				return finish(<-done)
			}
		}
	}
}

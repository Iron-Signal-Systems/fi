// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package main

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Iron-Signal-Systems/fi/go/internal/windows/runtimeowner"

	"golang.org/x/sys/windows/svc"
)

type senderServiceExecutionResult struct {
	exitCode        uint32
	serviceSpecific bool
}

func TestFISenderServiceConfigurationFailure(t *testing.T) {
	statuses := make(chan svc.Status, 2)
	runtimeCalled := false

	service := &fiSenderService{
		loadConfig: func() (senderConfig, error) {
			return senderConfig{}, errors.New("configuration failed")
		},
		runRuntime: func(context.Context, senderConfig) error {
			runtimeCalled = true
			return nil
		},
	}

	serviceSpecific, exitCode := service.Execute(
		nil,
		make(chan svc.ChangeRequest),
		statuses,
	)

	if serviceSpecific {
		t.Fatal("service-specific exit code = true, want false")
	}
	if exitCode != 1 {
		t.Fatalf("exit code = %d, want 1", exitCode)
	}
	if runtimeCalled {
		t.Fatal("runtime was called after configuration failure")
	}

	status := receiveSenderServiceStatus(t, statuses)
	if status.State != svc.StartPending {
		t.Fatalf(
			"status = %v, want StartPending",
			status.State,
		)
	}
}

func TestFISenderServiceOwnershipConflictFailsBeforeRunning(t *testing.T) {
	t.Setenv("FI_STATE_DIR", t.TempDir())

	ownership, err := runtimeowner.AcquireSender()
	if err != nil {
		t.Fatal(err)
	}
	defer ownership.Close()

	statuses := make(chan svc.Status, 4)
	runtimeCalled := false

	service := &fiSenderService{
		loadConfig: func() (senderConfig, error) {
			return senderConfig{}, nil
		},
		runRuntime: func(context.Context, senderConfig) error {
			runtimeCalled = true
			return nil
		},
	}

	serviceSpecific, exitCode := service.Execute(
		nil,
		make(chan svc.ChangeRequest),
		statuses,
	)

	if serviceSpecific {
		t.Fatal("service-specific exit code = true, want false")
	}
	if exitCode != 1 {
		t.Fatalf(
			"exit code = %d, want 1",
			exitCode,
		)
	}
	if runtimeCalled {
		t.Fatal(
			"sender runtime started without exclusive ownership",
		)
	}

	status := receiveSenderServiceStatus(
		t,
		statuses,
	)
	if status.State != svc.StartPending {
		t.Fatalf(
			"first status = %v, want StartPending",
			status.State,
		)
	}

	select {
	case status := <-statuses:
		if status.State == svc.Running {
			t.Fatal(
				"FISender reported Running without exclusive ownership",
			)
		}

		t.Fatalf(
			"unexpected additional service status %v",
			status.State,
		)

	default:
	}
}
func TestFISenderServiceRuntimeFailure(t *testing.T) {
	t.Setenv("FI_STATE_DIR", t.TempDir())
	statuses := make(chan svc.Status, 4)
	runtimeRelease := make(chan struct{})

	service := &fiSenderService{
		loadConfig: func() (senderConfig, error) {
			return senderConfig{}, nil
		},
		runRuntime: func(context.Context, senderConfig) error {
			<-runtimeRelease
			return errors.New("runtime failed")
		},
	}

	results := make(chan senderServiceExecutionResult, 1)

	go func() {
		serviceSpecific, exitCode := service.Execute(
			nil,
			make(chan svc.ChangeRequest),
			statuses,
		)

		results <- senderServiceExecutionResult{
			exitCode:        exitCode,
			serviceSpecific: serviceSpecific,
		}
	}()

	if status := receiveSenderServiceStatus(t, statuses); status.State != svc.StartPending {
		t.Fatalf(
			"first status = %v, want StartPending",
			status.State,
		)
	}

	if status := receiveSenderServiceStatus(t, statuses); status.State != svc.Running {
		t.Fatalf(
			"second status = %v, want Running",
			status.State,
		)
	}

	close(runtimeRelease)

	if status := receiveSenderServiceStatus(t, statuses); status.State != svc.StopPending {
		t.Fatalf(
			"third status = %v, want StopPending",
			status.State,
		)
	}

	result := receiveSenderServiceResult(t, results)

	if result.serviceSpecific {
		t.Fatal("service-specific exit code = true, want false")
	}
	if result.exitCode != 1 {
		t.Fatalf(
			"exit code = %d, want 1",
			result.exitCode,
		)
	}
}

func TestFISenderServiceStopCancelsRuntime(t *testing.T) {
	t.Setenv("FI_STATE_DIR", t.TempDir())
	requests := make(chan svc.ChangeRequest, 1)
	statuses := make(chan svc.Status, 4)

	service := &fiSenderService{
		loadConfig: func() (senderConfig, error) {
			return senderConfig{}, nil
		},
		runRuntime: func(
			ctx context.Context,
			_ senderConfig,
		) error {
			<-ctx.Done()
			return nil
		},
	}

	results := make(chan senderServiceExecutionResult, 1)

	go func() {
		serviceSpecific, exitCode := service.Execute(
			nil,
			requests,
			statuses,
		)

		results <- senderServiceExecutionResult{
			exitCode:        exitCode,
			serviceSpecific: serviceSpecific,
		}
	}()

	if status := receiveSenderServiceStatus(t, statuses); status.State != svc.StartPending {
		t.Fatalf(
			"first status = %v, want StartPending",
			status.State,
		)
	}

	if status := receiveSenderServiceStatus(t, statuses); status.State != svc.Running {
		t.Fatalf(
			"second status = %v, want Running",
			status.State,
		)
	}

	requests <- svc.ChangeRequest{Cmd: svc.Stop}

	if status := receiveSenderServiceStatus(t, statuses); status.State != svc.StopPending {
		t.Fatalf(
			"third status = %v, want StopPending",
			status.State,
		)
	}

	result := receiveSenderServiceResult(t, results)

	if result.serviceSpecific {
		t.Fatal("service-specific exit code = true, want false")
	}
	if result.exitCode != 0 {
		t.Fatalf(
			"exit code = %d, want 0",
			result.exitCode,
		)
	}
}

func TestFISenderServiceInterrogateReturnsRunning(t *testing.T) {
	t.Setenv("FI_STATE_DIR", t.TempDir())
	requests := make(chan svc.ChangeRequest, 1)
	statuses := make(chan svc.Status, 4)

	service := &fiSenderService{
		loadConfig: func() (senderConfig, error) {
			return senderConfig{}, nil
		},
		runRuntime: func(
			ctx context.Context,
			_ senderConfig,
		) error {
			<-ctx.Done()
			return nil
		},
	}

	results := make(chan senderServiceExecutionResult, 1)

	go func() {
		serviceSpecific, exitCode := service.Execute(
			nil,
			requests,
			statuses,
		)

		results <- senderServiceExecutionResult{
			exitCode:        exitCode,
			serviceSpecific: serviceSpecific,
		}
	}()

	receiveSenderServiceStatus(t, statuses)

	if status := receiveSenderServiceStatus(t, statuses); status.State != svc.Running {
		t.Fatalf(
			"second status = %v, want Running",
			status.State,
		)
	}

	requests <- svc.ChangeRequest{Cmd: svc.Interrogate}

	if status := receiveSenderServiceStatus(t, statuses); status.State != svc.Running {
		t.Fatalf(
			"interrogate status = %v, want Running",
			status.State,
		)
	}

	requests <- svc.ChangeRequest{Cmd: svc.Stop}
	receiveSenderServiceStatus(t, statuses)

	result := receiveSenderServiceResult(t, results)
	if result.exitCode != 0 {
		t.Fatalf(
			"exit code = %d, want 0",
			result.exitCode,
		)
	}
}

func TestRunSenderRuntimeRejectsNilContext(t *testing.T) {
	if err := runSenderRuntime(
		nil,
		senderConfig{},
	); err == nil {
		t.Fatal("runSenderRuntime(nil) error = nil")
	}
}

func receiveSenderServiceResult(
	t *testing.T,
	results <-chan senderServiceExecutionResult,
) senderServiceExecutionResult {
	t.Helper()

	select {
	case result := <-results:
		return result

	case <-time.After(2 * time.Second):
		t.Fatal(
			"timed out waiting for FI sender service result",
		)
		return senderServiceExecutionResult{}
	}
}

func receiveSenderServiceStatus(
	t *testing.T,
	statuses <-chan svc.Status,
) svc.Status {
	t.Helper()

	select {
	case status := <-statuses:
		return status

	case <-time.After(2 * time.Second):
		t.Fatal(
			"timed out waiting for FI sender service status",
		)
		return svc.Status{}
	}
}

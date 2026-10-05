// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package main

import (
	"context"
	"testing"
	"time"

	"golang.org/x/sys/windows/svc"
)

func TestFICRLRefresherServiceStopsCleanly(
	t *testing.T,
) {
	service :=
		&fiCRLRefresherService{
			runRuntime: func(
				ctx context.Context,
			) error {
				<-ctx.Done()

				return nil
			},
		}

	requests :=
		make(
			chan svc.ChangeRequest,
			1,
		)

	statuses :=
		make(
			chan svc.Status,
			4,
		)

	type executeResult struct {
		serviceSpecific bool
		exitCode        uint32
	}

	done :=
		make(
			chan executeResult,
			1,
		)

	go func() {
		specific, exitCode :=
			service.Execute(
				nil,
				requests,
				statuses,
			)

		done <- executeResult{
			serviceSpecific: specific,
			exitCode:        exitCode,
		}
	}()

	assertServiceState(
		t,
		statuses,
		svc.StartPending,
	)

	assertServiceState(
		t,
		statuses,
		svc.Running,
	)

	requests <- svc.ChangeRequest{
		Cmd: svc.Stop,
	}

	assertServiceState(
		t,
		statuses,
		svc.StopPending,
	)

	select {
	case result := <-done:
		if result.serviceSpecific {
			t.Fatal(
				"unexpected service-specific exit",
			)
		}

		if result.exitCode != 0 {
			t.Fatalf(
				"exit code=%d want=0",
				result.exitCode,
			)
		}

	case <-time.After(
		2 * time.Second,
	):
		t.Fatal(
			"service did not stop after cancellation",
		)
	}
}

func assertServiceState(
	t *testing.T,
	statuses <-chan svc.Status,
	want svc.State,
) {
	t.Helper()

	select {
	case status := <-statuses:
		if status.State != want {
			t.Fatalf(
				"service state=%v want=%v",
				status.State,
				want,
			)
		}

	case <-time.After(
		2 * time.Second,
	):
		t.Fatalf(
			"timed out waiting for service state=%v",
			want,
		)
	}
}

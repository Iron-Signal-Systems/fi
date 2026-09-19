// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package main

import (
	"context"
	"testing"
	"time"
)

func TestResolveServiceUSNIntervalDefaultsToTenMinutes(
	t *testing.T,
) {
	t.Setenv(
		serviceUSNIntervalEnvironment,
		"",
	)

	got, err := resolveServiceUSNInterval()
	if err != nil {
		t.Fatal(err)
	}

	if got != 10*time.Minute {
		t.Fatalf(
			"USN interval = %s, want 10m",
			got,
		)
	}
}

func TestResolveServiceUSNIntervalAcceptsOverride(
	t *testing.T,
) {
	t.Setenv(
		serviceUSNIntervalEnvironment,
		"15m",
	)

	got, err := resolveServiceUSNInterval()
	if err != nil {
		t.Fatal(err)
	}

	if got != 15*time.Minute {
		t.Fatalf(
			"USN interval = %s, want 15m",
			got,
		)
	}
}

func TestRunServiceUSNLoopSchedulesCatchUpAndStops(
	t *testing.T,
) {
	ctx, cancel := context.WithCancel(
		context.Background(),
	)
	defer cancel()

	catchUpRan := make(
		chan struct{},
		1,
	)

	records := make(
		chan serviceRuntimeRecord,
		1,
	)

	done := make(
		chan error,
		1,
	)

	go func() {
		done <- runServiceUSNLoop(
			ctx,
			20*time.Millisecond,
			func(
				context.Context,
			) (
				serviceUSNCatchUpSummary,
				error,
			) {
				select {
				case catchUpRan <- struct{}{}:
				default:
				}

				return serviceUSNCatchUpSummary{
					ConfiguredRoots: 1,
					CompletedRoots:  1,
				}, nil
			},
			func(
				record serviceRuntimeRecord,
			) error {
				records <- record
				cancel()
				return nil
			},
		)
	}()

	select {
	case <-catchUpRan:

	case <-time.After(
		2 * time.Second,
	):
		t.Fatal(
			"independent service USN catch-up was not scheduled",
		)
	}

	select {
	case record := <-records:
		if record.RecordKind != "USNCatchUp" {
			t.Fatalf(
				"record kind = %q, want USNCatchUp",
				record.RecordKind,
			)
		}

		if record.USNInterval != "20ms" {
			t.Fatalf(
				"USN interval = %q, want 20ms",
				record.USNInterval,
			)
		}

		if record.Outcome != serviceOutcomeComplete {
			t.Fatalf(
				"outcome = %q, want Complete",
				record.Outcome,
			)
		}

	case <-time.After(
		2 * time.Second,
	):
		t.Fatal(
			"service USN runtime record was not appended",
		)
	}

	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}

	case <-time.After(
		2 * time.Second,
	):
		t.Fatal(
			"service USN loop did not stop after cancellation",
		)
	}
}

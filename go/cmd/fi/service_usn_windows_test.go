// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package main

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

func TestResolveServiceUSNIntervalUsesConfiguredValue(t *testing.T) {
	got, err := resolveServiceUSNInterval(10 * time.Minute)
	if err != nil {
		t.Fatal(err)
	}

	if got != 10*time.Minute {
		t.Fatalf("USN interval = %s, want 10m", got)
	}
	if currentServiceUSNInterval() != "10m0s" {
		t.Fatalf("current USN interval = %q", currentServiceUSNInterval())
	}
}

func TestResolveServiceUSNIntervalRejectsNonPositiveValue(t *testing.T) {
	if _, err := resolveServiceUSNInterval(0); err == nil {
		t.Fatal("resolveServiceUSNInterval(0) error = nil")
	}
}

func TestWriteServiceUSNCatchUpUsesStartupSnapshotWithoutConfigReload(t *testing.T) {
	t.Setenv("ProgramData", t.TempDir())

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	summary, err := writeServiceUSNCatchUp(
		ctx,
		serviceOperationalSnapshot{
			GovernedRoots: []string{
				`C:\Data\A`,
				`D:\Data\B`,
			},
		},
	)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
	if summary.ConfiguredRoots != 2 {
		t.Fatalf("configured roots = %d, want 2", summary.ConfiguredRoots)
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
func TestServiceRootLockSetSeparatesGovernedRoots(
	t *testing.T,
) {
	set := newServiceRootLockSet()

	rootAFirst := set.lockFor("root-a")
	rootASecond := set.lockFor("root-a")
	rootB := set.lockFor("root-b")

	if rootAFirst != rootASecond {
		t.Fatal("same governed-root scope received different locks")
	}
	if rootAFirst == rootB {
		t.Fatal("different governed-root scopes shared one lock")
	}
}

func TestWriteServiceUSNRootSkipsBusySameRoot(
	t *testing.T,
) {
	governedRoot := `T:\FI-Test-Busy-Root`
	scopeID := configuredScopeID(governedRoot)
	rootLock := serviceRootLocks.lockFor(scopeID)

	rootLock.Lock()
	defer rootLock.Unlock()

	started := time.Now()
	result, err := writeServiceUSNRoot(
		context.Background(),
		governedRoot,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Skipped {
		t.Fatal("busy same-root USN pass was not skipped")
	}
	if elapsed := time.Since(started); elapsed > 250*time.Millisecond {
		t.Fatalf(
			"busy same-root USN pass blocked for %s",
			elapsed,
		)
	}
}

func TestRunServiceUSNLoopKeepsFixedCadenceWhilePriorCycleRuns(
	t *testing.T,
) {
	ctx, cancel := context.WithCancel(
		context.Background(),
	)
	defer cancel()

	firstStarted := make(chan struct{})
	secondStarted := make(chan struct{})
	releaseFirst := make(chan struct{})
	done := make(chan error, 1)

	var calls atomic.Int32

	go func() {
		done <- runServiceUSNLoop(
			ctx,
			20*time.Millisecond,
			func(
				cycleCtx context.Context,
			) (
				serviceUSNCatchUpSummary,
				error,
			) {
				call := calls.Add(1)

				switch call {
				case 1:
					close(firstStarted)
					select {
					case <-releaseFirst:
					case <-cycleCtx.Done():
						return serviceUSNCatchUpSummary{}, cycleCtx.Err()
					}

				case 2:
					close(secondStarted)
				}

				return serviceUSNCatchUpSummary{
					ConfiguredRoots: 1,
					CompletedRoots:  1,
				}, nil
			},
			func(serviceRuntimeRecord) error {
				return nil
			},
		)
	}()

	select {
	case <-firstStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("first USN cycle did not start")
	}

	select {
	case <-secondStarted:
	case <-time.After(250 * time.Millisecond):
		t.Fatal("second USN cycle was delayed by the first cycle")
	}

	close(releaseFirst)
	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("service USN loop did not stop")
	}
}

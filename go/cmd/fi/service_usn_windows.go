// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package main

import (
	"context"
	"errors"
	"fmt"
	"github.com/Iron-Signal-Systems/fi/go/internal/records"
	"github.com/Iron-Signal-Systems/fi/go/internal/windows/checkpoint"
	"github.com/Iron-Signal-Systems/fi/go/internal/windows/usn"
	"sync"
	"time"
)

var (
	serviceRuntimeLogMu  sync.Mutex
	serviceUSNIntervalMu sync.RWMutex
	serviceUSNInterval   string
	serviceRootLocks     = newServiceRootLockSet()
)

type serviceUSNCatchUpFunc func(
	context.Context,
) (serviceUSNCatchUpSummary, error)

type serviceUSNCatchUpSummary struct {
	ConfiguredRoots int
	CompletedRoots  int
	PartialRoots    int
	SkippedRoots    int
	FailedRoots     int
}

type serviceUSNRootResult struct {
	Partial bool
	Skipped bool
}

// serviceRootLockSet serializes checkpoint-owning work only within the same
// governed root. A long baseline or reconciliation on one root must never
// block independent USN catch-up for a different governed root.
type serviceRootLockSet struct {
	mu    sync.Mutex
	locks map[string]*sync.Mutex
}

func newServiceRootLockSet() *serviceRootLockSet {
	return &serviceRootLockSet{
		locks: make(map[string]*sync.Mutex),
	}
}

func (set *serviceRootLockSet) lockFor(scopeID string) *sync.Mutex {
	set.mu.Lock()
	defer set.mu.Unlock()

	lock := set.locks[scopeID]
	if lock != nil {
		return lock
	}

	lock = &sync.Mutex{}
	set.locks[scopeID] = lock
	return lock
}

func resolveServiceUSNInterval(interval time.Duration) (time.Duration, error) {
	if interval <= 0 {
		return 0, errors.New("service USN interval must be greater than zero")
	}

	serviceUSNIntervalMu.Lock()
	serviceUSNInterval = interval.String()
	serviceUSNIntervalMu.Unlock()

	return interval, nil
}

func currentServiceUSNInterval() string {
	serviceUSNIntervalMu.RLock()
	defer serviceUSNIntervalMu.RUnlock()

	return serviceUSNInterval
}

func runServiceUSNLoop(
	ctx context.Context,
	interval time.Duration,
	catchUp serviceUSNCatchUpFunc,
	appendRecord serviceAppendRecordFunc,
) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if interval <= 0 {
		return errors.New(
			"service USN interval must be greater than zero",
		)
	}
	if catchUp == nil || appendRecord == nil {
		return errors.New(
			"service USN runtime dependency is nil",
		)
	}

	loopCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	cycleErrors := make(chan error, 1)
	var cycles sync.WaitGroup

	launchCycle := func() {
		cycles.Add(1)
		go func() {
			defer cycles.Done()

			if err := runServiceUSNCycle(
				loopCtx,
				interval,
				catchUp,
				appendRecord,
			); err != nil {
				select {
				case cycleErrors <- err:
				default:
				}
			}
		}()
	}

	for {
		select {
		case <-ctx.Done():
			cancel()
			cycles.Wait()
			return nil

		case err := <-cycleErrors:
			cancel()
			cycles.Wait()
			return err

		case <-ticker.C:
			// Preserve fixed cadence. Per-root TryLock semantics make a root
			// already doing baseline/USN work a quick skip rather than a global
			// scheduling stall.
			launchCycle()
		}
	}
}

func runServiceUSNCycle(
	ctx context.Context,
	interval time.Duration,
	catchUp serviceUSNCatchUpFunc,
	appendRecord serviceAppendRecordFunc,
) error {
	summary, catchErr := catchUp(ctx)

	outcome := serviceOutcomeComplete

	switch {
	case catchErr != nil &&
		errors.Is(catchErr, context.Canceled) &&
		ctx.Err() != nil:
		outcome = serviceOutcomeInterrupted

	case catchErr != nil:
		outcome = serviceOutcomeFailed

	case summary.PartialRoots > 0 ||
		summary.SkippedRoots > 0:
		outcome = serviceOutcomePartial
	}

	record := serviceRuntimeRecord{
		Version:         serviceRuntimeVersion,
		RecordKind:      "USNCatchUp",
		ObservedAt:      serviceNow(),
		USNInterval:     interval.String(),
		Outcome:         outcome,
		ConfiguredRoots: summary.ConfiguredRoots,
		CompletedRoots:  summary.CompletedRoots,
		PartialRoots:    summary.PartialRoots,
		SkippedRoots:    summary.SkippedRoots,
		FailedRoots:     summary.FailedRoots,
	}

	if catchErr != nil {
		record.Error = catchErr.Error()
	}

	return appendRecord(record)
}

func writeServiceUSNCatchUp(
	ctx context.Context,
	snapshot serviceOperationalSnapshot,
) (serviceUSNCatchUpSummary, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	summary := serviceUSNCatchUpSummary{
		ConfiguredRoots: len(snapshot.GovernedRoots),
	}

	var runErr error

	type rootOutcome struct {
		governedRoot string
		result       serviceUSNRootResult
		err          error
	}

	outcomes := make(
		chan rootOutcome,
		len(snapshot.GovernedRoots),
	)

	var roots sync.WaitGroup

	for _, governedRoot := range snapshot.GovernedRoots {
		if err := ctx.Err(); err != nil {
			return summary, errors.Join(runErr, err)
		}

		roots.Add(1)
		go func(root string) {
			defer roots.Done()

			result, rootErr := writeServiceUSNRoot(
				ctx,
				root,
			)

			outcomes <- rootOutcome{
				governedRoot: root,
				result:       result,
				err:          rootErr,
			}
		}(governedRoot)
	}

	roots.Wait()
	close(outcomes)

	for outcome := range outcomes {
		if outcome.err != nil {
			summary.FailedRoots++

			runErr = errors.Join(
				runErr,
				fmt.Errorf(
					"service USN root %q: %w",
					outcome.governedRoot,
					outcome.err,
				),
			)

			continue
		}

		switch {
		case outcome.result.Skipped:
			summary.SkippedRoots++

		case outcome.result.Partial:
			summary.PartialRoots++

		default:
			summary.CompletedRoots++
		}
	}

	return summary, runErr
}

func writeServiceUSNRoot(
	ctx context.Context,
	governedRoot string,
) (serviceUSNRootResult, error) {
	scopeID := configuredScopeID(
		governedRoot,
	)

	rootLock := serviceRootLocks.lockFor(
		scopeID,
	)

	// Never let a long same-root baseline/reconciliation stall the independent
	// USN scheduler. The configured operation already owns this root and will
	// perform its required baseline/catch-up semantics before releasing it.
	if !rootLock.TryLock() {
		return serviceUSNRootResult{Skipped: true}, nil
	}
	defer rootLock.Unlock()

	statePath, err := checkpoint.DefaultPath(
		scopeID,
	)
	if err != nil {
		return serviceUSNRootResult{}, err
	}

	checkpointFound, err := fileExists(
		statePath,
	)
	if err != nil {
		return serviceUSNRootResult{}, err
	}

	if !checkpointFound {
		// Initial onboarding owns baseline/checkpoint creation. An independent
		// USN pass must not compete with that baseline.
		return serviceUSNRootResult{
			Skipped: true,
		}, nil
	}

	assessment, err := checkpoint.Check(
		ctx,
		scopeID,
		governedRoot,
		statePath,
	)
	if err != nil {
		return serviceUSNRootResult{}, err
	}

	if assessment.Status != checkpoint.ContinuityContinuous {
		// Full configured collection owns continuity-gap reconciliation.
		return serviceUSNRootResult{
			Skipped: true,
		}, nil
	}

	comparison, err := compareUSN(
		assessment.Checkpoint.NextUSN,
		assessment.JournalState.NextUSN,
	)
	if err != nil {
		return serviceUSNRootResult{}, err
	}

	if comparison >= 0 {
		return serviceUSNRootResult{}, nil
	}

	targetUSN := assessment.JournalState.NextUSN

	var passes []usnSpoolNextSummary

	_, opErr := runConfiguredOperation(
		scopeID,
		records.OperationUSNCatchUp,
		func() error {
			var err error

			passes, _, err = catchUpConfiguredRoot(
				usn.WithoutInterruptedRecovery(ctx),
				scopeID,
				governedRoot,
				targetUSN,
			)

			return err
		},
	)

	if opErr != nil {
		return serviceUSNRootResult{}, opErr
	}

	return serviceUSNRootResult{
		Partial: configuredUSNPassesPartial(
			passes,
		),
	}, nil
}

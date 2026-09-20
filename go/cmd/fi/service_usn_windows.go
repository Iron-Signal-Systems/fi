// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/Iron-Signal-Systems/fi/go/internal/config"
	"github.com/Iron-Signal-Systems/fi/go/internal/records"
	"github.com/Iron-Signal-Systems/fi/go/internal/spool"
	"github.com/Iron-Signal-Systems/fi/go/internal/windows/checkpoint"
	"github.com/Iron-Signal-Systems/fi/go/internal/windows/usn"
)

const (
	serviceUSNIntervalEnvironment = "FI_SERVICE_USN_EVERY"
	serviceUSNIntervalDefault     = "10m"
)

var (
	serviceRuntimeLogMu  sync.Mutex
	serviceUSNIntervalMu sync.RWMutex
	serviceUSNInterval   = serviceUSNIntervalDefault
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

func resolveServiceUSNInterval() (time.Duration, error) {
	value := strings.TrimSpace(
		os.Getenv(serviceUSNIntervalEnvironment),
	)
	if value == "" {
		value = serviceUSNIntervalDefault
	}

	interval, err := parseServiceInterval(
		serviceUSNIntervalEnvironment,
		value,
	)
	if err != nil {
		return 0, err
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
) (serviceUSNCatchUpSummary, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	value, _, err := config.LoadDefault()
	if err != nil {
		return serviceUSNCatchUpSummary{}, err
	}

	summary := serviceUSNCatchUpSummary{
		ConfiguredRoots: len(value.GovernedRoots),
	}

	var runErr error

	type rootOutcome struct {
		governedRoot string
		result       serviceUSNRootResult
		err          error
	}

	outcomes := make(
		chan rootOutcome,
		len(value.GovernedRoots),
	)

	var roots sync.WaitGroup

	for _, governedRoot := range value.GovernedRoots {
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

// writeServiceConfiguredCollector keeps the configured/full collection lane
// independent from the 10-minute USN lane while serializing checkpoint-owning
// work only within the same governed root.
//
// Root synchronization is keyed by governed-root scope ID. A long operation on
// one root therefore cannot block an unrelated root's independent USN pass.
// Shared spool publication/recovery uses the spool publication boundary instead
// of a root lock.
func writeServiceConfiguredCollector(
	ctx context.Context,
) (configuredRunSummary, error) {
	value, configPath, err := config.LoadDefault()
	if err != nil {
		return configuredRunSummary{}, err
	}

	summary := configuredRunSummary{
		ConfigPath:      configPath,
		VersionID:       value.VersionID,
		ConfiguredRoots: len(value.GovernedRoots),
		Complete:        true,
		Roots:           make([]configuredRootSummary, 0, len(value.GovernedRoots)),
		Semantics:       "FI processes Windows Security activity and each configured governed root as independent source observations. Major configured operations use append-only Started/Finished lifecycle journals so an unclosed operation is explicitly recovered as Interrupted after process restart. Interrupted FI spool artifacts are preserved separately and are never promoted into accepted batches or used to advance source checkpoints. Source facts, continuity gaps, checkpoints, spool recovery state, and operation lifecycle records remain separate records with separate meanings.",
	}

	spoolDir, err := spool.DefaultDir()
	if err != nil {
		summary.Complete = false
		return summary, err
	}

	// Interrupted-artifact recovery is a spool-publication concern, not a
	// governed-root checkpoint concern. Use the existing short-lived,
	// process-safe publication boundary so recovery never serializes unrelated
	// roots for the duration of a filesystem baseline.
	boundary, boundaryErr := spool.AcquirePublishBoundary()
	if boundaryErr != nil {
		summary.Complete = false
		return summary, fmt.Errorf(
			"acquire FI spool publish boundary for interrupted recovery: %w",
			boundaryErr,
		)
	}

	spoolRecovery, recoveryErr := spool.PreserveInterruptedArtifacts(
		spoolDir,
	)
	recoveryErr = errors.Join(recoveryErr, boundary.Close())

	summary.SpoolRecovery = spoolRecovery

	if recoveryErr != nil {
		summary.Complete = false
		return summary, fmt.Errorf(
			"preserve interrupted spool artifacts: %w",
			recoveryErr,
		)
	}

	var runErr error

	securityPrepared, securityPrepareErr := prepareConfiguredSecurity()
	if securityPrepareErr != nil {
		securityPrepared.Summary.Status = configuredSecurityFailed
		securityPrepared.Summary.Error = securityPrepareErr.Error()
		summary.WindowsSecurity = securityPrepared.Summary
		summary.Complete = false
		runErr = errors.Join(
			runErr,
			fmt.Errorf(
				"Windows Security source: %w",
				securityPrepareErr,
			),
		)
	}

	for _, governedRoot := range value.GovernedRoots {
		if err := ctx.Err(); err != nil {
			summary.Complete = false
			runErr = errors.Join(runErr, err)
			break
		}

		scopeID := configuredScopeID(
			governedRoot,
		)
		rootLock := serviceRootLocks.lockFor(
			scopeID,
		)

		rootLock.Lock()
		rootSummary, rootErr := writeConfiguredRoot(
			ctx,
			governedRoot,
		)
		rootLock.Unlock()

		if rootErr != nil {
			rootSummary.Status = configuredStatusFailed
			rootSummary.Error = rootErr.Error()
			summary.FailedRoots++
			summary.Complete = false
			runErr = errors.Join(
				runErr,
				fmt.Errorf(
					"configured root %q: %w",
					governedRoot,
					rootErr,
				),
			)
		} else {
			switch rootSummary.Status {
			case configuredStatusPartial:
				summary.PartialRoots++
				summary.Complete = false

			default:
				rootSummary.Status = configuredStatusComplete
				summary.CompletedRoots++
			}
		}

		summary.Roots = append(
			summary.Roots,
			rootSummary,
		)
	}

	if securityPrepareErr == nil {
		securitySummary, securityErr := finishConfiguredSecurity(
			ctx,
			securityPrepared,
			configuredSecurityScopes(
				value.GovernedRoots,
			),
		)

		if securityErr != nil {
			securitySummary.Status = configuredSecurityFailed
			securitySummary.Error = securityErr.Error()
			summary.Complete = false
			runErr = errors.Join(
				runErr,
				fmt.Errorf(
					"Windows Security source: %w",
					securityErr,
				),
			)
		}

		summary.WindowsSecurity = securitySummary

		if securitySummary.Coverage != nil &&
			securitySummary.Coverage.Status == "Ready" {
			summary.MonitoringPrerequisitesSatisfied = true
		}
	}

	return summary, runErr
}

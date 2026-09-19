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
	serviceRootUSNMu     sync.Mutex
	serviceRuntimeLogMu  sync.Mutex
	serviceUSNIntervalMu sync.RWMutex
	serviceUSNInterval   = serviceUSNIntervalDefault
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

	timer := time.NewTimer(interval)
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil

		case <-timer.C:
			if err := runServiceUSNCycle(
				ctx,
				interval,
				catchUp,
				appendRecord,
			); err != nil {
				return err
			}

			if ctx.Err() != nil {
				return nil
			}

			timer.Reset(interval)
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

	for _, governedRoot := range value.GovernedRoots {
		if err := ctx.Err(); err != nil {
			return summary, errors.Join(runErr, err)
		}

		result, rootErr := writeServiceUSNRoot(
			ctx,
			governedRoot,
		)

		if rootErr != nil {
			summary.FailedRoots++

			runErr = errors.Join(
				runErr,
				fmt.Errorf(
					"service USN root %q: %w",
					governedRoot,
					rootErr,
				),
			)

			continue
		}

		switch {
		case result.Skipped:
			summary.SkippedRoots++

		case result.Partial:
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
	serviceRootUSNMu.Lock()
	defer serviceRootUSNMu.Unlock()

	scopeID := configuredScopeID(
		governedRoot,
	)

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
// independent from the 10-minute USN lane while serializing the short pieces
// that own a governed-root USN checkpoint.
//
// The long Windows Security reconciliation/full-state walk is intentionally not
// covered by serviceRootUSNMu. That is the path we want the 200K-file test to
// exercise concurrently with independent USN catch-up.
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

	// The independent USN lane writes to the same FI spool. Serialize this
	// mechanical interrupted-artifact sweep with root USN publication so a
	// live USN .open batch can never be mistaken for abandoned work.
	serviceRootUSNMu.Lock()
	spoolRecovery, recoveryErr := spool.PreserveInterruptedArtifacts(
		spoolDir,
	)
	serviceRootUSNMu.Unlock()

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

		serviceRootUSNMu.Lock()
		rootSummary, rootErr := writeConfiguredRoot(
			ctx,
			governedRoot,
		)
		serviceRootUSNMu.Unlock()

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

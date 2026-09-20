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
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Iron-Signal-Systems/fi/go/internal/config"
	"github.com/Iron-Signal-Systems/fi/go/internal/records"
	"github.com/Iron-Signal-Systems/fi/go/internal/windows/securityevent"
)

const (
	serviceWindowsSecurityIntervalEnvironment = "FI_SERVICE_WINDOWS_SECURITY_EVERY"
	serviceWindowsSecurityIntervalDefault     = "1m"
)

var (
	serviceWindowsSecurityIntervalMu sync.RWMutex
	serviceWindowsSecurityInterval   = serviceWindowsSecurityIntervalDefault
)

type serviceWindowsSecurityCycleSummary struct {
	Status                  configuredSecurityStatus
	ReadWindows             int
	SourceMatchingEvents    int
	SelectedEvents          int
	IgnoredEvents           int
	VerifiedBatches         int
	CheckpointAdvanced      bool
	CheckpointReinitialized bool
	ContinuityGap           bool
	MoreAvailable           bool
}

// serviceWindowsSecuritySource is the scheduler-facing contract. The live
// implementation owns one Windows Security checkpoint and one sequential stream
// of bounded EventRecordID windows. The interface keeps scheduler tests free of
// Windows Event Log dependencies.
type serviceWindowsSecuritySource interface {
	Collect(context.Context) (serviceWindowsSecurityCycleSummary, error)
}

type liveServiceWindowsSecuritySource struct{}

func (liveServiceWindowsSecuritySource) Collect(
	ctx context.Context,
) (serviceWindowsSecurityCycleSummary, error) {
	return writeServiceWindowsSecurity(ctx)
}

func resolveServiceWindowsSecurityInterval() (time.Duration, error) {
	value := strings.TrimSpace(os.Getenv(serviceWindowsSecurityIntervalEnvironment))
	if value == "" {
		value = serviceWindowsSecurityIntervalDefault
	}

	interval, err := parseServiceInterval(
		serviceWindowsSecurityIntervalEnvironment,
		value,
	)
	if err != nil {
		return 0, err
	}

	serviceWindowsSecurityIntervalMu.Lock()
	serviceWindowsSecurityInterval = interval.String()
	serviceWindowsSecurityIntervalMu.Unlock()

	return interval, nil
}

func currentServiceWindowsSecurityInterval() string {
	serviceWindowsSecurityIntervalMu.RLock()
	defer serviceWindowsSecurityIntervalMu.RUnlock()

	return serviceWindowsSecurityInterval
}

// runServiceWindowsSecurityLoop starts immediately, never overlaps itself, and
// drains backlog without an interval sleep while MoreAvailable remains true.
// Once caught up it returns to the configured steady-state cadence.
func runServiceWindowsSecurityLoop(
	ctx context.Context,
	interval time.Duration,
	source serviceWindowsSecuritySource,
	appendRecord serviceAppendRecordFunc,
) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if interval <= 0 {
		return errors.New("service Windows Security interval must be greater than zero")
	}
	if source == nil || appendRecord == nil {
		return errors.New("service Windows Security runtime dependency is nil")
	}

	for {
		if err := ctx.Err(); err != nil {
			return nil
		}

		summary, collectErr := source.Collect(ctx)
		outcome := serviceOutcomeComplete
		switch {
		case collectErr != nil && errors.Is(collectErr, context.Canceled) && ctx.Err() != nil:
			outcome = serviceOutcomeInterrupted
		case collectErr != nil:
			outcome = serviceOutcomeFailed
		case summary.Status != configuredSecurityComplete:
			outcome = serviceOutcomePartial
		}

		record := serviceRuntimeRecord{
			Version:                    serviceRuntimeVersion,
			RecordKind:                 "WindowsSecurityCatchUp",
			ObservedAt:                 serviceNow(),
			SecurityInterval:           interval.String(),
			Outcome:                    outcome,
			SecurityReadWindows:        summary.ReadWindows,
			SecuritySourceMatches:      summary.SourceMatchingEvents,
			SecuritySelectedEvents:     summary.SelectedEvents,
			SecurityIgnoredEvents:      summary.IgnoredEvents,
			SecurityVerifiedBatches:    summary.VerifiedBatches,
			SecurityCheckpointAdvanced: summary.CheckpointAdvanced,
			SecurityCheckpointRebased:  summary.CheckpointReinitialized,
			SecurityContinuityGap:      summary.ContinuityGap,
			SecurityMoreAvailable:      summary.MoreAvailable,
		}
		if collectErr != nil {
			record.Error = collectErr.Error()
		}

		appendErr := appendRecord(record)
		if err := errors.Join(collectErr, appendErr); err != nil {
			if errors.Is(err, context.Canceled) && ctx.Err() != nil {
				return nil
			}
			return err
		}

		if summary.MoreAvailable {
			continue
		}

		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			return nil
		case <-timer.C:
		}
	}
}

func writeServiceWindowsSecurity(
	ctx context.Context,
) (serviceWindowsSecurityCycleSummary, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	value, _, err := config.LoadDefault()
	if err != nil {
		return serviceWindowsSecurityCycleSummary{}, err
	}
	scopes := configuredSecurityScopes(value.GovernedRoots)

	prepared, err := prepareConfiguredSecurity()
	if err != nil {
		return serviceWindowsSecurityCycleSummary{}, err
	}
	summary := prepared.Summary
	summary.Semantics = "FI service mode owns Windows Security in an independent sequential worker. " +
		"Each continuous EventRecordID window is durably spooled and verified before checkpoint advancement. " +
		"A proven Security-log continuity gap is preserved as incomplete; recovery records current Security coverage and establishes a fresh post-coverage boundary without rescanning every file in each governed root."

	target, err := securityevent.QueryLogState()
	if err != nil {
		return summarizeServiceWindowsSecurity(summary, false), err
	}
	summary.TargetLogState = &target
	summary.TargetEventRecordID = target.NewestEventRecordID

	targetAssessment, err := securityevent.AssessCheckpoint(
		prepared.Checkpoint,
		target,
	)
	if err != nil {
		return summarizeServiceWindowsSecurity(summary, false), err
	}

	var gapAssessment *securityevent.ContinuityAssessment
	switch {
	case prepared.GapAssessment != nil:
		gapAssessment = prepared.GapAssessment
	case targetAssessment.Status == securityevent.ContinuityGap:
		gapAssessment = &targetAssessment
	}

	if gapAssessment != nil {
		summary, err = reconcileServiceWindowsSecurityGap(
			ctx,
			summary,
			*gapAssessment,
			scopes,
		)
		if err != nil {
			return summarizeServiceWindowsSecurity(summary, false), err
		}
	} else {
		opRecord, opErr := runConfiguredOperation(
			configuredSecurityScopeID,
			records.OperationWindowsSecurityCatchUp,
			func() error {
				return finishConfiguredSecurityContinuous(
					ctx,
					&summary,
					prepared,
					target,
					scopes,
				)
			},
		)
		summary.Operations = appendConfiguredOperation(summary.Operations, opRecord)
		if opErr != nil {
			return summarizeServiceWindowsSecurity(summary, false), opErr
		}
		summary.Status = configuredSecurityComplete
	}

	moreAvailable, err := serviceWindowsSecurityMoreAvailable(summary)
	if err != nil {
		return summarizeServiceWindowsSecurity(summary, false), err
	}

	return summarizeServiceWindowsSecurity(summary, moreAvailable), nil
}

func reconcileServiceWindowsSecurityGap(
	ctx context.Context,
	summary configuredSecuritySummary,
	assessment securityevent.ContinuityAssessment,
	scopes []securityevent.GovernedScope,
) (configuredSecuritySummary, error) {
	gap, err := newWindowsSecurityContinuityGapObservation(assessment)
	if err != nil {
		return summary, err
	}
	if err := records.ValidateWindowsSecurityContinuityGapObservation(gap); err != nil {
		return summary, err
	}

	summary.ContinuityGap = &gap
	gapSpool, err := writeWindowsSecurityContinuityGap(gap)
	summary.ContinuityGapSpool = &gapSpool
	if err != nil {
		return summary, err
	}

	opRecord, opErr := runConfiguredOperation(
		configuredSecurityScopeID,
		records.OperationReconciliation,
		func() error {
			// Security continuity is reconciled against Security-specific current
			// state: audit policy, channel readability, and governed-root SACL
			// coverage. The independent Security worker must not block behind a
			// multi-hour full-file root baseline.
			coverage, err := securityevent.AssessCoverage(ctx, scopes)
			if err != nil {
				return err
			}
			if err := records.ValidateWindowsSecurityCoverageObservation(coverage); err != nil {
				return err
			}
			summary.Coverage = &coverage

			coverageSpool, err := writeWindowsSecurityRecoveryCoverage(coverage)
			summary.RecoveryCoverageSpool = &coverageSpool
			if err != nil {
				return err
			}

			// Choose the new boundary only after current-state coverage has been
			// durably recorded. This prevents a long reconciliation from rebasing
			// to an already-expired pre-reconciliation EventRecordID.
			freshTarget, err := securityevent.QueryLogState()
			if err != nil {
				return err
			}
			summary.TargetLogState = &freshTarget
			summary.TargetEventRecordID = freshTarget.NewestEventRecordID

			reinitialized, err := securityevent.InitializeCheckpoint(
				summary.StatePath,
				freshTarget,
			)
			if err != nil {
				return err
			}
			persisted, err := securityevent.LoadCheckpoint(summary.StatePath)
			if err != nil {
				return err
			}
			if persisted.LastEventRecordID != reinitialized.LastEventRecordID ||
				persisted.LastEventRecordID != freshTarget.NewestEventRecordID {
				return errors.New(
					"persisted Windows Security service checkpoint does not match fresh reconciliation boundary",
				)
			}

			summary.CheckpointReinitialized = true
			summary.FinalCheckpoint = &persisted
			return nil
		},
	)
	summary.Operations = appendConfiguredOperation(summary.Operations, opRecord)
	if opErr != nil {
		return summary, opErr
	}

	summary.Status = configuredSecurityComplete
	return summary, nil
}

func serviceWindowsSecurityMoreAvailable(
	summary configuredSecuritySummary,
) (bool, error) {
	checkpoint := summary.FinalCheckpoint
	if checkpoint == nil {
		return false, nil
	}

	checkpointID, err := strconv.ParseUint(checkpoint.LastEventRecordID, 10, 64)
	if err != nil {
		return false, fmt.Errorf("parse final Windows Security checkpoint: %w", err)
	}

	state, err := securityevent.QueryLogState()
	if err != nil {
		return false, err
	}
	newestID, err := strconv.ParseUint(state.NewestEventRecordID, 10, 64)
	if err != nil {
		return false, fmt.Errorf("parse current Windows Security head: %w", err)
	}

	return checkpointID < newestID, nil
}

func summarizeServiceWindowsSecurity(
	summary configuredSecuritySummary,
	moreAvailable bool,
) serviceWindowsSecurityCycleSummary {
	return serviceWindowsSecurityCycleSummary{
		Status:                  summary.Status,
		ReadWindows:             summary.ReadWindows,
		SourceMatchingEvents:    summary.SourceMatchingEvents,
		SelectedEvents:          summary.SelectedEvents,
		IgnoredEvents:           summary.IgnoredEvents,
		VerifiedBatches:         summary.VerifiedBatches,
		CheckpointAdvanced:      summary.CheckpointAdvanced,
		CheckpointReinitialized: summary.CheckpointReinitialized,
		ContinuityGap:           summary.ContinuityGap != nil,
		MoreAvailable:           moreAvailable,
	}
}

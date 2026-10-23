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
	"github.com/Iron-Signal-Systems/fi/go/internal/windows/securityevent"
	"strconv"
	"sync"
	"time"
)

var (
	serviceWindowsSecurityIntervalMu sync.RWMutex
	serviceWindowsSecurityInterval   string
)

type serviceWindowsSecurityCycleSummary struct {
	Status                  configuredSecurityStatus
	CoverageStatus          records.WindowsSecurityCoverageStatus
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

type liveServiceWindowsSecuritySource struct {
	operationalSnapshot serviceOperationalSnapshot
}

func (source liveServiceWindowsSecuritySource) Collect(
	ctx context.Context,
) (serviceWindowsSecurityCycleSummary, error) {
	return writeServiceWindowsSecurity(
		ctx,
		source.operationalSnapshot,
	)
}

func resolveServiceWindowsSecurityInterval(interval time.Duration) (time.Duration, error) {
	if interval <= 0 {
		return 0, errors.New("service Windows Security interval must be greater than zero")
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

// runServiceWindowsSecurityLoop starts immediately, never overlaps itself,
// and bounds continuous catch-up retries to avoid a busy Security-log loop.
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
		return errors.New(
			"service Windows Security interval must be greater than zero",
		)
	}
	if source == nil || appendRecord == nil {
		return errors.New(
			"service Windows Security runtime dependency is nil",
		)
	}

	waitFor := func(delay time.Duration) bool {
		timer := time.NewTimer(delay)
		defer timer.Stop()

		select {
		case <-ctx.Done():
			return false

		case <-timer.C:
			return true
		}
	}

	for {
		if err := ctx.Err(); err != nil {
			return nil
		}

		summary, collectErr := source.Collect(ctx)

		outcome := serviceOutcomeComplete

		switch {
		case collectErr != nil &&
			errors.Is(
				collectErr,
				context.Canceled,
			) &&
			ctx.Err() != nil:
			return nil

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
			SecurityCoverageStatus:     string(summary.CoverageStatus),
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

		if err := appendRecord(record); err != nil {
			return fmt.Errorf(
				"persist Windows Security runtime record: %w",
				err,
			)
		}

		if collectErr != nil {
			// Windows Security is an independently observable collection lane.
			// A source-cycle failure must not terminate unrelated root or USN
			// collection. Preserve the exact error durably, return to normal
			// cadence, and retry. Failure to preserve that runtime record remains
			// fatal because FI would otherwise lose observability of the fault.
			if !waitFor(interval) {
				return nil
			}
			continue
		}

		// A verified recovery checkpoint also leaves a retained backlog to
		// drain. It must use the bounded catch-up cadence, not the normal
		// one-minute steady-state cadence.
		delay := nextServiceWindowsSecurityDelay(
			interval,
			summary.MoreAvailable,
			summary.CheckpointAdvanced || summary.CheckpointReinitialized,
		)
		if !waitFor(delay) {
			return nil
		}
	}
}

func writeServiceWindowsSecurity(
	ctx context.Context,
	snapshot serviceOperationalSnapshot,
) (serviceWindowsSecurityCycleSummary, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	scopes := configuredSecurityScopes(snapshot.GovernedRoots)

	prepared, err := prepareConfiguredSecurity()
	if err != nil {
		return serviceWindowsSecurityCycleSummary{}, err
	}
	summary := prepared.Summary
	summary.Semantics = "FI service mode owns Windows Security in an independent sequential worker. " +
		"Consecutive empty EventRecordID query windows are bounded and durably represented by one coverage batch before checkpoint advancement; non-empty windows are published individually. " +
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

			// Recheck the Security log after durable coverage publication. The
			// original gap observation remains immutable. If the oldest retained
			// record moved during coverage assessment, publish the expanded gap
			// before advancing the checkpoint over those additional lost IDs.
			freshTarget, err := securityevent.QueryLogState()
			if err != nil {
				return err
			}
			summary.TargetLogState = &freshTarget
			summary.TargetEventRecordID = freshTarget.NewestEventRecordID

			freshAssessment, err := securityevent.AssessCheckpoint(
				assessment.Checkpoint,
				freshTarget,
			)
			if err != nil {
				return err
			}
			if freshAssessment.Status != securityevent.ContinuityGap {
				return errors.New("Windows Security recovery gap changed unexpectedly")
			}
			if freshAssessment.ReasonCode != assessment.ReasonCode ||
				freshAssessment.LogState.OldestEventRecordID != assessment.LogState.OldestEventRecordID {
				updatedGap, err := newWindowsSecurityContinuityGapObservation(freshAssessment)
				if err != nil {
					return err
				}
				updatedGapSpool, err := writeWindowsSecurityContinuityGap(updatedGap)
				if err != nil {
					return err
				}
				summary.ContinuityGap = &updatedGap
				summary.ContinuityGapSpool = &updatedGapSpool
			}

			checkpointTarget, replayRetained, err := serviceWindowsSecurityRecoveryCheckpoint(freshAssessment)
			if err != nil {
				return err
			}
			var reinitialized securityevent.Checkpoint
			if replayRetained {
				// The gap covers the unavailable prefix. Resume reading at the
				// oldest still-retained EventRecordID, not at the live head.
				reinitialized, err = securityevent.AdvanceCheckpoint(
					summary.StatePath,
					assessment.Checkpoint.LastEventRecordID,
					checkpointTarget,
				)
			} else {
				// A reset/clear cannot use a retained-history boundary.
				// The explicit reset gap has already been published.
				reinitialized, err = securityevent.InitializeCheckpoint(summary.StatePath, freshTarget)
			}
			if err != nil {
				return err
			}
			persisted, err := securityevent.LoadCheckpoint(summary.StatePath)
			if err != nil {
				return err
			}
			if persisted.LastEventRecordID != reinitialized.LastEventRecordID ||
				persisted.LastEventRecordID != checkpointTarget {
				return errors.New(
					"persisted Windows Security service checkpoint does not match verified recovery boundary",
				)
			}

			summary.CheckpointReinitialized = true
			summary.FinalCheckpoint = &persisted
			if replayRetained {
				// Resume the still-retained EventRecordID range before leaving the
				// reconciliation cycle. Deferring it to the next scheduled cycle
				// allows the rolling Security log to overtake oldest-1 again.
				replay := configuredSecurityPrepared{Checkpoint: persisted}
				if err := finishConfiguredSecurityContinuous(ctx, &summary, replay, freshTarget, scopes); err != nil {
					return fmt.Errorf("read retained Windows Security history after recovery: %w", err)
				}
			}
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
	var coverageStatus records.WindowsSecurityCoverageStatus
	if summary.Coverage != nil {
		coverageStatus = summary.Coverage.Status
	}
	return serviceWindowsSecurityCycleSummary{
		Status:                  summary.Status,
		CoverageStatus:          coverageStatus,
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

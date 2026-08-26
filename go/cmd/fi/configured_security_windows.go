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
	"github.com/Iron-Signal-Systems/fi/go/internal/runtimeidentity"
	"github.com/Iron-Signal-Systems/fi/go/internal/spool"
	"github.com/Iron-Signal-Systems/fi/go/internal/windows/securityevent"
	"strconv"
)

const configuredSecurityScopeID = "windows-security-local"

type configuredSecurityStatus string

const (
	configuredSecurityComplete configuredSecurityStatus = "Complete"
	configuredSecurityFailed   configuredSecurityStatus = "Failed"
)

type configuredSecurityReconciliation struct {
	ScopeID      string          `json:"scope_id"`
	GovernedRoot string          `json:"governed_root"`
	Snapshot     spoolRunSummary `json:"snapshot"`
}
type configuredSecuritySummary struct {
	StatePath               string                                           `json:"state_path"`
	OperationJournal        string                                           `json:"operation_journal"`
	RecoveredOperations     []records.OperationRecord                        `json:"recovered_operations"`
	Operations              []records.OperationRecord                        `json:"operations"`
	CheckpointFound         bool                                             `json:"checkpoint_found"`
	Status                  configuredSecurityStatus                         `json:"status"`
	InitialLogState         *securityevent.LogState                          `json:"initial_log_state,omitempty"`
	TargetLogState          *securityevent.LogState                          `json:"target_log_state,omitempty"`
	StartAfterEventRecordID string                                           `json:"start_after_event_record_id,omitempty"`
	TargetEventRecordID     string                                           `json:"target_event_record_id,omitempty"`
	Coverage                *records.WindowsSecurityCoverageObservation      `json:"coverage,omitempty"`
	ContinuityGap           *records.WindowsSecurityContinuityGapObservation `json:"continuity_gap,omitempty"`
	ContinuityGapSpool      *windowsSecurityGapSpoolSummary                  `json:"continuity_gap_spool,omitempty"`
	Reconciliation          []configuredSecurityReconciliation               `json:"reconciliation"`
	RecoveryCoverageSpool   *windowsSecurityGapSpoolSummary                  `json:"recovery_coverage_spool,omitempty"`
	SourceMatchingEvents    int                                              `json:"source_matching_events"`
	SelectedEvents          int                                              `json:"selected_events"`
	IgnoredEvents           int                                              `json:"ignored_events"`
	UnresolvedFileDeletes   int                                              `json:"unresolved_file_deletes"`
	Batches                 []spool.FinalizedBatch                           `json:"batches"`
	VerifiedBatches         int                                              `json:"verified_batches"`
	CheckpointAdvanced      bool                                             `json:"checkpoint_advanced"`
	CheckpointReinitialized bool                                             `json:"checkpoint_reinitialized"`
	FinalCheckpoint         *securityevent.Checkpoint                        `json:"final_checkpoint,omitempty"`
	Error                   string                                           `json:"error,omitempty"`
	Semantics               string                                           `json:"semantics"`
}
type configuredSecurityPrepared struct {
	Summary       configuredSecuritySummary
	Checkpoint    securityevent.Checkpoint
	GapAssessment *securityevent.ContinuityAssessment
}

func configuredSecurityScopes(roots []string) []securityevent.GovernedScope {
	r := make([]securityevent.GovernedScope, 0, len(roots))
	for _, root := range roots {
		r = append(r, securityevent.GovernedScope{ScopeID: configuredScopeID(root), GovernedRoot: root})
	}
	return r
}
func prepareConfiguredSecurity() (configuredSecurityPrepared, error) {
	statePath, err := securityevent.DefaultCheckpointPath()
	if err != nil {
		return configuredSecurityPrepared{}, err
	}
	summary := configuredSecuritySummary{StatePath: statePath, Batches: []spool.FinalizedBatch{}, Reconciliation: []configuredSecurityReconciliation{}, RecoveredOperations: []records.OperationRecord{}, Operations: []records.OperationRecord{}, Semantics: "FI anchors the local Windows Security channel before configured root processing, then reads through a fixed post-root target. Major Security catch-up and reconciliation operations use the append-only FI operation journal. Missing historical Security events remain explicitly incomplete and are never reconstructed from current state."}
	journalPath, recovered, err := recoverConfiguredOperations(configuredSecurityScopeID)
	summary.OperationJournal = journalPath
	summary.RecoveredOperations = recovered
	if err != nil {
		return configuredSecurityPrepared{Summary: summary}, err
	}
	state, err := securityevent.QueryLogState()
	if err != nil {
		return configuredSecurityPrepared{Summary: summary}, err
	}
	summary.InitialLogState = &state
	found, err := fileExists(statePath)
	if err != nil {
		return configuredSecurityPrepared{Summary: summary}, err
	}
	summary.CheckpointFound = found
	prepared := configuredSecurityPrepared{Summary: summary}
	switch found {
	case false:
		cp, err := securityevent.InitializeCheckpoint(statePath, state)
		if err != nil {
			return prepared, err
		}
		prepared.Checkpoint = cp
	case true:
		cp, err := securityevent.LoadCheckpoint(statePath)
		if err != nil {
			return prepared, err
		}
		prepared.Checkpoint = cp
		assessment, err := securityevent.AssessCheckpoint(cp, state)
		if err != nil {
			return prepared, err
		}
		if assessment.Status == securityevent.ContinuityGap {
			prepared.GapAssessment = &assessment
		}
	}
	prepared.Summary.StartAfterEventRecordID = prepared.Checkpoint.LastEventRecordID
	return prepared, nil
}
func finishConfiguredSecurity(ctx context.Context, prepared configuredSecurityPrepared, scopes []securityevent.GovernedScope) (configuredSecuritySummary, error) {
	summary := prepared.Summary
	if err := ctx.Err(); err != nil {
		return summary, err
	}
	target, err := securityevent.QueryLogState()
	if err != nil {
		return summary, err
	}
	summary.TargetLogState = &target
	summary.TargetEventRecordID = target.NewestEventRecordID
	targetAssessment, err := securityevent.AssessCheckpoint(prepared.Checkpoint, target)
	if err != nil {
		return summary, err
	}
	switch {
	case prepared.GapAssessment != nil:
		return reconcileConfiguredSecurityGap(ctx, summary, *prepared.GapAssessment, target, scopes)
	case targetAssessment.Status == securityevent.ContinuityGap:
		return reconcileConfiguredSecurityGap(ctx, summary, targetAssessment, target, scopes)
	}
	opRecord, opErr := runConfiguredOperation(configuredSecurityScopeID, records.OperationWindowsSecurityCatchUp, func() error { return finishConfiguredSecurityContinuous(ctx, &summary, prepared, target, scopes) })
	summary.Operations = append(summary.Operations, opRecord)
	if opErr != nil {
		return summary, opErr
	}
	summary.Status = configuredSecurityComplete
	return summary, nil
}
func finishConfiguredSecurityContinuous(ctx context.Context, summary *configuredSecuritySummary, prepared configuredSecurityPrepared, target securityevent.LogState, scopes []securityevent.GovernedScope) error {
	start, err := strconv.ParseUint(prepared.Checkpoint.LastEventRecordID, 10, 64)
	if err != nil {
		return err
	}
	through, err := strconv.ParseUint(target.NewestEventRecordID, 10, 64)
	if err != nil {
		return err
	}
	events, err := securityevent.ReadSelectedEvents(start, through)
	if err != nil {
		return err
	}
	summary.SourceMatchingEvents = len(events)
	selected := make([]records.WindowsSecurityEventObservation, 0, len(events))
	for _, event := range events {
		value, keep := securityevent.SelectEvent(event, scopes)
		if !keep {
			summary.IgnoredEvents++
			continue
		}
		if value.ScopeBasis == records.WindowsSecurityScopeUnresolvedFileDeleteIncluded {
			summary.UnresolvedFileDeletes++
		}
		if err := records.ValidateWindowsSecurityEventObservation(value); err != nil {
			return err
		}
		selected = append(selected, value)
	}
	summary.SelectedEvents = len(selected)
	coverage, err := securityevent.AssessCoverage(ctx, scopes)
	if err != nil {
		return err
	}
	if err := records.ValidateWindowsSecurityCoverageObservation(coverage); err != nil {
		return err
	}
	summary.Coverage = &coverage
	spoolDir, err := spool.DefaultDir()
	if err != nil {
		return err
	}
	executable, err := runtimeidentity.CurrentExecutable()
	if err != nil {
		return err
	}
	writer, err := spool.NewWriter(spoolDir, spool.DefaultBatchSize, spool.CollectorIdentity{ExecutablePath: executable.Path, ExecutableSHA256: executable.SHA256})
	if err != nil {
		return err
	}
	closeNeeded := true
	defer func() {
		if closeNeeded {
			_ = writer.Close()
		}
	}()
	if err := writer.Append("WindowsSecurityCoverage", configuredSecurityScopeID, coverage); err != nil {
		return err
	}
	for _, event := range selected {
		if err := writer.Append("WindowsSecurityEvent", configuredSecurityScopeID, event); err != nil {
			return err
		}
	}
	if err := writer.Close(); err != nil {
		return err
	}
	closeNeeded = false
	summary.Batches = writer.FinalizedBatches()
	for _, batch := range summary.Batches {
		verification, err := spool.VerifyManifest(batch.ManifestPath)
		if err != nil {
			return err
		}
		if !verification.Verified {
			return errors.New("Windows Security spool batch verification did not confirm the batch")
		}
		summary.VerifiedBatches++
	}
	if summary.VerifiedBatches != len(summary.Batches) {
		return errors.New("not every Windows Security spool batch verified")
	}
	advanced, err := securityevent.AdvanceCheckpoint(summary.StatePath, prepared.Checkpoint.LastEventRecordID, target.NewestEventRecordID)
	if err != nil {
		return err
	}
	summary.CheckpointAdvanced = true
	summary.FinalCheckpoint = &advanced
	return nil
}
func reconcileConfiguredSecurityGap(ctx context.Context, summary configuredSecuritySummary, gapAssessment securityevent.ContinuityAssessment, target securityevent.LogState, scopes []securityevent.GovernedScope) (configuredSecuritySummary, error) {
	gap, err := newWindowsSecurityContinuityGapObservation(gapAssessment)
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
	opRecord, opErr := runConfiguredOperation(configuredSecurityScopeID, records.OperationReconciliation, func() error {
		for _, scope := range scopes {
			if err := ctx.Err(); err != nil {
				return err
			}
			snapshot, err := writeSpoolRoot(ctx, scope.ScopeID, scope.GovernedRoot)
			summary.Reconciliation = append(summary.Reconciliation, configuredSecurityReconciliation{ScopeID: scope.ScopeID, GovernedRoot: scope.GovernedRoot, Snapshot: snapshot})
			if err != nil {
				return err
			}
			if err := validateBaselineSpoolForCheckpoint(snapshot); err != nil {
				return fmt.Errorf("Windows Security gap reconciliation for %q: %w", scope.GovernedRoot, err)
			}
		}
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
		reinitialized, err := securityevent.InitializeCheckpoint(summary.StatePath, target)
		if err != nil {
			return err
		}
		persisted, err := securityevent.LoadCheckpoint(summary.StatePath)
		if err != nil {
			return err
		}
		if persisted.LastEventRecordID != reinitialized.LastEventRecordID || persisted.LastEventRecordID != target.NewestEventRecordID {
			return errors.New("persisted Windows Security recovery checkpoint does not match the fixed recovery target")
		}
		summary.CheckpointReinitialized = true
		summary.FinalCheckpoint = &persisted
		return nil
	})
	summary.Operations = append(summary.Operations, opRecord)
	if opErr != nil {
		return summary, opErr
	}
	summary.Status = configuredSecurityComplete
	return summary, nil
}

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package main

import (
	"context"
	"errors"
	"fmt"
	"strconv"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
	"github.com/Iron-Signal-Systems/fi/go/internal/runtimeidentity"
	"github.com/Iron-Signal-Systems/fi/go/internal/spool"
	"github.com/Iron-Signal-Systems/fi/go/internal/windows/securityevent"
)

const configuredSecurityScopeID = "windows-security-local"

type configuredSecurityStatus string

const (
	configuredSecurityComplete configuredSecurityStatus = "Complete"
	configuredSecurityFailed   configuredSecurityStatus = "Failed"
)

type configuredSecuritySummary struct {
	StatePath               string                                      `json:"state_path"`
	CheckpointFound         bool                                        `json:"checkpoint_found"`
	Status                  configuredSecurityStatus                    `json:"status"`
	InitialLogState         *securityevent.LogState                     `json:"initial_log_state,omitempty"`
	TargetLogState          *securityevent.LogState                     `json:"target_log_state,omitempty"`
	StartAfterEventRecordID string                                      `json:"start_after_event_record_id,omitempty"`
	TargetEventRecordID     string                                      `json:"target_event_record_id,omitempty"`
	Coverage                *records.WindowsSecurityCoverageObservation `json:"coverage,omitempty"`
	SourceMatchingEvents    int                                         `json:"source_matching_events"`
	SelectedEvents          int                                         `json:"selected_events"`
	IgnoredEvents           int                                         `json:"ignored_events"`
	UnresolvedFileDeletes   int                                         `json:"unresolved_file_deletes"`
	Batches                 []spool.FinalizedBatch                      `json:"batches"`
	VerifiedBatches         int                                         `json:"verified_batches"`
	CheckpointAdvanced      bool                                        `json:"checkpoint_advanced"`
	FinalCheckpoint         *securityevent.Checkpoint                   `json:"final_checkpoint,omitempty"`
	Error                   string                                      `json:"error,omitempty"`
	Semantics               string                                      `json:"semantics"`
}

type configuredSecurityPrepared struct {
	Summary    configuredSecuritySummary
	Checkpoint securityevent.Checkpoint
}

func configuredSecurityScopes(roots []string) []securityevent.GovernedScope {
	result := make([]securityevent.GovernedScope, 0, len(roots))
	for _, root := range roots {
		result = append(result, securityevent.GovernedScope{ScopeID: configuredScopeID(root), GovernedRoot: root})
	}
	return result
}

func prepareConfiguredSecurity() (configuredSecurityPrepared, error) {
	statePath, err := securityevent.DefaultCheckpointPath()
	if err != nil {
		return configuredSecurityPrepared{}, err
	}
	summary := configuredSecuritySummary{
		StatePath: statePath,
		Batches:   []spool.FinalizedBatch{},
		Semantics: "FI anchors the local Windows Security channel before configured root processing, then reads through a fixed post-root target. Security events are preserved as an independent source and are not used by the collector to infer actor intent. The Security checkpoint advances only after the selected events and coverage record are durably spooled and verified.",
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

	var checkpoint securityevent.Checkpoint
	switch found {
	case false:
		checkpoint, err = securityevent.InitializeCheckpoint(statePath, state)
		if err != nil {
			return configuredSecurityPrepared{Summary: summary}, err
		}
	case true:
		checkpoint, err = securityevent.LoadCheckpoint(statePath)
		if err != nil {
			return configuredSecurityPrepared{Summary: summary}, err
		}
		assessment, err := securityevent.AssessCheckpoint(checkpoint, state)
		if err != nil {
			return configuredSecurityPrepared{Summary: summary}, err
		}
		if assessment.Status != securityevent.ContinuityContinuous {
			return configuredSecurityPrepared{Summary: summary}, fmt.Errorf("Windows Security checkpoint is not continuous: %s", assessment.ReasonCode)
		}
	}
	summary.StartAfterEventRecordID = checkpoint.LastEventRecordID
	return configuredSecurityPrepared{Summary: summary, Checkpoint: checkpoint}, nil
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

	assessment, err := securityevent.AssessCheckpoint(prepared.Checkpoint, target)
	if err != nil {
		return summary, err
	}
	if assessment.Status != securityevent.ContinuityContinuous {
		return summary, fmt.Errorf("Windows Security checkpoint lost continuity during configured run: %s", assessment.ReasonCode)
	}

	start, err := strconv.ParseUint(prepared.Checkpoint.LastEventRecordID, 10, 64)
	if err != nil {
		return summary, err
	}
	through, err := strconv.ParseUint(target.NewestEventRecordID, 10, 64)
	if err != nil {
		return summary, err
	}
	events, err := securityevent.ReadSelectedEvents(start, through)
	if err != nil {
		return summary, err
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
			return summary, err
		}
		selected = append(selected, value)
	}
	summary.SelectedEvents = len(selected)

	coverage, err := securityevent.AssessCoverage(ctx, scopes)
	if err != nil {
		return summary, err
	}
	if err := records.ValidateWindowsSecurityCoverageObservation(coverage); err != nil {
		return summary, err
	}
	summary.Coverage = &coverage

	spoolDir, err := spool.DefaultDir()
	if err != nil {
		return summary, err
	}
	executable, err := runtimeidentity.CurrentExecutable()
	if err != nil {
		return summary, err
	}
	writer, err := spool.NewWriter(spoolDir, spool.DefaultBatchSize, spool.CollectorIdentity{
		ExecutablePath:   executable.Path,
		ExecutableSHA256: executable.SHA256,
	})
	if err != nil {
		return summary, err
	}
	closeNeeded := true
	defer func() {
		if closeNeeded {
			_ = writer.Close()
		}
	}()

	if err := writer.Append("WindowsSecurityCoverage", configuredSecurityScopeID, coverage); err != nil {
		return summary, err
	}
	for _, event := range selected {
		if err := writer.Append("WindowsSecurityEvent", configuredSecurityScopeID, event); err != nil {
			return summary, err
		}
	}
	if err := writer.Close(); err != nil {
		return summary, err
	}
	closeNeeded = false
	summary.Batches = writer.FinalizedBatches()
	for _, batch := range summary.Batches {
		verification, err := spool.VerifyManifest(batch.ManifestPath)
		if err != nil {
			return summary, err
		}
		if !verification.Verified {
			return summary, errors.New("Windows Security spool batch verification did not confirm the batch")
		}
		summary.VerifiedBatches++
	}
	if summary.VerifiedBatches != len(summary.Batches) {
		return summary, errors.New("not every Windows Security spool batch verified")
	}

	advanced, err := securityevent.AdvanceCheckpoint(summary.StatePath, prepared.Checkpoint.LastEventRecordID, target.NewestEventRecordID)
	if err != nil {
		return summary, err
	}
	summary.CheckpointAdvanced = true
	summary.FinalCheckpoint = &advanced
	summary.Status = configuredSecurityComplete
	return summary, nil
}

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package main

import (
	"errors"
	"fmt"
	"time"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
	"github.com/Iron-Signal-Systems/fi/go/internal/runtimeidentity"
	"github.com/Iron-Signal-Systems/fi/go/internal/spool"
	"github.com/Iron-Signal-Systems/fi/go/internal/windows/checkpoint"
)

type usnGapSpoolSummary struct {
	Batches         []spool.FinalizedBatch `json:"batches"`
	VerifiedBatches int                    `json:"verified_batches"`
}

func newUSNContinuityGapObservation(
	governedRoot string,
	assessment checkpoint.ContinuityAssessment,
) (records.USNContinuityGapObservation, error) {
	checkedAt, err := time.Parse(time.RFC3339Nano, assessment.CheckedAt)
	if err != nil {
		return records.USNContinuityGapObservation{}, fmt.Errorf("parse USN continuity gap checked_at: %w", err)
	}

	return records.USNContinuityGapObservation{
		ObservedAt:            checkedAt.UTC().Format("2006-01-02T15:04:05.000000000Z"),
		CollectionMethod:      records.WindowsUSNCollectionMethod,
		ScopeID:               assessment.Checkpoint.ScopeID,
		GovernedRoot:          governedRoot,
		ReasonCode:            assessment.ReasonCode,
		CheckpointJournalID:   assessment.Checkpoint.JournalID,
		CheckpointNextUSN:     assessment.Checkpoint.NextUSN,
		CurrentJournalID:      assessment.JournalState.JournalID,
		CurrentFirstUSN:       assessment.JournalState.FirstUSN,
		CurrentLowestValidUSN: assessment.JournalState.LowestValidUSN,
		CurrentNextUSN:        assessment.JournalState.NextUSN,
		CoverageState:         records.USNContinuityGapCoverageIncomplete,
		ReconciliationAction:  records.USNContinuityGapReconcileBaselineAndCatchUp,
	}, nil
}

func writeUSNContinuityGap(value records.USNContinuityGapObservation) (usnGapSpoolSummary, error) {
	if err := records.ValidateUSNContinuityGapObservation(value); err != nil {
		return usnGapSpoolSummary{}, err
	}

	spoolDir, err := spool.DefaultDir()
	if err != nil {
		return usnGapSpoolSummary{}, err
	}
	executable, err := runtimeidentity.CurrentExecutable()
	if err != nil {
		return usnGapSpoolSummary{}, err
	}
	writer, err := spool.NewWriter(spoolDir, spool.DefaultBatchSize, spool.CollectorIdentity{
		ExecutablePath:   executable.Path,
		ExecutableSHA256: executable.SHA256,
	})
	if err != nil {
		return usnGapSpoolSummary{}, err
	}
	closeNeeded := true
	defer func() {
		if closeNeeded {
			_ = writer.Close()
		}
	}()

	if err := writer.Append("USNContinuityGap", value.ScopeID, value); err != nil {
		return usnGapSpoolSummary{}, err
	}
	if err := writer.Close(); err != nil {
		return usnGapSpoolSummary{}, err
	}
	closeNeeded = false

	summary := usnGapSpoolSummary{Batches: writer.FinalizedBatches()}
	for _, batch := range summary.Batches {
		verification, err := spool.VerifyManifest(batch.ManifestPath)
		if err != nil {
			return summary, err
		}
		if !verification.Verified {
			return summary, errors.New("USN continuity-gap spool verification did not confirm the batch")
		}
		summary.VerifiedBatches++
	}
	if len(summary.Batches) == 0 || summary.VerifiedBatches != len(summary.Batches) {
		return summary, errors.New("USN continuity-gap record was not durably verified")
	}
	return summary, nil
}

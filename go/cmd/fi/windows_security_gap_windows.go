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
	"github.com/Iron-Signal-Systems/fi/go/internal/windows/securityevent"
)

type windowsSecurityGapSpoolSummary struct {
	Batches         []spool.FinalizedBatch `json:"batches"`
	VerifiedBatches int                    `json:"verified_batches"`
}

func newWindowsSecurityContinuityGapObservation(
	assessment securityevent.ContinuityAssessment,
) (records.WindowsSecurityContinuityGapObservation, error) {
	observedAt, err := time.Parse(time.RFC3339Nano, assessment.LogState.ObservedAt)
	if err != nil {
		return records.WindowsSecurityContinuityGapObservation{}, fmt.Errorf(
			"parse Windows Security continuity gap observed_at: %w",
			err,
		)
	}

	return records.WindowsSecurityContinuityGapObservation{
		ObservedAt:                 observedAt.UTC().Format("2006-01-02T15:04:05.000000000Z"),
		CollectionMethod:           records.WindowsSecurityCollectionMethod,
		Channel:                    assessment.LogState.Channel,
		ScopeID:                    configuredSecurityScopeID,
		ReasonCode:                 assessment.ReasonCode,
		CheckpointEventRecordID:    assessment.Checkpoint.LastEventRecordID,
		CurrentOldestEventRecordID: assessment.LogState.OldestEventRecordID,
		CurrentNewestEventRecordID: assessment.LogState.NewestEventRecordID,
		CoverageState:              records.WindowsSecurityContinuityGapCoverageIncomplete,
		ReconciliationAction:       records.WindowsSecurityContinuityGapReconcileCurrentStateBaseline,
	}, nil
}

func writeWindowsSecurityContinuityGap(
	value records.WindowsSecurityContinuityGapObservation,
) (windowsSecurityGapSpoolSummary, error) {
	if err := records.ValidateWindowsSecurityContinuityGapObservation(value); err != nil {
		return windowsSecurityGapSpoolSummary{}, err
	}
	return writeWindowsSecurityRecoveryRecord(
		"WindowsSecurityContinuityGap",
		value,
	)
}

func writeWindowsSecurityRecoveryCoverage(
	value records.WindowsSecurityCoverageObservation,
) (windowsSecurityGapSpoolSummary, error) {
	if err := records.ValidateWindowsSecurityCoverageObservation(value); err != nil {
		return windowsSecurityGapSpoolSummary{}, err
	}
	return writeWindowsSecurityRecoveryRecord(
		"WindowsSecurityCoverage",
		value,
	)
}

func writeWindowsSecurityRecoveryRecord(
	recordKind string,
	payload any,
) (windowsSecurityGapSpoolSummary, error) {
	spoolDir, err := spool.DefaultDir()
	if err != nil {
		return windowsSecurityGapSpoolSummary{}, err
	}
	executable, err := runtimeidentity.CurrentExecutable()
	if err != nil {
		return windowsSecurityGapSpoolSummary{}, err
	}
	writer, err := spool.NewWriter(spoolDir, spool.DefaultBatchSize, spool.CollectorIdentity{
		ExecutablePath:   executable.Path,
		ExecutableSHA256: executable.SHA256,
	})
	if err != nil {
		return windowsSecurityGapSpoolSummary{}, err
	}
	closeNeeded := true
	defer func() {
		if closeNeeded {
			_ = writer.Close()
		}
	}()

	if err := writer.Append(recordKind, configuredSecurityScopeID, payload); err != nil {
		return windowsSecurityGapSpoolSummary{}, err
	}
	if err := writer.Close(); err != nil {
		return windowsSecurityGapSpoolSummary{}, err
	}
	closeNeeded = false

	summary := windowsSecurityGapSpoolSummary{
		Batches: writer.FinalizedBatches(),
	}
	for _, batch := range summary.Batches {
		verification, err := spool.VerifyManifest(batch.ManifestPath)
		if err != nil {
			return summary, err
		}
		if !verification.Verified {
			return summary, errors.New("Windows Security recovery spool verification did not confirm the batch")
		}
		summary.VerifiedBatches++
	}
	if len(summary.Batches) == 0 || summary.VerifiedBatches != len(summary.Batches) {
		return summary, errors.New("Windows Security recovery record was not durably verified")
	}
	return summary, nil
}

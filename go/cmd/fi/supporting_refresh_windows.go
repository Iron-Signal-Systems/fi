// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package main

import (
	"context"
	"errors"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
	"github.com/Iron-Signal-Systems/fi/go/internal/runtimeidentity"
	"github.com/Iron-Signal-Systems/fi/go/internal/spool"
	"github.com/Iron-Signal-Systems/fi/go/internal/windows/operation"
)

const supportingSourceRefreshScopeID = "windows-supporting-sources-local"

type supportingSourceRefreshStatus string

const (
	supportingSourceRefreshComplete supportingSourceRefreshStatus = "Complete"
	supportingSourceRefreshPartial  supportingSourceRefreshStatus = "Partial"
	supportingSourceRefreshFailed   supportingSourceRefreshStatus = "Failed"
)

type supportingSourceRefreshSummary struct {
	ScopeID                   string                        `json:"scope_id"`
	Status                    supportingSourceRefreshStatus `json:"status"`
	OperationJournal          string                        `json:"operation_journal"`
	RecoveredOperations       []records.OperationRecord     `json:"recovered_operations"`
	Operation                 *records.OperationRecord      `json:"operation,omitempty"`
	SpoolDir                  string                        `json:"spool_dir,omitempty"`
	CollectorIdentityRecords  int                           `json:"collector_identity_records"`
	SMBShareSnapshotRecords   int                           `json:"smb_share_snapshot_records"`
	LocalPrincipalRecords     int                           `json:"local_principal_records"`
	DirectoryPrincipalRecords int                           `json:"directory_principal_records"`
	SupportingSourceErrors    int                           `json:"supporting_source_errors"`
	SupportingSIDStatePath    string                        `json:"supporting_sid_state_path,omitempty"`
	SupportingSIDCountBefore  int                           `json:"supporting_sid_count_before"`
	SupportingSIDCountAfter   int                           `json:"supporting_sid_count_after"`
	Batches                   []spool.FinalizedBatch        `json:"batches"`
	VerifiedBatches           int                           `json:"verified_batches"`
	Semantics                 string                        `json:"semantics"`
	Error                     string                        `json:"error,omitempty"`
}

// writeSupportingSourceRefresh runs one bounded host-level refresh. It does not
// decide when refreshes should be scheduled; the later service/runtime policy
// will own cadence.
func writeSupportingSourceRefresh(
	ctx context.Context,
) (supportingSourceRefreshSummary, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	summary := supportingSourceRefreshSummary{
		ScopeID:             supportingSourceRefreshScopeID,
		RecoveredOperations: []records.OperationRecord{},
		Batches:             []spool.FinalizedBatch{},
		Semantics: "FI refreshes current SMB, local-identity, and bounded AD source facts. " +
			"Previously relevant domain SIDs remain in FI-owned operational state so " +
			"historical identities are not silently forgotten. Large relevant-SID sets " +
			"are read as separate bounded directory snapshots rather than one synthetic " +
			"LDAP observation. No transitive membership or effective-access conclusion " +
			"is calculated by this operation.",
	}

	journalPath, err := operation.DefaultJournalPath(supportingSourceRefreshScopeID)
	if err != nil {
		summary.Status = supportingSourceRefreshFailed
		summary.Error = err.Error()
		return summary, err
	}
	summary.OperationJournal = journalPath

	recovered, err := operation.RecoverInterrupted(
		journalPath,
		supportingSourceRefreshScopeID,
	)
	if recovered == nil {
		recovered = []records.OperationRecord{}
	}
	summary.RecoveredOperations = recovered
	if err != nil {
		summary.Status = supportingSourceRefreshFailed
		summary.Error = err.Error()
		return summary, err
	}

	started, err := operation.Start(
		supportingSourceRefreshScopeID,
		records.OperationSupportingSourceRefresh,
	)
	if err != nil {
		summary.Status = supportingSourceRefreshFailed
		summary.Error = err.Error()
		return summary, err
	}
	if err := operation.AppendStarted(journalPath, started); err != nil {
		summary.Status = supportingSourceRefreshFailed
		summary.Error = err.Error()
		return summary, err
	}

	bodyErr := collectSupportingSourceRefresh(ctx, &summary)

	outcome := records.OperationComplete
	reasonCode := ""
	switch {
	case bodyErr != nil:
		summary.Status = supportingSourceRefreshFailed
		summary.Error = bodyErr.Error()
		outcome = records.OperationFailed
		reasonCode = "SupportingSourceRefreshFailed"

	case summary.SupportingSourceErrors > 0:
		summary.Status = supportingSourceRefreshPartial
		outcome = records.OperationPartial
		reasonCode = "SupportingSourceUnavailable"

	default:
		summary.Status = supportingSourceRefreshComplete
	}

	record, finishErr := started.Finish(outcome, reasonCode)
	if finishErr == nil {
		finishErr = operation.AppendFinished(journalPath, record)
	}
	if record.OperationID != "" {
		summary.Operation = &record
	}

	if finishErr != nil && summary.Error == "" {
		summary.Error = finishErr.Error()
		summary.Status = supportingSourceRefreshFailed
	}
	return summary, errors.Join(bodyErr, finishErr)
}

func collectSupportingSourceRefresh(
	ctx context.Context,
	summary *supportingSourceRefreshSummary,
) error {
	if summary == nil {
		return errors.New("supporting-source refresh summary is required")
	}

	supporting, err := collectSupportingSourceContext(ctx)
	if err != nil {
		return err
	}

	statePath, sidCountBefore, err := loadSupportingSIDState(
		supporting.CollectorIdentity,
		supporting.ObservedSIDs,
	)
	summary.SupportingSIDStatePath = statePath
	summary.SupportingSIDCountBefore = sidCountBefore
	if err != nil {
		return err
	}

	directorySource := collectDirectorySource(
		ctx,
		supporting.CollectorIdentity,
		supporting.ObservedSIDs,
	)
	for _, snapshot := range directorySource.Snapshots {
		addDirectoryPrincipalSIDs(
			supporting.ObservedSIDs,
			snapshot,
		)
	}

	dir, err := spool.DefaultDir()
	if err != nil {
		return err
	}
	summary.SpoolDir = dir

	executable, err := runtimeidentity.CurrentExecutable()
	if err != nil {
		return err
	}
	writer, err := spool.NewWriter(
		dir,
		spool.DefaultBatchSize,
		spool.CollectorIdentity{
			ExecutablePath:   executable.Path,
			ExecutableSHA256: executable.SHA256,
		},
	)
	if err != nil {
		return err
	}

	tempSummary := spoolRunSummary{
		SpoolDir:        dir,
		TargetBatchSize: spool.DefaultBatchSize,
	}

	if err := appendSupportingSourceStart(
		writer,
		supportingSourceRefreshScopeID,
		supporting,
		&tempSummary,
	); err != nil {
		closeErr := writer.Close()
		summary.Batches = writer.FinalizedBatches()
		return errors.Join(err, closeErr)
	}

	directoryErr := appendDirectorySource(
		writer,
		supportingSourceRefreshScopeID,
		directorySource,
		&tempSummary,
	)

	closeErr := writer.Close()
	summary.Batches = writer.FinalizedBatches()

	var verifyErr error
	for _, finalized := range summary.Batches {
		verification, err := spool.VerifyManifest(finalized.ManifestPath)
		if err != nil {
			verifyErr = errors.Join(verifyErr, err)
			continue
		}
		if !verification.Verified {
			verifyErr = errors.Join(
				verifyErr,
				errors.New("FI spool verification did not return verified=true"),
			)
			continue
		}
		summary.VerifiedBatches++
	}

	summary.CollectorIdentityRecords = tempSummary.CollectorIdentityRecords
	summary.SMBShareSnapshotRecords = tempSummary.SMBShareSnapshotRecords
	summary.LocalPrincipalRecords = tempSummary.LocalPrincipalRecords
	summary.DirectoryPrincipalRecords = tempSummary.DirectoryPrincipalRecords
	summary.SupportingSourceErrors = tempSummary.SupportingSourceErrors

	if err := errors.Join(directoryErr, closeErr, verifyErr); err != nil {
		return err
	}

	statePath, sidCountAfter, err := saveSupportingSIDState(
		supporting.CollectorIdentity,
		supporting.ObservedSIDs,
	)
	summary.SupportingSIDStatePath = statePath
	summary.SupportingSIDCountAfter = sidCountAfter
	if err != nil {
		return err
	}

	return nil
}

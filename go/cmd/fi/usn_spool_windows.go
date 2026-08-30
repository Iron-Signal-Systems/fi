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
	"syscall"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
	"github.com/Iron-Signal-Systems/fi/go/internal/runtimeidentity"
	"github.com/Iron-Signal-Systems/fi/go/internal/spool"
	"github.com/Iron-Signal-Systems/fi/go/internal/windows/checkpoint"
	"github.com/Iron-Signal-Systems/fi/go/internal/windows/ntfs"
	"github.com/Iron-Signal-Systems/fi/go/internal/windows/process"
	"github.com/Iron-Signal-Systems/fi/go/internal/windows/usn"
)

const windowsErrorInvalidParameter syscall.Errno = 87

const (
	scopeBasisCurrentObjectContained         = "CurrentObjectContained"
	scopeBasisCurrentObjectContainedByHelper = "CurrentObjectContainedByHelper"
	scopeBasisRecordedParentContained        = "RecordedParentContained"
	scopeBasisUnresolvedIncluded             = "ScopeUnresolvedIncluded"
)

type parentScopeStatus string

const (
	parentScopeContained   parentScopeStatus = "Contained"
	parentScopeOutside     parentScopeStatus = "OutsideGovernedRoot"
	parentScopeUnavailable parentScopeStatus = "Unavailable"
	parentScopeError       parentScopeStatus = "Error"
)

type parentScopeResult struct {
	Status parentScopeStatus
	Error  string
}

type selectedUSNObject struct {
	Reobservation usn.ChangeReobservation
	Changes       []records.USNChangeObservation
	ScopeBasis    string
	ScopeDetail   string
}

// spooledUSNReadBoundary records the exact bounded journal range and the
// mechanical scope selection applied before FI writes object records.
type spooledUSNReadBoundary struct {
	ObservedAt                 string                 `json:"observed_at"`
	CollectionMethod           string                 `json:"collection_method"`
	VolumeIdentity             records.VolumeIdentity `json:"volume_identity"`
	JournalID                  string                 `json:"journal_id"`
	StartUSN                   string                 `json:"start_usn"`
	NextUSN                    string                 `json:"next_usn"`
	SourceRecordCount          int                    `json:"source_record_count"`
	SourceDistinctObjectCount  int                    `json:"source_distinct_object_count"`
	SelectedRecordCount        int                    `json:"selected_record_count"`
	SelectedObjectCount        int                    `json:"selected_object_count"`
	IgnoredVolumeRecordCount   int                    `json:"ignored_volume_record_count"`
	IgnoredVolumeObjectCount   int                    `json:"ignored_volume_object_count"`
	ScopeUnresolvedObjectCount int                    `json:"scope_unresolved_object_count"`
	USNReadOperationID         string                 `json:"usn_read_operation_id"`
	ReObservationOperationID   string                 `json:"reobservation_operation_id"`
}

// spooledUSNObjectObservation keeps the raw USN facts for one selected NTFS
// object beside the fresh File-ID observation attempt.
type spooledUSNObjectObservation struct {
	FileIdentity  records.NTFSObjectIdentity      `json:"file_identity"`
	Changes       []records.USNChangeObservation  `json:"changes"`
	ScopeBasis    string                          `json:"scope_basis"`
	ScopeDetail   string                          `json:"scope_detail,omitempty"`
	Status        usn.ReobservationStatus         `json:"status"`
	ReasonCode    string                          `json:"reason_code,omitempty"`
	Error         string                          `json:"error,omitempty"`
	NTFS          *ntfs.Observation               `json:"ntfs_observation,omitempty"`
	ContentHashes *records.ContentHashObservation `json:"content_hashes,omitempty"`
}

type usnSpoolNextSummary struct {
	StatePath                 string                          `json:"state_path"`
	SpoolDir                  string                          `json:"spool_dir"`
	Assessment                checkpoint.ContinuityAssessment `json:"assessment"`
	StartUSN                  string                          `json:"start_usn"`
	NextUSN                   string                          `json:"next_usn,omitempty"`
	SourceUSNRecords          int                             `json:"source_usn_records"`
	DistinctObjects           int                             `json:"distinct_objects"`
	SelectedUSNRecords        int                             `json:"selected_usn_records"`
	SelectedObjects           int                             `json:"selected_objects"`
	IgnoredVolumeUSNRecords   int                             `json:"ignored_volume_usn_records"`
	IgnoredVolumeObjects      int                             `json:"ignored_volume_objects"`
	ScopeUnresolvedObjects    int                             `json:"scope_unresolved_objects"`
	SpooledObjects            int                             `json:"spooled_objects"`
	OutsideScopeObjects       int                             `json:"outside_scope_objects"`
	UnavailableObjects        int                             `json:"unavailable_objects"`
	ReobservationErrors       int                             `json:"reobservation_errors"`
	HashErrors                int                             `json:"hash_errors"`
	Batches                   []spool.FinalizedBatch          `json:"batches"`
	VerifiedBatches           int                             `json:"verified_batches"`
	SupportingSIDStatePath    string                          `json:"supporting_sid_state_path,omitempty"`
	SupportingSIDCountBefore  int                             `json:"supporting_sid_count_before"`
	SupportingSIDCountAfter   int                             `json:"supporting_sid_count_after"`
	SupportingSIDStateUpdated bool                            `json:"supporting_sid_state_updated"`
	CheckpointAdvanced        bool                            `json:"checkpoint_advanced"`
	AdvancedCheckpoint        *checkpoint.USNCheckpoint       `json:"advanced_checkpoint,omitempty"`
}

func runUSNSpoolNext(governedRoot string) {
	summary, err := writeUSNSpoolNext(context.Background(), spoolScopeID, governedRoot)
	if err != nil {
		if summary.StatePath != "" || summary.Assessment.Status != "" {
			writeIndentedJSON(summary)
		}
		fmt.Fprintln(os.Stderr, "ERROR:", err)
		os.Exit(1)
	}
	writeIndentedJSON(summary)
}

func writeUSNSpoolNext(
	ctx context.Context,
	scopeID string,
	governedRoot string,
) (usnSpoolNextSummary, error) {
	statePath, err := checkpoint.DefaultPath(scopeID)
	if err != nil {
		return usnSpoolNextSummary{}, err
	}
	assessment, err := checkpoint.Check(ctx, scopeID, governedRoot, statePath)
	if err != nil {
		return usnSpoolNextSummary{StatePath: statePath}, err
	}

	summary := usnSpoolNextSummary{
		StatePath:          statePath,
		Assessment:         assessment,
		StartUSN:           assessment.Checkpoint.NextUSN,
		Batches:            []spool.FinalizedBatch{},
		CheckpointAdvanced: false,
	}
	if assessment.Status != checkpoint.ContinuityContinuous {
		return summary, fmt.Errorf("%w: %s", ErrUSNContinuityGap, assessment.ReasonCode)
	}

	result, err := usn.ReadAndReobserveJournaled(
		ctx,
		scopeID,
		governedRoot,
		assessment.Checkpoint.NextUSN,
	)
	if err != nil {
		return summary, err
	}
	batch := result.Result.USNBatch
	if err := validateUSNNextBatch(assessment, batch); err != nil {
		return summary, err
	}

	summary.NextUSN = batch.NextUSN
	summary.SourceUSNRecords = len(batch.Records)
	summary.DistinctObjects = len(result.Result.Reobservations)

	changes := groupUSNChanges(batch.Records)
	parentCache := make(map[records.NTFSObjectIdentity]parentScopeResult)
	checker := func(identity records.NTFSObjectIdentity) parentScopeResult {
		if value, ok := parentCache[identity]; ok {
			return value
		}
		value := checkRecordedParentScope(ctx, scopeID, governedRoot, identity)
		parentCache[identity] = value
		return value
	}

	selected := make([]selectedUSNObject, 0, len(result.Result.Reobservations))
	for _, reobservation := range result.Result.Reobservations {
		objectChanges := changes[reobservation.FileIdentity]
		selection, keep := selectUSNObjectForSpool(
			reobservation,
			objectChanges,
			assessment.CurrentGovernedRoot.ObjectIdentity,
			checker,
		)
		if !keep {
			summary.IgnoredVolumeObjects++
			summary.IgnoredVolumeUSNRecords += len(objectChanges)
			continue
		}
		selected = append(selected, selection)
		summary.SelectedObjects++
		summary.SelectedUSNRecords += len(objectChanges)
		if selection.ScopeBasis == scopeBasisUnresolvedIncluded {
			summary.ScopeUnresolvedObjects++
		}
	}

	dir, err := spool.DefaultDir()
	if err != nil {
		return summary, err
	}
	summary.SpoolDir = dir

	// If the bounded journal range contains no governed-root-relevant objects,
	// there are no newly observed governed NTFS security SIDs to retain.
	if len(selected) == 0 {
		refreshed, advanced, err := advanceUSNAfterScopeDecision(
			ctx,
			scopeID,
			governedRoot,
			statePath,
			assessment,
			batch,
		)
		if err != nil {
			return summary, err
		}
		summary.Assessment = refreshed
		summary.CheckpointAdvanced = true
		summary.AdvancedCheckpoint = &advanced
		return summary, nil
	}

	executable, err := runtimeidentity.CurrentExecutable()
	if err != nil {
		return summary, err
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
		return summary, err
	}

	if err := writer.Append("USNReadBoundary", scopeID, spooledUSNReadBoundary{
		ObservedAt:                 batch.ObservedAt,
		CollectionMethod:           batch.CollectionMethod,
		VolumeIdentity:             batch.VolumeIdentity,
		JournalID:                  batch.JournalID,
		StartUSN:                   batch.StartUSN,
		NextUSN:                    batch.NextUSN,
		SourceRecordCount:          summary.SourceUSNRecords,
		SourceDistinctObjectCount:  summary.DistinctObjects,
		SelectedRecordCount:        summary.SelectedUSNRecords,
		SelectedObjectCount:        summary.SelectedObjects,
		IgnoredVolumeRecordCount:   summary.IgnoredVolumeUSNRecords,
		IgnoredVolumeObjectCount:   summary.IgnoredVolumeObjects,
		ScopeUnresolvedObjectCount: summary.ScopeUnresolvedObjects,
		USNReadOperationID:         result.USNReadOperation.OperationID,
		ReObservationOperationID:   result.ReObservationOperation.OperationID,
	}); err != nil {
		return summary, err
	}

	for _, selection := range selected {
		if err := ctx.Err(); err != nil {
			return summary, err
		}
		reobservation := selection.Reobservation

		switch reobservation.Status {
		case usn.ReobservationOutsideGovernedRoot:
			summary.OutsideScopeObjects++
		case usn.ReobservationUnavailable:
			summary.UnavailableObjects++
		case usn.ReobservationError:
			summary.ReobservationErrors++
		}

		record := spooledUSNObjectObservation{
			FileIdentity: reobservation.FileIdentity,
			Changes:      selection.Changes,
			ScopeBasis:   selection.ScopeBasis,
			ScopeDetail:  selection.ScopeDetail,
			Status:       reobservation.Status,
			ReasonCode:   reobservation.ReasonCode,
			Error:        reobservation.Error,
			NTFS:         reobservation.Observation,
		}

		if reobservation.Status == usn.ReobservationObserved &&
			reobservation.Observation != nil {
			if reobservation.Observation.ContentHashes == nil {
				return summary,
					errors.New("USN re-observation missing integrated content hashes")
			}
			hashes := *reobservation.Observation.ContentHashes
			if err := records.ValidateContentHashObservation(hashes); err != nil {
				return summary, err
			}
			if hashes.State == records.ContentHashError {
				summary.HashErrors++
			}

			spooledNTFS := *reobservation.Observation
			spooledNTFS.ContentHashes = nil
			record.NTFS = &spooledNTFS
			record.ContentHashes = &hashes
		}

		if err := writer.Append("USNObjectObservation", scopeID, record); err != nil {
			return summary, err
		}
		summary.SpooledObjects++
	}

	if err := writer.Close(); err != nil {
		return summary, err
	}
	summary.Batches = writer.FinalizedBatches()
	for _, finalized := range summary.Batches {
		verification, err := spool.VerifyManifest(finalized.ManifestPath)
		if err != nil {
			return summary, err
		}
		if !verification.Verified {
			return summary,
				errors.New("FI spool verification did not return verified=true")
		}
		summary.VerifiedBatches++
	}

	// The source batch is now in durable verified FI custody. Only after that
	// boundary may FI update the host-level relevant-SID state. If this state
	// update fails, the USN checkpoint does not advance, so the bounded source
	// range remains replayable rather than silently losing a newly relevant SID.
	sidUpdate, err := mergeUSNObservedSIDsIntoSupportingState(selected)
	summary.SupportingSIDStatePath = sidUpdate.Path
	summary.SupportingSIDCountBefore = sidUpdate.CountBefore
	summary.SupportingSIDCountAfter = sidUpdate.CountAfter
	summary.SupportingSIDStateUpdated = sidUpdate.Updated
	if err != nil {
		return summary, err
	}

	refreshed, advanced, err := advanceUSNAfterScopeDecision(
		ctx,
		scopeID,
		governedRoot,
		statePath,
		assessment,
		batch,
	)
	if err != nil {
		return summary, err
	}
	summary.Assessment = refreshed
	summary.CheckpointAdvanced = true
	summary.AdvancedCheckpoint = &advanced
	return summary, nil
}

func mergeUSNObservedSIDsIntoSupportingState(
	selected []selectedUSNObject,
) (supportingSIDStateMergeResult, error) {
	observedSIDs := newObservedSIDSet()
	for _, selection := range selected {
		reobservation := selection.Reobservation
		if reobservation.Status != usn.ReobservationObserved ||
			reobservation.Observation == nil {
			continue
		}
		addNTFSObservationSIDs(observedSIDs, *reobservation.Observation)
	}
	if len(observedSIDs.values) == 0 {
		return supportingSIDStateMergeResult{}, nil
	}

	identity, err := process.CurrentIdentity()
	if err != nil {
		return supportingSIDStateMergeResult{}, fmt.Errorf(
			"collector identity for supporting SID state: %w",
			err,
		)
	}
	return mergeSupportingSIDState(identity, observedSIDs)
}

func advanceUSNAfterScopeDecision(
	ctx context.Context,
	scopeID string,
	governedRoot string,
	statePath string,
	assessment checkpoint.ContinuityAssessment,
	batch records.USNReadBatch,
) (checkpoint.ContinuityAssessment, checkpoint.USNCheckpoint, error) {
	refreshed, err := checkpoint.Check(ctx, scopeID, governedRoot, statePath)
	if err != nil {
		return checkpoint.ContinuityAssessment{},
			checkpoint.USNCheckpoint{}, err
	}
	if refreshed.Status != checkpoint.ContinuityContinuous {
		return checkpoint.ContinuityAssessment{},
			checkpoint.USNCheckpoint{},
			fmt.Errorf("%w: %s", ErrUSNContinuityGap, refreshed.ReasonCode)
	}
	if err := validateUSNNextBatch(refreshed, batch); err != nil {
		return checkpoint.ContinuityAssessment{},
			checkpoint.USNCheckpoint{}, err
	}
	advanced, err := checkpoint.Advance(
		statePath,
		refreshed,
		assessment.Checkpoint.NextUSN,
		batch.NextUSN,
	)
	if err != nil {
		return checkpoint.ContinuityAssessment{},
			checkpoint.USNCheckpoint{}, err
	}
	return refreshed, advanced, nil
}

func selectUSNObjectForSpool(
	reobservation usn.ChangeReobservation,
	changes []records.USNChangeObservation,
	governedRootIdentity records.NTFSObjectIdentity,
	checkParent func(records.NTFSObjectIdentity) parentScopeResult,
) (selectedUSNObject, bool) {
	selection := selectedUSNObject{
		Reobservation: reobservation,
		Changes:       changes,
	}

	if reobservation.Status == usn.ReobservationObserved &&
		reobservation.Observation != nil {
		selection.ScopeBasis = scopeBasisCurrentObjectContained
		return selection, true
	}
	if reobservation.Status == usn.ReobservationError &&
		reobservation.ReasonCode == usn.ReobservationReasonContainedObjectAccessDenied {
		selection.ScopeBasis = scopeBasisCurrentObjectContainedByHelper
		return selection, true
	}

	seenParents := make(map[records.NTFSObjectIdentity]struct{})
	unresolvedDetail := ""
	for _, change := range changes {
		parent := change.ParentIdentity
		if _, exists := seenParents[parent]; exists {
			continue
		}
		seenParents[parent] = struct{}{}

		if parent == governedRootIdentity {
			selection.ScopeBasis = scopeBasisRecordedParentContained
			return selection, true
		}

		result := checkParent(parent)
		switch result.Status {
		case parentScopeContained:
			selection.ScopeBasis = scopeBasisRecordedParentContained
			return selection, true
		case parentScopeOutside, parentScopeUnavailable:
			continue
		case parentScopeError:
			if unresolvedDetail == "" {
				unresolvedDetail = result.Error
			}
		default:
			if unresolvedDetail == "" {
				unresolvedDetail = "unexpected parent scope status"
			}
		}
	}

	if unresolvedDetail != "" || len(changes) == 0 {
		selection.ScopeBasis = scopeBasisUnresolvedIncluded
		selection.ScopeDetail = unresolvedDetail
		if selection.ScopeDetail == "" {
			selection.ScopeDetail =
				"object had no USN changes available for recorded-parent scope proof"
		}
		return selection, true
	}

	return selectedUSNObject{}, false
}

func checkRecordedParentScope(
	ctx context.Context,
	scopeID string,
	governedRoot string,
	parent records.NTFSObjectIdentity,
) parentScopeResult {
	_, err := ntfs.CollectFileReference(ctx, scopeID, governedRoot, parent)
	if err == nil {
		return parentScopeResult{Status: parentScopeContained}
	}
	if errors.Is(err, ntfs.ErrOutsideGovernedRoot) {
		return parentScopeResult{Status: parentScopeOutside}
	}
	if usn.IsOpenFileByIDAccessDenied(err) {
		containment, containmentErr := usn.CheckObjectContainment(ctx, governedRoot, parent)
		if containmentErr != nil {
			return parentScopeResult{
				Status: parentScopeError,
				Error: errors.Join(
					err,
					fmt.Errorf("FIUSNReader parent containment: %w", containmentErr),
				).Error(),
			}
		}
		switch containment {
		case usn.ContainmentContained:
			return parentScopeResult{Status: parentScopeContained}
		case usn.ContainmentOutside:
			return parentScopeResult{Status: parentScopeOutside}
		case usn.ContainmentUnavailable:
			return parentScopeResult{Status: parentScopeUnavailable}
		}
	}

	var ntfsErr *ntfs.Error
	if errors.As(err, &ntfsErr) &&
		ntfsErr.Stage == ntfs.StageOpen &&
		ntfsErr.Op == "OpenFileById" {
		switch {
		case errors.Is(err, syscall.ERROR_FILE_NOT_FOUND),
			errors.Is(err, syscall.ERROR_PATH_NOT_FOUND),
			errors.Is(err, windowsErrorInvalidParameter):
			return parentScopeResult{Status: parentScopeUnavailable}
		}
	}
	return parentScopeResult{
		Status: parentScopeError,
		Error:  err.Error(),
	}
}

func groupUSNChanges(
	changes []records.USNChangeObservation,
) map[records.NTFSObjectIdentity][]records.USNChangeObservation {
	grouped := make(
		map[records.NTFSObjectIdentity][]records.USNChangeObservation,
	)
	for _, change := range changes {
		grouped[change.FileIdentity] = append(
			grouped[change.FileIdentity],
			change,
		)
	}
	return grouped
}

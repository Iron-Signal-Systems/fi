// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package usn

import (
	"context"
	"errors"
	"fmt"
	"syscall"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
	"github.com/Iron-Signal-Systems/fi/go/internal/windows/ntfs"
	"github.com/Iron-Signal-Systems/fi/go/internal/windows/objbroker"
)

// ReobservationStatus describes what happened when FI tried to turn a USN
// object reference into a fresh governed NTFS observation.
type ReobservationStatus string

const (
	windowsErrorInvalidParameter syscall.Errno = 87

	ReobservationObserved            ReobservationStatus = "Observed"
	ReobservationOutsideGovernedRoot ReobservationStatus = "OutsideGovernedRoot"
	ReobservationUnavailable         ReobservationStatus = "Unavailable"
	ReobservationError               ReobservationStatus = "Error"

	// ReobservationReasonContainedObjectAccessDenied is retained as a stable
	// historical reason value for records produced before FIObjReader fallback
	// existed.
	ReobservationReasonContainedObjectAccessDenied = "ContainedObjectAccessDenied"

	// ReobservationReasonBackupAuthorityObservationFailed identifies the narrow
	// case where the ordinary FICollector File-ID open was access denied, the
	// bounded FIObjReader fallback also failed, and FIUSNReader independently
	// proved that the exact object identity is still contained by the configured
	// governed root.
	ReobservationReasonBackupAuthorityObservationFailed = "BackupAuthorityObservationFailed"
)

// ChangeReobservation links one distinct NTFS object mentioned by a USN batch
// to the result of FI's fresh File-ID observation attempt.
//
// TriggerUSNs contains every USN in the batch that mentioned this object. The
// complete USN records remain authoritative in USNBatch; this list is only the
// deterministic link between those source facts and the one fresh observation.
type ChangeReobservation struct {
	FileIdentity records.NTFSObjectIdentity `json:"file_identity"`
	TriggerUSNs  []string                   `json:"trigger_usns"`
	Status       ReobservationStatus        `json:"status"`
	ReasonCode   string                     `json:"reason_code,omitempty"`
	Error        string                     `json:"error,omitempty"`
	Observation  *ntfs.Observation          `json:"observation,omitempty"`
}

// ReobservationBatch preserves the complete volume-wide USN batch and records
// one bounded re-observation result for every distinct object identity that
// appeared in that batch.
//
// FI does not use the USN leaf filename to decide scope. Surviving objects are
// reopened by File ID and the NTFS collector proves current governed-root
// containment from the returned handle. Objects that no longer exist remain
// represented by their USN facts and an explicit Unavailable result.
type ReobservationBatch struct {
	USNBatch       records.USNReadBatch  `json:"usn_batch"`
	Reobservations []ChangeReobservation `json:"reobservations"`
}

type backupObjectObserver func(
	context.Context,
	string,
	records.NTFSObjectIdentity,
) (ntfs.Observation, error)

type containmentChecker func(
	context.Context,
	string,
	records.NTFSObjectIdentity,
) (ContainmentResult, error)

type fileReferenceCollector func(
	context.Context,
	string,
	string,
	records.NTFSObjectIdentity,
) (ntfs.Observation, error)

// ReadAndReobserve reads one bounded USN batch, then freshly observes each
// distinct object identity referenced by that batch.
func ReadAndReobserve(
	ctx context.Context,
	scopeID string,
	governedRoot string,
	startUSN string,
) (ReobservationBatch, error) {
	batch, err := ReadJournal(ctx, scopeID, governedRoot, startUSN)
	if err != nil {
		return ReobservationBatch{}, err
	}
	return ReobserveBatch(ctx, governedRoot, batch), nil
}

// ReobserveBatch performs the File-ID re-observation stage for an already-read
// USN batch. Per-object failures are recorded in the returned results instead
// of discarding the source USN facts for the rest of the batch.
//
// FICollector always attempts the ordinary nonprivileged File-ID collection
// first. FIObjReader is invoked only when that initial exact OpenFileById fails
// with ERROR_ACCESS_DENIED. Later access-denied failures from metadata,
// security, content hashing, path resolution, or consistency checks never
// trigger backup-authority collection.
func ReobserveBatch(
	ctx context.Context,
	governedRoot string,
	batch records.USNReadBatch,
) ReobservationBatch {
	return reobserveBatchWithDependencies(
		ctx,
		governedRoot,
		batch,
		ntfs.CollectFileReference,
		objbroker.ObserveObject,
		CheckObjectContainment,
	)
}

func reobserveBatchWithDependencies(
	ctx context.Context,
	governedRoot string,
	batch records.USNReadBatch,
	collect fileReferenceCollector,
	observeBackup backupObjectObserver,
	checkContainment containmentChecker,
) ReobservationBatch {
	result := ReobservationBatch{
		USNBatch:       batch,
		Reobservations: make([]ChangeReobservation, 0),
	}

	candidates := distinctReobservationCandidates(batch.Records)
	result.Reobservations = make([]ChangeReobservation, 0, len(candidates))
	for _, candidate := range candidates {
		if err := validateContext(ctx); err != nil {
			result.Reobservations = append(result.Reobservations, ChangeReobservation{
				FileIdentity: candidate.identity,
				TriggerUSNs:  candidate.triggerUSNs,
				Status:       ReobservationError,
				ReasonCode:   "ContextCanceled",
				Error:        err.Error(),
			})
			continue
		}

		observation, err := collect(
			ctx,
			batch.ScopeID,
			governedRoot,
			candidate.identity,
		)
		if err == nil {
			result.Reobservations = append(
				result.Reobservations,
				observedReobservation(candidate, observation),
			)
			continue
		}

		if IsOpenFileByIDAccessDenied(err) {
			backupObservation, backupErr := observeBackup(
				ctx,
				governedRoot,
				candidate.identity,
			)
			if backupErr == nil {
				result.Reobservations = append(
					result.Reobservations,
					observedReobservation(candidate, backupObservation),
				)
				continue
			}

			result.Reobservations = append(
				result.Reobservations,
				classifyBackupAuthorityFailure(
					ctx,
					governedRoot,
					candidate,
					err,
					backupErr,
					checkContainment,
				),
			)
			continue
		}

		status, reason := classifyReobservationError(err)
		result.Reobservations = append(result.Reobservations, ChangeReobservation{
			FileIdentity: candidate.identity,
			TriggerUSNs:  candidate.triggerUSNs,
			Status:       status,
			ReasonCode:   reason,
			Error:        err.Error(),
		})
	}

	return result
}

func classifyBackupAuthorityFailure(
	ctx context.Context,
	governedRoot string,
	candidate reobservationCandidate,
	ordinaryErr error,
	backupErr error,
	checkContainment containmentChecker,
) ChangeReobservation {
	status := ReobservationError
	reason := "ReobservationFailed"
	errorText := errors.Join(
		ordinaryErr,
		fmt.Errorf("FIObjReader observation: %w", backupErr),
	).Error()

	containment, containmentErr := checkContainment(
		ctx,
		governedRoot,
		candidate.identity,
	)
	if containmentErr != nil {
		errorText = errors.Join(
			ordinaryErr,
			fmt.Errorf("FIObjReader observation: %w", backupErr),
			fmt.Errorf("FIUSNReader containment: %w", containmentErr),
		).Error()
	} else {
		switch containment {
		case ContainmentOutside:
			status = ReobservationOutsideGovernedRoot
			reason = "OutsideGovernedRoot"
			errorText = ""

		case ContainmentUnavailable:
			status = ReobservationUnavailable
			reason = "ObjectUnavailableAfterUSN"
			errorText = ""

		case ContainmentContained:
			status = ReobservationError
			reason = ReobservationReasonBackupAuthorityObservationFailed
		}
	}

	return ChangeReobservation{
		FileIdentity: candidate.identity,
		TriggerUSNs:  candidate.triggerUSNs,
		Status:       status,
		ReasonCode:   reason,
		Error:        errorText,
	}
}

func observedReobservation(
	candidate reobservationCandidate,
	observation ntfs.Observation,
) ChangeReobservation {
	return ChangeReobservation{
		FileIdentity: candidate.identity,
		TriggerUSNs:  candidate.triggerUSNs,
		Status:       ReobservationObserved,
		Observation:  &observation,
	}
}

type reobservationCandidate struct {
	identity    records.NTFSObjectIdentity
	triggerUSNs []string
}

// distinctReobservationCandidates keeps first-seen USN order while collapsing
// repeated records for the same NTFS object. This avoids re-reading the same
// object for every DataExtend/Close/Rename record in one bounded journal batch.
func distinctReobservationCandidates(changes []records.USNChangeObservation) []reobservationCandidate {
	positions := make(map[records.NTFSObjectIdentity]int, len(changes))
	candidates := make([]reobservationCandidate, 0, len(changes))

	for _, change := range changes {
		position, exists := positions[change.FileIdentity]
		if !exists {
			positions[change.FileIdentity] = len(candidates)
			candidates = append(candidates, reobservationCandidate{
				identity:    change.FileIdentity,
				triggerUSNs: []string{change.USN},
			})
			continue
		}

		triggers := candidates[position].triggerUSNs
		if len(triggers) == 0 || triggers[len(triggers)-1] != change.USN {
			candidates[position].triggerUSNs = append(triggers, change.USN)
		}
	}
	return candidates
}

func classifyReobservationError(err error) (ReobservationStatus, string) {
	if errors.Is(err, ntfs.ErrOutsideGovernedRoot) {
		return ReobservationOutsideGovernedRoot, "OutsideGovernedRoot"
	}

	// A USN record can legitimately reference an object that no longer exists by
	// the time FI performs the fresh File-ID observation. Restrict this
	// classification to OpenFileById failures so an unrelated invalid-parameter
	// error elsewhere in collection is never mislabeled as object disappearance.
	var ntfsErr *ntfs.Error
	if errors.As(err, &ntfsErr) && ntfsErr.Stage == ntfs.StageOpen && ntfsErr.Op == "OpenFileById" {
		switch {
		case errors.Is(err, syscall.ERROR_FILE_NOT_FOUND),
			errors.Is(err, syscall.ERROR_PATH_NOT_FOUND),
			errors.Is(err, windowsErrorInvalidParameter):
			return ReobservationUnavailable, "ObjectUnavailableAfterUSN"
		}
	}

	return ReobservationError, "ReobservationFailed"
}

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

	// ReobservationReasonContainedObjectAccessDenied identifies the narrow case
	// where FICollector could not open the object by File ID, but FIUSNReader
	// independently proved that the exact object identity is currently inside
	// the configured governed root. Scope is known; collection still failed.
	ReobservationReasonContainedObjectAccessDenied = "ContainedObjectAccessDenied"
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
func ReobserveBatch(
	ctx context.Context,
	governedRoot string,
	batch records.USNReadBatch,
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

		observation, err := ntfs.CollectFileReference(
			ctx,
			batch.ScopeID,
			governedRoot,
			candidate.identity,
		)
		if err == nil {
			result.Reobservations = append(result.Reobservations, ChangeReobservation{
				FileIdentity: candidate.identity,
				TriggerUSNs:  candidate.triggerUSNs,
				Status:       ReobservationObserved,
				Observation:  &observation,
			})
			continue
		}

		status, reason := classifyReobservationError(err)
		errorText := err.Error()
		if IsOpenFileByIDAccessDenied(err) {
			containment, containmentErr := CheckObjectContainment(
				ctx,
				governedRoot,
				candidate.identity,
			)
			if containmentErr != nil {
				errorText = errors.Join(
					err,
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
					reason = ReobservationReasonContainedObjectAccessDenied
				}
			}
		}

		result.Reobservations = append(result.Reobservations, ChangeReobservation{
			FileIdentity: candidate.identity,
			TriggerUSNs:  candidate.triggerUSNs,
			Status:       status,
			ReasonCode:   reason,
			Error:        errorText,
		})
	}
	return result
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

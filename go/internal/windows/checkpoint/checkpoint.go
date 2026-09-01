// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package checkpoint

import (
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
)

const SchemaVersion = "fi-usn-checkpoint/0.1"

type ContinuityStatus string

const (
	ContinuityContinuous ContinuityStatus = "Continuous"
	ContinuityGap        ContinuityStatus = "Gap"
)

var (
	ErrInvalidCheckpoint  = errors.New("invalid FI USN checkpoint")
	ErrContinuityGap      = errors.New("USN continuity gap")
	ErrCheckpointConflict = errors.New("USN checkpoint changed since it was read")
)

// USNCheckpoint is FI-owned mutable runtime state. It is not an authoritative
// file-history record and is never used as a substitute for source observations.
type USNCheckpoint struct {
	Version      string                       `json:"version"`
	ScopeID      string                       `json:"scope_id"`
	GovernedRoot records.GovernedRootIdentity `json:"governed_root"`
	JournalID    string                       `json:"journal_id"`
	NextUSN      string                       `json:"next_usn"`
	UpdatedAt    string                       `json:"updated_at"`
}

// ContinuityAssessment compares one persisted checkpoint with the current
// governed-root identity and current NTFS journal state.
type ContinuityAssessment struct {
	CheckedAt           string                       `json:"checked_at"`
	Status              ContinuityStatus             `json:"status"`
	ReasonCode          string                       `json:"reason_code,omitempty"`
	Checkpoint          USNCheckpoint                `json:"checkpoint"`
	CurrentGovernedRoot records.GovernedRootIdentity `json:"current_governed_root"`
	JournalState        records.USNJournalState      `json:"journal_state"`
}

func Validate(value USNCheckpoint) error {
	if value.Version != SchemaVersion {
		return fmt.Errorf("%w: unsupported version", ErrInvalidCheckpoint)
	}
	if value.ScopeID == "" || value.ScopeID != value.GovernedRoot.ScopeID {
		return fmt.Errorf("%w: scope mismatch", ErrInvalidCheckpoint)
	}
	if err := records.ValidateGovernedRootIdentity(value.GovernedRoot); err != nil {
		return fmt.Errorf("%w: governed root: %v", ErrInvalidCheckpoint, err)
	}
	if _, err := canonicalUnsigned(value.JournalID); err != nil {
		return fmt.Errorf("%w: journal_id", ErrInvalidCheckpoint)
	}
	if _, err := canonicalUnsigned(value.NextUSN); err != nil {
		return fmt.Errorf("%w: next_usn", ErrInvalidCheckpoint)
	}
	when, err := time.Parse(time.RFC3339Nano, value.UpdatedAt)
	if err != nil || when.Location() != time.UTC {
		return fmt.Errorf("%w: updated_at", ErrInvalidCheckpoint)
	}
	return nil
}

func Assess(
	value USNCheckpoint,
	currentRoot records.GovernedRootIdentity,
	journal records.USNJournalState,
) (ContinuityAssessment, error) {
	if err := Validate(value); err != nil {
		return ContinuityAssessment{}, err
	}
	if err := records.ValidateGovernedRootIdentity(currentRoot); err != nil {
		return ContinuityAssessment{}, err
	}
	if err := records.ValidateUSNJournalState(journal); err != nil {
		return ContinuityAssessment{}, err
	}

	assessment := ContinuityAssessment{
		CheckedAt:           time.Now().UTC().Format(time.RFC3339Nano),
		Status:              ContinuityContinuous,
		Checkpoint:          value,
		CurrentGovernedRoot: currentRoot,
		JournalState:        journal,
	}

	switch {
	case value.ScopeID != journal.ScopeID || value.ScopeID != currentRoot.ScopeID:
		return gap(assessment, "ScopeChanged"), nil
	case !sameVolume(value.GovernedRoot.VolumeIdentity, currentRoot.VolumeIdentity):
		return gap(assessment, "GovernedRootVolumeChanged"), nil
	case !sameObject(value.GovernedRoot.ObjectIdentity, currentRoot.ObjectIdentity):
		return gap(assessment, "GovernedRootObjectChanged"), nil
	case !sameVolume(value.GovernedRoot.VolumeIdentity, journal.VolumeIdentity):
		return gap(assessment, "JournalVolumeChanged"), nil
	case value.JournalID != journal.JournalID:
		return gap(assessment, "JournalIDChanged"), nil
	}

	checkpointUSN, _ := canonicalUnsigned(value.NextUSN)
	firstUSN, err := canonicalUnsigned(journal.FirstUSN)
	if err != nil {
		return ContinuityAssessment{}, err
	}
	lowestValidUSN, err := canonicalUnsigned(journal.LowestValidUSN)
	if err != nil {
		return ContinuityAssessment{}, err
	}
	nextUSN, err := canonicalUnsigned(journal.NextUSN)
	if err != nil {
		return ContinuityAssessment{}, err
	}

	switch {
	case lowestValidUSN != 0 && checkpointUSN < lowestValidUSN:
		return gap(assessment, "CheckpointBeforeLowestValidUSN"), nil
	case checkpointUSN < firstUSN:
		return gap(assessment, "CheckpointAgedOut"), nil
	case checkpointUSN > nextUSN:
		return gap(assessment, "CheckpointAheadOfJournal"), nil
	default:
		return assessment, nil
	}
}

// ValidateAdvance verifies that a caller may move a checkpoint from
// expectedCurrentUSN to newNextUSN without crossing a continuity boundary or
// moving backward/beyond the observed journal. It performs no I/O and does not
// decide whether the bounded source range is safe to retire; that is the
// caller's durability/processing responsibility.
func ValidateAdvance(
	assessment ContinuityAssessment,
	expectedCurrentUSN string,
	newNextUSN string,
) error {
	if assessment.Status != ContinuityContinuous {
		return ErrContinuityGap
	}
	if assessment.Checkpoint.NextUSN != expectedCurrentUSN {
		return ErrCheckpointConflict
	}

	current, err := canonicalUnsigned(expectedCurrentUSN)
	if err != nil {
		return err
	}
	next, err := canonicalUnsigned(newNextUSN)
	if err != nil {
		return err
	}
	journalNext, err := canonicalUnsigned(assessment.JournalState.NextUSN)
	if err != nil {
		return err
	}
	if next < current {
		return fmt.Errorf("checkpoint cannot move backward")
	}
	if next > journalNext {
		return fmt.Errorf("checkpoint cannot move beyond current journal NextUSN")
	}
	return nil
}

func sameVolume(left records.VolumeIdentity, right records.VolumeIdentity) bool {
	return left.VolumeGUID == right.VolumeGUID && left.VolumeSerial == right.VolumeSerial
}

func sameObject(left records.NTFSObjectIdentity, right records.NTFSObjectIdentity) bool {
	return left.FileReferenceNumber == right.FileReferenceNumber && left.SequenceNumber == right.SequenceNumber
}

func gap(value ContinuityAssessment, reason string) ContinuityAssessment {
	value.Status = ContinuityGap
	value.ReasonCode = reason
	return value
}

func canonicalUnsigned(value string) (uint64, error) {
	if value == "0" {
		return 0, nil
	}
	if value == "" || value[0] < '1' || value[0] > '9' {
		return 0, errors.New("not canonical unsigned decimal")
	}
	for i := 1; i < len(value); i++ {
		if value[i] < '0' || value[i] > '9' {
			return 0, errors.New("not canonical unsigned decimal")
		}
	}
	return strconv.ParseUint(value, 10, 64)
}

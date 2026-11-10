// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

// Package volumeepoch supplies pure, fail-closed continuity decisions for the
// proposed volume-owned NTFS USN pipeline. It does not read source volumes,
// create checkpoints, reconcile missing history, or authorize acquisition.
package volumeepoch

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

const CheckpointVersion = "fi-volume-usn-checkpoint/1"

// State is an assessment of source-history continuity, not an operational
// success indicator. Both BaselineRequired and Gap require separate custody
// and reconciliation work before their replacement checkpoints can be written.
type State string

const (
	BaselineRequired State = "BaselineRequired"
	Continuous       State = "Continuous"
	Gap              State = "Gap"
)

// Reason is stable evidence describing why a checkpoint cannot be used.
type Reason string

const (
	NoCheckpoint      Reason = "NoCheckpoint"
	VolumeChanged     Reason = "VolumeChanged"
	JournalChanged    Reason = "JournalChanged"
	JournalAgedOut    Reason = "JournalAgedOut"
	BeforeLowestValid Reason = "BeforeLowestValidUSN"
	AheadOfJournal    Reason = "AheadOfJournal"
)

var (
	ErrInvalidCheckpoint = errors.New("invalid volume-owned USN checkpoint")
	ErrInvalidJournal    = errors.New("invalid current NTFS USN journal state")
)

// Identity describes the observed NTFS instance and USN journal. VolumeGUID
// is an OS-managed locator, NOT proof that a formatted volume was unchanged.
// VolumeSerial is the 64-bit FILE_ID_INFO identity value, not the 32-bit serial
// shown by fsutil volumeinfo. JournalID detects journal recreation.
// All unsigned source identifiers use canonical decimal strings to preserve
// full uint64 precision when serialized as JSON.
type Identity struct {
	VolumeGUID   string `json:"volume_guid"`
	VolumeSerial string `json:"volume_serial"`
	JournalID    string `json:"journal_id"`
}

// Checkpoint is scoped to a single operator-enrolled logical volume and epoch.
// An epoch never spans a known NTFS-history discontinuity. The checkpoint's
// cursor may advance only after durable capture is independently verified.
type Checkpoint struct {
	Version      string   `json:"version"`
	EnrollmentID string   `json:"enrollment_id"`
	Epoch        uint64   `json:"epoch"`
	Identity     Identity `json:"identity"`
	NextUSN      string   `json:"next_usn"`
}

// Journal describes a single independently acquired, trusted snapshot of
// the current volume journal. It must come from the enrolled native volume,
// not from a path guessed by the collector.
type Journal struct {
	Identity       Identity `json:"identity"`
	FirstUSN       string   `json:"first_usn"`
	LowestValidUSN string   `json:"lowest_valid_usn"`
	NextUSN        string   `json:"next_usn"`
}

type Assessment struct {
	State  State  `json:"state"`
	Reason Reason `json:"reason,omitempty"`
}

// Assess verifies that a saved checkpoint can continue against a current
// NTFS journal. A nil checkpoint requires explicit initial onboarding. A gap
// never silently resets a cursor or asserts missing history was collected.
// Errors indicate malformed/untrustworthy state rather than a recoverable gap.
func Assess(enrollmentID string, saved *Checkpoint, current Journal) (Assessment, error) {
	if err := validateJournal(current); err != nil {
		return Assessment{}, err
	}
	if !validEnrollmentID(enrollmentID) {
		return Assessment{}, errors.New("invalid canonical volume enrollment identity")
	}
	if saved == nil {
		return Assessment{State: BaselineRequired, Reason: NoCheckpoint}, nil
	}
	if err := validateCheckpoint(*saved, enrollmentID); err != nil {
		return Assessment{}, err
	}
	savedGUID, _ := canonicalVolumeGUID(saved.Identity.VolumeGUID)
	currentGUID, _ := canonicalVolumeGUID(current.Identity.VolumeGUID)
	if savedGUID != currentGUID || saved.Identity.VolumeSerial != current.Identity.VolumeSerial {
		return Assessment{State: Gap, Reason: VolumeChanged}, nil
	}
	if saved.Identity.JournalID != current.Identity.JournalID {
		return Assessment{State: Gap, Reason: JournalChanged}, nil
	}
	cursor, _ := parseDecimal(saved.NextUSN)
	first, _ := parseDecimal(current.FirstUSN)
	lowest, _ := parseDecimal(current.LowestValidUSN)
	next, _ := parseDecimal(current.NextUSN)
	switch {
	case lowest != 0 && cursor < lowest:
		return Assessment{State: Gap, Reason: BeforeLowestValid}, nil
	case cursor < first:
		return Assessment{State: Gap, Reason: JournalAgedOut}, nil
	case cursor > next:
		return Assessment{State: Gap, Reason: AheadOfJournal}, nil
	default:
		return Assessment{State: Continuous}, nil
	}
}

// ValidateCheckpoint validates one exact, persisted epoch checkpoint without
// inventing a current journal snapshot. It grants no volume-read permission,
// does not establish baseline custody and never writes state.
func ValidateCheckpoint(enrollmentID string, saved Checkpoint) error {
	if !validEnrollmentID(enrollmentID) {
		return fmt.Errorf("%w: invalid enrolled-volume key", ErrInvalidCheckpoint)
	}
	return validateCheckpoint(saved, enrollmentID)
}

func validateCheckpoint(saved Checkpoint, enrollmentID string) error {
	if saved.Version != CheckpointVersion || saved.Epoch == 0 || saved.EnrollmentID != enrollmentID {
		return fmt.Errorf("%w: version, epoch or enrollment identity mismatch", ErrInvalidCheckpoint)
	}
	if err := validateIdentity(saved.Identity); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidCheckpoint, err)
	}
	if _, err := parseDecimal(saved.NextUSN); err != nil {
		return fmt.Errorf("%w: next_usn: %v", ErrInvalidCheckpoint, err)
	}
	return nil
}

func validateJournal(j Journal) error {
	if err := validateIdentity(j.Identity); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidJournal, err)
	}
	first, err := parseDecimal(j.FirstUSN)
	if err != nil {
		return fmt.Errorf("%w: first_usn: %v", ErrInvalidJournal, err)
	}
	low, err := parseDecimal(j.LowestValidUSN)
	if err != nil {
		return fmt.Errorf("%w: lowest_valid_usn: %v", ErrInvalidJournal, err)
	}
	next, err := parseDecimal(j.NextUSN)
	if err != nil {
		return fmt.Errorf("%w: next_usn: %v", ErrInvalidJournal, err)
	}
	if first > next || low > next {
		return fmt.Errorf("%w: journal bounds are inconsistent", ErrInvalidJournal)
	}
	return nil
}

func validateIdentity(id Identity) error {
	if _, err := canonicalVolumeGUID(id.VolumeGUID); err != nil {
		return err
	}
	if _, err := parseDecimal(id.VolumeSerial); err != nil {
		return fmt.Errorf("volume_serial: %w", err)
	}
	if _, err := parseDecimal(id.JournalID); err != nil {
		return fmt.Errorf("journal_id: %w", err)
	}
	return nil
}

// canonicalVolumeGUID accepts the exact Windows volume GUID path shape,
// insensitive only to ASCII letter case. Arbitrary device paths, drive letters,
// and UNC paths cannot be substituted for an approved native volume identity.
func canonicalVolumeGUID(value string) (string, error) {
	const prefix = `\\?\Volume{`
	const suffix = `}\`
	if len(value) != len(prefix)+36+len(suffix) ||
		!strings.EqualFold(value[:min(len(value), len(prefix))], prefix) ||
		!strings.HasSuffix(value, suffix) {
		return "", errors.New("volume GUID must be a Windows volume GUID path")
	}
	guid := value[len(prefix) : len(prefix)+36]
	for i := 0; i < len(guid); i++ {
		switch i {
		case 8, 13, 18, 23:
			if guid[i] != '-' {
				return "", errors.New("malformed volume GUID separators")
			}
		default:
			c := guid[i]
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
				return "", errors.New("volume GUID contains nonhexadecimal characters")
			}
		}
	}
	return strings.ToLower(guid), nil
}

func parseDecimal(value string) (uint64, error) {
	if value == "0" {
		return 0, nil
	}
	if len(value) == 0 || value[0] < '1' || value[0] > '9' {
		return 0, errors.New("must be canonical unsigned decimal")
	}
	for i := 1; i < len(value); i++ {
		if value[i] < '0' || value[i] > '9' {
			return 0, errors.New("must be canonical unsigned decimal")
		}
	}
	return strconv.ParseUint(value, 10, 64)
}

// validEnrollmentID restricts the stable key used for later volume-owned state
// filenames. It deliberately does not accept a path, arbitrary Unicode or an
// unbounded identifier. This is not a substitute for enrolled-volume consent.
func validEnrollmentID(id string) bool {
	if len(id) == 0 || len(id) > 64 || id[0] < 'a' || id[0] > 'z' {
		return false
	}
	for i := 1; i < len(id); i++ {
		c := id[i]
		if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

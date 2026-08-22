// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package records

import (
	"fmt"
	"sort"
)

// USNJournalState records the source-side state of one NTFS change journal.
//
// The journal identifier and USN bounds are source facts. Backend continuity
// logic can later compare successive states to determine whether an earlier
// checkpoint is still valid. The collector does not infer continuity here.
type USNJournalState struct {
	ObservedAt       string         `json:"observed_at"`
	CollectionMethod string         `json:"collection_method"`
	ScopeID          string         `json:"scope_id"`
	VolumeIdentity   VolumeIdentity `json:"volume_identity"`
	JournalID        string         `json:"journal_id"`
	FirstUSN         string         `json:"first_usn"`
	NextUSN          string         `json:"next_usn"`
	LowestValidUSN   string         `json:"lowest_valid_usn"`
	MaxUSN           string         `json:"max_usn"`
	MaximumSize      string         `json:"maximum_size"`
	AllocationDelta  string         `json:"allocation_delta"`
}

// USNChangeObservation is one USN_RECORD_V2 source record.
//
// FileIdentity and ParentIdentity preserve the NTFS file references carried by
// the journal. FileNameUTF16LEBase64URL is only the name recorded in this USN
// record; it is not treated as a complete path or as object identity.
type USNChangeObservation struct {
	MajorVersion             string             `json:"major_version"`
	MinorVersion             string             `json:"minor_version"`
	FileIdentity             NTFSObjectIdentity `json:"file_identity"`
	ParentIdentity           NTFSObjectIdentity `json:"parent_identity"`
	USN                      string             `json:"usn"`
	Timestamp                string             `json:"timestamp"`
	ReasonRaw                string             `json:"reason_raw"`
	ReasonNames              []string           `json:"reason_names"`
	SourceInfoRaw            string             `json:"source_info_raw"`
	SecurityID               string             `json:"security_id"`
	FileAttributesRaw        string             `json:"file_attributes_raw"`
	FileNameUTF16LEBase64URL string             `json:"file_name_utf16le_base64url"`
}

// USNReadBatch is one bounded FSCTL_READ_USN_JOURNAL result.
//
// StartUSN is the requested starting position. NextUSN is the continuation USN
// returned by Windows in the first eight bytes of the output buffer.
type USNReadBatch struct {
	ObservedAt       string                 `json:"observed_at"`
	CollectionMethod string                 `json:"collection_method"`
	ScopeID          string                 `json:"scope_id"`
	VolumeIdentity   VolumeIdentity         `json:"volume_identity"`
	JournalID        string                 `json:"journal_id"`
	StartUSN         string                 `json:"start_usn"`
	NextUSN          string                 `json:"next_usn"`
	Records          []USNChangeObservation `json:"records"`
}

// ValidateUSNJournalState validates the shared change-journal state record.
func ValidateUSNJournalState(state USNJournalState) error {
	if err := require(state.ObservedAt, "usn_journal_state.observed_at"); err != nil {
		return err
	}
	if err := ValidateObservedAt(state.ObservedAt); err != nil {
		return err
	}
	if err := require(state.CollectionMethod, "usn_journal_state.collection_method"); err != nil {
		return err
	}
	if err := require(state.ScopeID, "usn_journal_state.scope_id"); err != nil {
		return err
	}
	if err := ValidateVolumeIdentity(state.VolumeIdentity); err != nil {
		return err
	}

	for _, item := range []struct {
		field string
		value string
	}{
		{"usn_journal_state.journal_id", state.JournalID},
		{"usn_journal_state.first_usn", state.FirstUSN},
		{"usn_journal_state.next_usn", state.NextUSN},
		{"usn_journal_state.lowest_valid_usn", state.LowestValidUSN},
		{"usn_journal_state.max_usn", state.MaxUSN},
		{"usn_journal_state.maximum_size", state.MaximumSize},
		{"usn_journal_state.allocation_delta", state.AllocationDelta},
	} {
		if err := validateDecimal(item.value, item.field); err != nil {
			return err
		}
	}
	return nil
}

// ValidateUSNReadBatch validates a bounded USN journal read and its records.
func ValidateUSNReadBatch(batch USNReadBatch) error {
	if err := require(batch.ObservedAt, "usn_read_batch.observed_at"); err != nil {
		return err
	}
	if err := ValidateObservedAt(batch.ObservedAt); err != nil {
		return err
	}
	if err := require(batch.CollectionMethod, "usn_read_batch.collection_method"); err != nil {
		return err
	}
	if err := require(batch.ScopeID, "usn_read_batch.scope_id"); err != nil {
		return err
	}
	if err := ValidateVolumeIdentity(batch.VolumeIdentity); err != nil {
		return err
	}
	for _, item := range []struct {
		field string
		value string
	}{
		{"usn_read_batch.journal_id", batch.JournalID},
		{"usn_read_batch.start_usn", batch.StartUSN},
		{"usn_read_batch.next_usn", batch.NextUSN},
	} {
		if err := validateDecimal(item.value, item.field); err != nil {
			return err
		}
	}

	previousUSN := uint64(0)
	for i, record := range batch.Records {
		if err := ValidateUSNChangeObservation(record); err != nil {
			return err
		}
		currentUSN, err := canonicalUnsigned(record.USN)
		if err != nil {
			return invalid("InvalidDecimal", fmt.Sprintf("usn_read_batch.records[%d].usn", i))
		}
		if i > 0 && currentUSN < previousUSN {
			return invalid("UnsortedCollection", "usn_read_batch.records")
		}
		previousUSN = currentUSN
	}
	return nil
}

// ValidateUSNChangeObservation validates one parsed USN_RECORD_V2 source fact.
func ValidateUSNChangeObservation(record USNChangeObservation) error {
	if record.MajorVersion != "2" {
		return invalid("UnsupportedValue", "usn_change.major_version")
	}
	if err := validateDecimal(record.MinorVersion, "usn_change.minor_version"); err != nil {
		return err
	}
	if err := ValidateNTFSObjectIdentity(record.FileIdentity); err != nil {
		return err
	}
	if err := ValidateNTFSObjectIdentity(record.ParentIdentity); err != nil {
		return err
	}
	for _, item := range []struct {
		field string
		value string
	}{
		{"usn_change.usn", record.USN},
		{"usn_change.reason_raw", record.ReasonRaw},
		{"usn_change.source_info_raw", record.SourceInfoRaw},
		{"usn_change.security_id", record.SecurityID},
		{"usn_change.file_attributes_raw", record.FileAttributesRaw},
	} {
		if err := validateDecimal(item.value, item.field); err != nil {
			return err
		}
	}
	if err := ValidateObservedAt(record.Timestamp); err != nil {
		return err
	}
	if err := validateUTF16LEBase64URL(record.FileNameUTF16LEBase64URL, "usn_change.file_name_utf16le_base64url"); err != nil {
		return err
	}
	if !sort.StringsAreSorted(record.ReasonNames) {
		return invalid("UnsortedCollection", "usn_change.reason_names")
	}
	for i := 1; i < len(record.ReasonNames); i++ {
		if record.ReasonNames[i] == record.ReasonNames[i-1] {
			return invalid("DuplicateValue", "usn_change.reason_names")
		}
	}
	return nil
}

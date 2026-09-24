// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build linux

package recordingest

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
	"github.com/Iron-Signal-Systems/fi/go/internal/windows/ntfs"
	"github.com/jackc/pgx/v5"
)

type fileObservationPayload struct {
	NTFS          ntfs.Observation               `json:"ntfs_observation"`
	ContentHashes records.ContentHashObservation `json:"content_hashes"`
}

type ntfsCollectionErrorPayload struct {
	PathDisplay          string `json:"path_display"`
	PathUTF16LEBase64URL string `json:"path_utf16le_base64url"`
	Error                string `json:"error"`
}

type supportingSourceCollectionErrorPayload struct {
	Source string `json:"source"`
	Error  string `json:"error"`
}

type usnObjectObservationPayload struct {
	FileIdentity  records.NTFSObjectIdentity      `json:"file_identity"`
	Changes       []records.USNChangeObservation  `json:"changes"`
	ScopeBasis    string                          `json:"scope_basis"`
	ScopeDetail   string                          `json:"scope_detail,omitempty"`
	Status        string                          `json:"status"`
	ReasonCode    string                          `json:"reason_code,omitempty"`
	Error         string                          `json:"error,omitempty"`
	NTFS          *ntfs.Observation               `json:"ntfs_observation,omitempty"`
	ContentHashes *records.ContentHashObservation `json:"content_hashes,omitempty"`
}

type usnReadBoundaryPayload struct {
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

// ProjectSourceRecord strictly decodes one already-validated source envelope
// into the relational tables owned by that record kind. Unknown payload fields
// fail closed: PostgreSQL must never silently discard collector facts.
func ProjectSourceRecord(ctx context.Context, tx pgx.Tx, sourceID string, sourceRecordID int64, record SourceRecord) error {
	if ctx == nil || tx == nil || sourceID == "" || sourceRecordID <= 0 {
		return errors.New("FI relational projector input is incomplete")
	}

	switch record.Record.RecordKind {
	case "CollectorIdentity":
		var value records.ProcessIdentityObservation
		if err := decodeStrictPayload(record.Record.Payload, &value); err != nil {
			return projectionDecodeError(record.Record.RecordKind, err)
		}
		if err := records.ValidateProcessIdentityObservation(value); err != nil {
			return projectionValidationError(record.Record.RecordKind, err)
		}
		return projectCollectorIdentity(ctx, tx, sourceRecordID, value)

	case "DirectoryPrincipalSnapshot":
		var value records.DirectoryPrincipalSnapshot
		if err := decodeStrictPayload(record.Record.Payload, &value); err != nil {
			return projectionDecodeError(record.Record.RecordKind, err)
		}
		if err := records.ValidateDirectoryPrincipalSnapshot(value); err != nil {
			return projectionValidationError(record.Record.RecordKind, err)
		}
		return projectDirectoryPrincipalSnapshot(ctx, tx, sourceRecordID, value)

	case "FileObservation":
		var value fileObservationPayload
		if err := decodeStrictPayload(record.Record.Payload, &value); err != nil {
			return projectionDecodeError(record.Record.RecordKind, err)
		}
		value.NTFS.ContentHashes = &value.ContentHashes
		if err := ntfs.ValidateObservation(value.NTFS); err != nil {
			return projectionValidationError(record.Record.RecordKind, err)
		}
		if value.NTFS.GovernedRoot.ScopeID != record.Record.ScopeID {
			return projectionValidationError(record.Record.RecordKind, errors.New("governed-root scope does not match source envelope"))
		}
		return projectNTFSObservation(ctx, tx, sourceID, sourceRecordID, value.NTFS, &value.ContentHashes)

	case "LocalPrincipalSnapshot":
		var value records.LocalPrincipalSnapshot
		if err := decodeStrictPayload(record.Record.Payload, &value); err != nil {
			return projectionDecodeError(record.Record.RecordKind, err)
		}
		if err := records.ValidateLocalPrincipalSnapshot(value); err != nil {
			return projectionValidationError(record.Record.RecordKind, err)
		}
		return projectLocalPrincipalSnapshot(ctx, tx, sourceRecordID, value)

	case "NTFSCollectionError":
		var value ntfsCollectionErrorPayload
		if err := decodeStrictPayload(record.Record.Payload, &value); err != nil {
			return projectionDecodeError(record.Record.RecordKind, err)
		}
		if value.PathDisplay == "" || value.PathUTF16LEBase64URL == "" || value.Error == "" {
			return projectionValidationError(record.Record.RecordKind, errors.New("collection error fields are required"))
		}
		return projectNTFSCollectionError(ctx, tx, sourceRecordID, value)

	case "SMBShareSnapshot":
		var value records.SMBShareSnapshot
		if err := decodeStrictPayload(record.Record.Payload, &value); err != nil {
			return projectionDecodeError(record.Record.RecordKind, err)
		}
		if err := records.ValidateSMBShareSnapshot(value); err != nil {
			return projectionValidationError(record.Record.RecordKind, err)
		}
		return projectSMBShareSnapshot(ctx, tx, sourceRecordID, value)

	case "SupportingSourceCollectionError":
		var value supportingSourceCollectionErrorPayload
		if err := decodeStrictPayload(record.Record.Payload, &value); err != nil {
			return projectionDecodeError(record.Record.RecordKind, err)
		}
		if value.Source == "" || value.Error == "" {
			return projectionValidationError(record.Record.RecordKind, errors.New("supporting-source error fields are required"))
		}
		return projectSupportingSourceCollectionError(ctx, tx, sourceRecordID, value)

	case "USNContinuityGap":
		var value records.USNContinuityGapObservation
		if err := decodeStrictPayload(record.Record.Payload, &value); err != nil {
			return projectionDecodeError(record.Record.RecordKind, err)
		}
		if err := records.ValidateUSNContinuityGapObservation(value); err != nil {
			return projectionValidationError(record.Record.RecordKind, err)
		}
		return projectUSNContinuityGap(ctx, tx, sourceRecordID, value)

	case "USNObjectObservation":
		var value usnObjectObservationPayload
		if err := decodeStrictPayload(record.Record.Payload, &value); err != nil {
			return projectionDecodeError(record.Record.RecordKind, err)
		}
		return projectUSNObjectObservation(ctx, tx, sourceID, sourceRecordID, record.Record.ScopeID, value)

	case "USNReadBoundary":
		var value usnReadBoundaryPayload
		if err := decodeStrictPayload(record.Record.Payload, &value); err != nil {
			return projectionDecodeError(record.Record.RecordKind, err)
		}
		return projectUSNReadBoundary(ctx, tx, sourceID, sourceRecordID, record.Record.ScopeID, value)

	case "WindowsSecurityContinuityGap":
		var value records.WindowsSecurityContinuityGapObservation
		if err := decodeStrictPayload(record.Record.Payload, &value); err != nil {
			return projectionDecodeError(record.Record.RecordKind, err)
		}
		if err := records.ValidateWindowsSecurityContinuityGapObservation(value); err != nil {
			return projectionValidationError(record.Record.RecordKind, err)
		}
		return projectWindowsSecurityContinuityGap(ctx, tx, sourceRecordID, value)

	case "WindowsSecurityCoverage":
		var value records.WindowsSecurityCoverageObservation
		if err := decodeStrictPayload(record.Record.Payload, &value); err != nil {
			return projectionDecodeError(record.Record.RecordKind, err)
		}
		if err := records.ValidateWindowsSecurityCoverageObservation(value); err != nil {
			return projectionValidationError(record.Record.RecordKind, err)
		}
		return projectWindowsSecurityCoverage(ctx, tx, sourceRecordID, value)

	case "WindowsSecurityEvent":
		var value records.WindowsSecurityEventObservation
		if err := decodeStrictPayload(record.Record.Payload, &value); err != nil {
			return projectionDecodeError(record.Record.RecordKind, err)
		}
		if err := records.ValidateWindowsSecurityEventObservation(value); err != nil {
			return projectionValidationError(record.Record.RecordKind, err)
		}
		return projectWindowsSecurityEvent(ctx, tx, sourceRecordID, value)

	default:
		return fmt.Errorf("FI relational projector does not support record kind %q", record.Record.RecordKind)
	}
}

func projectionDecodeError(kind string, err error) error {
	return fmt.Errorf("decode FI relational %s payload: %w", kind, err)
}

func projectionValidationError(kind string, err error) error {
	return fmt.Errorf("validate FI relational %s payload: %w", kind, err)
}

func rawPayloadForTest(value any) json.RawMessage {
	raw, _ := json.Marshal(value)
	return raw
}

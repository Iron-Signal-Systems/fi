// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package recordingest

import (
	"context"
	"errors"
	"fmt"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
	"github.com/Iron-Signal-Systems/fi/go/internal/windows/ntfs"
	"github.com/jackc/pgx/v5"
)

func projectUSNReadBoundary(ctx context.Context, tx pgx.Tx, sourceID string, sourceRecordID int64, scopeID string, value usnReadBoundaryPayload) error {
	if sourceID == "" || scopeID == "" {
		return errors.New("FI USN read boundary source and scope are required")
	}
	if value.CollectionMethod != records.WindowsUSNCollectionMethod {
		return fmt.Errorf("unsupported FI USN read boundary collection method %q", value.CollectionMethod)
	}
	if err := records.ValidateVolumeIdentity(value.VolumeIdentity); err != nil {
		return fmt.Errorf("validate FI USN read boundary volume: %w", err)
	}
	if value.SourceRecordCount < 0 || value.SourceDistinctObjectCount < 0 || value.SelectedRecordCount < 0 || value.SelectedObjectCount < 0 || value.IgnoredVolumeRecordCount < 0 || value.IgnoredVolumeObjectCount < 0 || value.ScopeUnresolvedObjectCount < 0 {
		return errors.New("FI USN read boundary counts must not be negative")
	}
	if value.USNReadOperationID == "" || value.ReObservationOperationID == "" {
		return errors.New("FI USN read boundary operation IDs are required")
	}
	observedAt, err := parseRFC3339(value.ObservedAt, "usn_read_boundary.observed_at")
	if err != nil {
		return err
	}
	volumeID, err := ensureNTFSVolume(ctx, tx, sourceID, value.VolumeIdentity)
	if err != nil {
		return err
	}
	for field, valueText := range map[string]string{"journal_id": value.JournalID, "start_usn": value.StartUSN, "next_usn": value.NextUSN} {
		if _, err := parseDecimalCanonical(valueText, "usn_read_boundary."+field); err != nil {
			return err
		}
	}
	_, err = tx.Exec(ctx, `
INSERT INTO fi.usn_read_boundary (
 source_record_id,observed_at,collection_method,ntfs_volume_id,journal_id,start_usn,next_usn,source_record_count,source_distinct_object_count,
 selected_record_count,selected_object_count,ignored_volume_record_count,ignored_volume_object_count,scope_unresolved_object_count,
 usn_read_operation_id,reobservation_operation_id
) VALUES ($1,$2,$3,$4,$5::text::numeric,$6::text::numeric,$7::text::numeric,$8,$9,$10,$11,$12,$13,$14,$15,$16)
`, sourceRecordID, observedAt, value.CollectionMethod, volumeID, value.JournalID, value.StartUSN, value.NextUSN, value.SourceRecordCount,
		value.SourceDistinctObjectCount, value.SelectedRecordCount, value.SelectedObjectCount, value.IgnoredVolumeRecordCount, value.IgnoredVolumeObjectCount,
		value.ScopeUnresolvedObjectCount, value.USNReadOperationID, value.ReObservationOperationID)
	if err != nil {
		return fmt.Errorf("insert FI USN read boundary: %w", err)
	}
	return nil
}

func projectUSNObjectObservation(ctx context.Context, tx pgx.Tx, sourceID string, sourceRecordID int64, scopeID string, value usnObjectObservationPayload) error {
	if err := validateUSNObjectObservationPayload(scopeID, value); err != nil {
		return err
	}

	boundaryRecordID, volumeID, err := findPrecedingUSNReadBoundary(ctx, tx, sourceID, scopeID, sourceRecordID)
	if err != nil {
		return err
	}
	objectID, err := ensureNTFSObject(ctx, tx, volumeID, value.FileIdentity)
	if err != nil {
		return err
	}

	_, err = tx.Exec(ctx, `
INSERT INTO fi.usn_object_observation (
 source_record_id,scope_basis,scope_detail,status,reason_code,error_text,has_ntfs_observation,has_content_hashes,
 usn_read_boundary_source_record_id,ntfs_object_id
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
`, sourceRecordID, value.ScopeBasis, nullString(value.ScopeDetail), value.Status, nullString(value.ReasonCode), nullString(value.Error),
		value.NTFS != nil, value.ContentHashes != nil, boundaryRecordID, objectID)
	if err != nil {
		return fmt.Errorf("insert FI USN object observation: %w", err)
	}

	for i, change := range value.Changes {
		fileObjectID, err := ensureNTFSObject(ctx, tx, volumeID, change.FileIdentity)
		if err != nil {
			return err
		}
		parentObjectID, err := ensureNTFSObject(ctx, tx, volumeID, change.ParentIdentity)
		if err != nil {
			return err
		}
		major, err := parseUint(change.MajorVersion, 15, "usn_object_change.major_version")
		if err != nil {
			return err
		}
		minor, err := parseUint(change.MinorVersion, 15, "usn_object_change.minor_version")
		if err != nil {
			return err
		}
		if _, err := parseDecimalCanonical(change.USN, "usn_object_change.usn"); err != nil {
			return err
		}
		timestamp, err := parseRFC3339(change.Timestamp, "usn_object_change.timestamp")
		if err != nil {
			return err
		}
		reasonRaw, err := parseUint(change.ReasonRaw, 32, "usn_object_change.reason_raw")
		if err != nil {
			return err
		}
		sourceInfo, err := parseUint(change.SourceInfoRaw, 32, "usn_object_change.source_info_raw")
		if err != nil {
			return err
		}
		securityID, err := parseUint(change.SecurityID, 32, "usn_object_change.security_id")
		if err != nil {
			return err
		}
		attributes, err := parseUint(change.FileAttributesRaw, 32, "usn_object_change.file_attributes_raw")
		if err != nil {
			return err
		}
		fileName, err := decodeBase64URL(change.FileNameUTF16LEBase64URL, true, "usn_object_change.file_name_utf16le")
		if err != nil {
			return err
		}
		ordinal := i + 1
		_, err = tx.Exec(ctx, `
INSERT INTO fi.usn_object_change (
 source_record_id,change_ordinal,major_version,minor_version,usn,event_timestamp,reason_raw,source_info_raw,security_id,file_attributes_raw,
 file_name_utf16le,file_ntfs_object_id,parent_ntfs_object_id
) VALUES ($1,$2,$3,$4,$5::text::numeric,$6,$7,$8,$9,$10,$11,$12,$13)
`, sourceRecordID, ordinal, int(major), int(minor), change.USN, timestamp, int64(reasonRaw), int64(sourceInfo), int64(securityID), int64(attributes),
			fileName, fileObjectID, parentObjectID)
		if err != nil {
			return fmt.Errorf("insert FI USN object change: %w", err)
		}
		for reasonIndex, reason := range change.ReasonNames {
			if _, err := tx.Exec(ctx, `INSERT INTO fi.usn_object_change_reason (source_record_id,change_ordinal,reason_ordinal,reason_name) VALUES ($1,$2,$3,$4)`, sourceRecordID, ordinal, reasonIndex+1, reason); err != nil {
				return fmt.Errorf("insert FI USN object change reason: %w", err)
			}
		}
	}

	if value.NTFS != nil {
		nested := *value.NTFS
		nested.ContentHashes = value.ContentHashes
		if nested.ObjectIdentity != value.FileIdentity {
			return errors.New("FI USN nested NTFS observation identity does not match USN object identity")
		}
		if nested.GovernedRoot.ScopeID != scopeID {
			return errors.New("FI USN nested NTFS governed-root scope does not match source envelope")
		}
		if err := ntfs.ValidateObservation(nested); err != nil {
			return fmt.Errorf("validate FI USN nested NTFS observation: %w", err)
		}
		nestedVolumeID, err := ensureNTFSVolume(ctx, tx, sourceID, nested.VolumeIdentity)
		if err != nil {
			return err
		}
		if nestedVolumeID != volumeID {
			return errors.New("FI USN nested NTFS observation volume does not match preceding read boundary")
		}
		if err := projectNTFSObservation(ctx, tx, sourceID, sourceRecordID, nested, value.ContentHashes); err != nil {
			return err
		}
	}
	return nil
}

func validateUSNObjectObservationPayload(scopeID string, value usnObjectObservationPayload) error {
	if scopeID == "" {
		return errors.New("FI USN object observation scope is required")
	}
	if err := records.ValidateNTFSObjectIdentity(value.FileIdentity); err != nil {
		return fmt.Errorf("validate FI USN object identity: %w", err)
	}
	switch value.ScopeBasis {
	case "CurrentObjectContained", "CurrentObjectContainedByHelper", "RecordedAncestorContained", "RecordedParentContained", "ScopeUnresolvedIncluded":
	default:
		return fmt.Errorf("unsupported FI USN scope basis %q", value.ScopeBasis)
	}
	switch value.Status {
	case "Observed":
		if value.NTFS == nil || value.ContentHashes == nil {
			return errors.New("FI observed USN object is missing NTFS/content-hash observation")
		}
		if value.ReasonCode != "" || value.Error != "" {
			return errors.New("FI observed USN object carries failure fields")
		}
	case "OutsideGovernedRoot", "Unavailable", "Error":
		if value.NTFS != nil || value.ContentHashes != nil {
			return errors.New("FI non-observed USN object carries NTFS/content-hash observation")
		}
		if value.ReasonCode == "" {
			return errors.New("FI non-observed USN object reason code is required")
		}
	default:
		return fmt.Errorf("unsupported FI USN re-observation status %q", value.Status)
	}
	if len(value.Changes) == 0 {
		return errors.New("FI USN object observation contains no source changes")
	}
	for i, change := range value.Changes {
		if err := records.ValidateUSNChangeObservation(change); err != nil {
			return fmt.Errorf("validate FI USN object change %d: %w", i+1, err)
		}
		if change.FileIdentity != value.FileIdentity {
			return fmt.Errorf("FI USN object change %d file identity does not match object observation", i+1)
		}
	}
	return nil
}

func findPrecedingUSNReadBoundary(ctx context.Context, tx pgx.Tx, sourceID string, scopeID string, sourceRecordID int64) (int64, int64, error) {
	var boundaryRecordID int64
	var volumeID int64
	err := tx.QueryRow(ctx, `
SELECT urb.source_record_id, urb.ntfs_volume_id
FROM fi.usn_read_boundary AS urb
JOIN fi.source_record AS sr ON sr.source_record_id = urb.source_record_id
JOIN fi.source_batch AS sb ON sb.source_batch_id = sr.source_batch_id
JOIN fi.recorded_generation AS rg ON rg.recorded_generation_id = sb.recorded_generation_id
WHERE rg.source_id = $1
  AND sr.scope_id = $2
  AND sr.source_record_id < $3
ORDER BY sr.source_record_id DESC
LIMIT 1
`, sourceID, scopeID, sourceRecordID).Scan(&boundaryRecordID, &volumeID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, 0, errors.New("FI USN object observation has no preceding durable USN read boundary")
		}
		return 0, 0, fmt.Errorf("resolve FI USN read boundary: %w", err)
	}
	return boundaryRecordID, volumeID, nil
}

func projectUSNContinuityGap(ctx context.Context, tx pgx.Tx, sourceRecordID int64, value records.USNContinuityGapObservation) error {
	observedAt, err := parseRFC3339(value.ObservedAt, "usn_continuity_gap.observed_at")
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `
INSERT INTO fi.usn_continuity_gap (
 source_record_id,observed_at,collection_method,scope_id,governed_root,reason_code,checkpoint_journal_id,checkpoint_next_usn,
 current_journal_id,current_first_usn,current_lowest_valid_usn,current_next_usn,coverage_state,reconciliation_action
) VALUES ($1,$2,$3,$4,$5,$6,$7::text::numeric,$8::text::numeric,$9::text::numeric,$10::text::numeric,$11::text::numeric,$12::text::numeric,$13,$14)
`, sourceRecordID, observedAt, value.CollectionMethod, value.ScopeID, value.GovernedRoot, value.ReasonCode, value.CheckpointJournalID,
		value.CheckpointNextUSN, value.CurrentJournalID, value.CurrentFirstUSN, value.CurrentLowestValidUSN, value.CurrentNextUSN,
		value.CoverageState, value.ReconciliationAction)
	if err != nil {
		return fmt.Errorf("insert FI USN continuity gap: %w", err)
	}
	return nil
}

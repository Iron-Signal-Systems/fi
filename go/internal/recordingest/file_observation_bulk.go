// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package recordingest

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
	"github.com/Iron-Signal-Systems/fi/go/internal/windows/ntfs"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

// Buffered rows never leave the generation transaction. Both standalone
// FileObservation and nested USN observations use the same FK-safe COPY path.
const (
	fileObservationBulkMaxRecords = 1024
	fileObservationBulkMaxBytes   = 8 << 20
)

type fileObservationBulkRecord struct {
	sourceID       string
	sourceRecordID int64
	ordinal        int64
	value          ntfs.Observation
	hashes         *records.ContentHashObservation
	bytes          int64
}

type fileObservationBulkPrepared struct {
	record   fileObservationBulkRecord
	parent   []any
	metadata []any
}

type fileObservationBulkState struct {
	records []fileObservationBulkRecord
	bytes   int64
}

type fileObservationBulkContextKey struct{}
type fileObservationBulkBytesContextKey struct{}

func newFileObservationBulkState() *fileObservationBulkState {
	return &fileObservationBulkState{}
}

// add may flush the prior bounded chunk. An oversized single record remains
// one atomic chunk; its immutable input was already admitted by source custody.
func (s *fileObservationBulkState) add(ctx context.Context, tx pgx.Tx, record fileObservationBulkRecord) error {
	if s == nil || tx == nil || record.sourceID == "" || record.sourceRecordID <= 0 || record.bytes <= 0 {
		return errors.New("FI file observation bulk input is incomplete")
	}
	if len(s.records) >= fileObservationBulkMaxRecords ||
		(len(s.records) > 0 && s.bytes+record.bytes > fileObservationBulkMaxBytes) {
		if err := s.flush(ctx, tx); err != nil {
			return err
		}
	}
	s.records = append(s.records, record)
	s.bytes += record.bytes
	return nil
}

func (s *fileObservationBulkState) flush(ctx context.Context, tx pgx.Tx) error {
	if s == nil || len(s.records) == 0 {
		return nil
	}
	if ctx == nil || tx == nil {
		return errors.New("FI file observation bulk flush input is incomplete")
	}
	if err := copyFileObservationBulk(ctx, tx, s.records); err != nil {
		return err
	}
	s.records = nil
	s.bytes = 0
	return nil
}

// This function is intentionally ordered: resolve identities first; COPY
// file_observation parents; COPY metadata children; project remaining children.
// Errors propagate to the existing generation transaction's rollback path.
func copyFileObservationBulk(ctx context.Context, tx pgx.Tx, pending []fileObservationBulkRecord) error {
	if len(pending) == 0 {
		return nil
	}
	if ctx == nil || tx == nil || len(pending) > fileObservationBulkMaxRecords {
		return errors.New("FI file observation COPY input is incomplete or exceeds bounds")
	}

	counters, _ := ctx.Value(ntfsStageTimingContextKey{}).(*ntfsStageTimingCounters)
	batchStarted := time.Now()
	prepared := make([]fileObservationBulkPrepared, 0, len(pending))
	for _, p := range pending {
		started := time.Now()
		parent, metadata, err := prepareFileObservationBulk(ctx, tx, p)
		if err != nil {
			return fmt.Errorf("FI file observation source record %d (ordinal %d): %w", p.sourceRecordID, p.ordinal, err)
		}
		prepared = append(prepared, fileObservationBulkPrepared{record: p, parent: parent, metadata: metadata})
		if counters != nil {
			counters.Identity += time.Since(started)
		}
	}

	if err := copyFileBulkRelationalRows(ctx, tx, prepared, counters); err != nil {
		return err
	}

	// Foreign keys now exist. The existing child projector functions retain
	// their validation, COPY state, and original per-child error behavior.
	var childTotal time.Duration
	for _, p := range prepared {
		childStarted := time.Now()
		if err := projectFileObservationBulkChildren(ctx, tx, p.record); err != nil {
			return fmt.Errorf("FI file observation child source record %d (ordinal %d): %w", p.record.sourceRecordID, p.record.ordinal, err)
		}
		childTotal += time.Since(childStarted)
	}
	if counters != nil {
		counters.Total += time.Since(batchStarted) - childTotal
	}
	return nil
}

// copyFileBulkRelationalRows enforces parent-before-child COPY ordering.
// Kept independent of identity resolution for isolated relational testing.
func copyFileBulkRelationalRows(ctx context.Context, tx pgx.Tx, prepared []fileObservationBulkPrepared, counters *ntfsStageTimingCounters) error {
	fileStarted := time.Now()
	fileColumns := []string{
		"source_record_id", "governed_root_id", "ntfs_object_id", "parent_state", "parent_ntfs_object_id", "parent_reason_code",
		"subject_kind", "requested_path_utf16le", "resolved_path_utf16le", "observed_at", "containment_method_version",
		"collection_entry_method", "collection_method", "observation_status",
	}
	copied, err := tx.CopyFrom(ctx, pgx.Identifier{"fi", "file_observation"}, fileColumns,
		pgx.CopyFromSlice(len(prepared), func(i int) ([]any, error) { return prepared[i].parent, nil }))
	if counters != nil {
		counters.File += time.Since(fileStarted)
	}
	if err != nil {
		return fmt.Errorf("FI file observation COPY: %w", err)
	}
	if copied != int64(len(prepared)) {
		return fmt.Errorf("FI file observation COPY count: got %d expected %d", copied, len(prepared))
	}

	metadataStarted := time.Now()
	metadataColumns := []string{
		"source_record_id", "logical_size", "allocated_size", "creation_time", "last_write_time", "change_time", "last_access_time", "raw_attributes", "link_count",
	}
	copied, err = tx.CopyFrom(ctx, pgx.Identifier{"fi", "file_metadata_observation"}, metadataColumns,
		pgx.CopyFromSlice(len(prepared), func(i int) ([]any, error) { return prepared[i].metadata, nil }))
	if counters != nil {
		counters.Metadata += time.Since(metadataStarted)
	}
	if err != nil {
		return fmt.Errorf("FI file metadata COPY: %w", err)
	}
	if copied != int64(len(prepared)) {
		return fmt.Errorf("FI file metadata COPY count: got %d expected %d", copied, len(prepared))
	}

	return nil
}

func prepareFileObservationBulk(ctx context.Context, tx pgx.Tx, p fileObservationBulkRecord) ([]any, []any, error) {
	if p.sourceID == "" || p.sourceRecordID <= 0 {
		return nil, nil, errors.New("FI file observation identity missing")
	}
	v := p.value
	if v.VolumeIdentity != v.GovernedRoot.VolumeIdentity {
		return nil, nil, errors.New("FI NTFS observation volume identity does not match governed-root volume")
	}
	if err := ntfs.ValidateObservation(v); err != nil {
		return nil, nil, fmt.Errorf("validate FI NTFS observation: %w", err)
	}

	volumeID, err := ensureNTFSVolume(ctx, tx, p.sourceID, v.VolumeIdentity)
	if err != nil {
		return nil, nil, err
	}
	objectID, err := ensureNTFSObject(ctx, tx, volumeID, v.ObjectIdentity)
	if err != nil {
		return nil, nil, err
	}
	governedRootID, err := ensureGovernedRoot(ctx, tx, p.sourceID, v.GovernedRoot)
	if err != nil {
		return nil, nil, err
	}
	var parentObjectID any
	if v.ParentBinding.ObjectIdentity != nil {
		parentObjectID, err = ensureNTFSObject(ctx, tx, volumeID, *v.ParentBinding.ObjectIdentity)
		if err != nil {
			return nil, nil, err
		}
	}
	requested, err := decodeBase64URL(v.PathBinding.RequestedPathUTF16LEBase64URL, true, "path_binding.requested_path")
	if err != nil {
		return nil, nil, err
	}
	resolved, err := decodeBase64URL(v.PathBinding.ResolvedPathUTF16LEBase64URL, true, "path_binding.resolved_path")
	if err != nil {
		return nil, nil, err
	}
	observedAt, err := parseRFC3339(v.ObservedAt, "ntfs.observed_at")
	if err != nil {
		return nil, nil, err
	}
	parent := []any{p.sourceRecordID, governedRootID, objectID, string(v.ParentBinding.State), parentObjectID,
		nullString(v.ParentBinding.ReasonCode), string(v.SubjectKind), requested, resolved, observedAt, v.Containment.MethodVersion,
		string(v.CollectionEntryMethod), string(v.CollectionMethod), string(v.ObservationStatus)}

	creation, err := parseRFC3339(v.Metadata.CreationTime, "metadata.creation_time")
	if err != nil {
		return nil, nil, err
	}
	lastWrite, err := parseRFC3339(v.Metadata.LastWriteTime, "metadata.last_write_time")
	if err != nil {
		return nil, nil, err
	}
	change, err := parseRFC3339(v.Metadata.ChangeTime, "metadata.change_time")
	if err != nil {
		return nil, nil, err
	}
	lastAccess, err := parseRFC3339(v.Metadata.LastAccessTime, "metadata.last_access_time")
	if err != nil {
		return nil, nil, err
	}
	attributes, err := parseUint(v.Metadata.RawAttributes, 32, "metadata.raw_attributes")
	if err != nil {
		return nil, nil, err
	}
	links, err := parseUint(v.Metadata.LinkCount, 32, "metadata.link_count")
	if err != nil {
		return nil, nil, err
	}
	logical, err := fileBulkNumeric(v.Metadata.LogicalSize)
	if err != nil {
		return nil, nil, fmt.Errorf("metadata.logical_size: %w", err)
	}
	allocated, err := fileBulkNumeric(v.Metadata.AllocatedSize)
	if err != nil {
		return nil, nil, fmt.Errorf("metadata.allocated_size: %w", err)
	}
	metadata := []any{p.sourceRecordID, logical, allocated, creation, lastWrite, change, lastAccess, int64(attributes), int64(links)}
	return parent, metadata, nil
}

func fileBulkNumeric(value string) (pgtype.Numeric, error) {
	number, ok := new(big.Int).SetString(value, 10)
	if !ok || number.Sign() < 0 {
		return pgtype.Numeric{}, errors.New("expected nonnegative decimal")
	}
	return pgtype.Numeric{Int: number, Exp: 0, Valid: true}, nil
}

func projectFileObservationBulkChildren(ctx context.Context, tx pgx.Tx, p fileObservationBulkRecord) error {
	sourceRecordID := p.sourceRecordID
	v := p.value
	stages := beginNTFSStage(ctx)
	defer stages.finish()
	// The normal projector always includes these child calls. Preserve their
	// order and error handling after the parent and metadata COPY operations.
	if p.hashes != nil {
		if err := projectContentHashes(ctx, tx, sourceRecordID, *p.hashes); err != nil {
			return err
		}
	}
	stages.mark("hashes")
	if v.ContentPrefix != nil {
		if err := projectContentPrefix(ctx, tx, sourceRecordID, *v.ContentPrefix); err != nil {
			return err
		}
	}
	stages.mark("prefix")
	if err := projectReparseObservation(ctx, tx, sourceRecordID, v.Reparse); err != nil {
		return err
	}
	stages.mark("reparse")
	if err := projectStreamInventory(ctx, tx, sourceRecordID, v.StreamInventory); err != nil {
		return err
	}
	stages.mark("streams")
	if err := projectSecurityObservation(ctx, tx, sourceRecordID, v.Security); err != nil {
		return err
	}
	stages.mark("security")
	if err := projectSACLObservation(ctx, tx, sourceRecordID, v.SACL); err != nil {
		return err
	}
	stages.mark("sacl")
	for i, warning := range v.Warnings {
		if _, err := tx.Exec(ctx, `INSERT INTO fi.observation_warning (source_record_id,warning_ordinal,code,detail) VALUES ($1,$2,$3,$4)`, sourceRecordID, i+1, warning.Code, nullString(warning.Detail)); err != nil {
			return fmt.Errorf("insert FI observation warning: %w", err)
		}
	}
	stages.mark("warnings")
	return nil
}

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package recordingest

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

const (
	fileSourceBulkMaxRecords = 1024
	fileSourceBulkMaxBytes   = 8 << 20
)

// fileSourceBulkRecord holds only authoritative, already-validated source
// envelope fields. The normal projector processes each record after COPY.
type fileSourceBulkRecord struct {
	sourceBatchID  int64 // original signed batch, not a processing-chunk identifier
	ordinal        int64
	prepared       SourceRecord
	digest         []byte
	sourceRecordID int64
}

// copyFileSourceBulk preserves source record ordinals and maps database-generated
// IDs without assuming sequence contiguity. No projection happens here.
func copyFileSourceBulk(ctx context.Context, tx pgx.Tx, sourceBatchID int64, pending []fileSourceBulkRecord, profile *ingestStageProfile) error {
	if len(pending) == 0 {
		return nil
	}
	if ctx == nil || tx == nil || profile == nil || sourceBatchID <= 0 {
		return errors.New("FI FileObservation source COPY inputs are incomplete")
	}
	if len(pending) > fileBulkLimitsFromContext(ctx).SourceMaxRecords {
		return errors.New("FI FileObservation source COPY exceeds record limit")
	}
	for i, item := range pending {
		batchID := bulkSourceBatchID(item.sourceBatchID, sourceBatchID)
		previousBatch := sourceBatchID
		if i > 0 {
			previousBatch = bulkSourceBatchID(pending[i-1].sourceBatchID, sourceBatchID)
		}
		if batchID <= 0 || item.ordinal <= 0 || (item.prepared.Record.RecordKind != "FileObservation" && item.prepared.Record.RecordKind != "USNObjectObservation") ||
			item.prepared.RecordBytes <= 0 || len(item.digest) != 32 ||
			(i > 0 && batchID == previousBatch && item.ordinal != pending[i-1].ordinal+1) {
			return fmt.Errorf("FI FileObservation source COPY invalid record at index %d", i)
		}
	}

	started := time.Now()
	defer func() { profile.SourceSQL += time.Since(started) }()

	columns := []string{
		"source_batch_id", "record_ordinal", "version", "record_kind", "scope_id",
		"written_at", "record_bytes", "record_sha256", "ingest_version",
	}
	// Preserve production COPY values; reuse rows only in private W128/P3.
	sourceRows := fileSourceRecordCopyRows(ctx, pending, sourceBatchID)
	copied, err := tx.CopyFrom(ctx, pgx.Identifier{"fi", "source_record"}, columns, sourceRows)
	if err != nil {
		return fmt.Errorf("FI FileObservation source COPY: %w", err)
	}
	if copied != int64(len(pending)) {
		return fmt.Errorf("FI FileObservation source COPY count: got %d expected %d", copied, len(pending))
	}

	batchIDs := make([]int64, len(pending))
	ordinals := make([]int64, len(pending))
	for i, p := range pending {
		batchIDs[i] = bulkSourceBatchID(p.sourceBatchID, sourceBatchID)
		ordinals[i] = p.ordinal
	}
	ids, err := lookupBulkSourceRecordIDs(ctx, tx, batchIDs, ordinals)
	if err != nil {
		return fmt.Errorf("FI FileObservation source ID lookup: %w", err)
	}
	for i, id := range ids {
		pending[i].sourceRecordID = id
	}
	return nil
}

// fileSourceRecordCopyRows isolates the reusable-row selection from the transaction
// and preserves the original callback for production P1 and ordinary P3.
func fileSourceRecordCopyRows(ctx context.Context, pending []fileSourceBulkRecord, sourceBatchID int64) pgx.CopyFromSource {
	var sourceRows pgx.CopyFromSource
	if usePrivateSinglePassSecurity(ctx) {
		sourceRows = newFileSourceRecordCopySource(pending, sourceBatchID)
	} else {
		sourceRows = pgx.CopyFromSlice(len(pending), func(i int) ([]any, error) {
			p := pending[i]
			return []any{bulkSourceBatchID(p.sourceBatchID, sourceBatchID), p.ordinal, p.prepared.Record.Version,
				p.prepared.Record.RecordKind, p.prepared.Record.ScopeID,
				p.prepared.WrittenAtUTC, p.prepared.RecordBytes, p.digest, IngestVersion}, nil
		})
	}
	return sourceRows
}

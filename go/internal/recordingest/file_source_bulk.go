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
	if len(pending) > fileSourceBulkMaxRecords {
		return errors.New("FI FileObservation source COPY exceeds record limit")
	}
	for i, item := range pending {
		if item.ordinal <= 0 || (item.prepared.Record.RecordKind != "FileObservation" && item.prepared.Record.RecordKind != "USNObjectObservation") ||
			item.prepared.RecordBytes <= 0 || len(item.digest) != 32 ||
			(i > 0 && item.ordinal != pending[i-1].ordinal+1) {
			return fmt.Errorf("FI FileObservation source COPY invalid record at index %d", i)
		}
	}

	started := time.Now()
	defer func() { profile.SourceSQL += time.Since(started) }()

	columns := []string{
		"source_batch_id", "record_ordinal", "version", "record_kind", "scope_id",
		"written_at", "record_bytes", "record_sha256", "ingest_version",
	}
	copied, err := tx.CopyFrom(ctx, pgx.Identifier{"fi", "source_record"}, columns,
		pgx.CopyFromSlice(len(pending), func(i int) ([]any, error) {
			p := pending[i]
			return []any{sourceBatchID, p.ordinal, p.prepared.Record.Version,
				p.prepared.Record.RecordKind, p.prepared.Record.ScopeID,
				p.prepared.WrittenAtUTC, p.prepared.RecordBytes, p.digest, IngestVersion}, nil
		}))
	if err != nil {
		return fmt.Errorf("FI FileObservation source COPY: %w", err)
	}
	if copied != int64(len(pending)) {
		return fmt.Errorf("FI FileObservation source COPY count: got %d expected %d", copied, len(pending))
	}

	rows, err := tx.Query(ctx, `
SELECT record_ordinal, source_record_id
FROM fi.source_record
WHERE source_batch_id=$1 AND record_ordinal BETWEEN $2 AND $3
ORDER BY record_ordinal`, sourceBatchID, pending[0].ordinal, pending[len(pending)-1].ordinal)
	if err != nil {
		return fmt.Errorf("FI FileObservation source ID lookup: %w", err)
	}
	index := 0
	for rows.Next() {
		var ordinal, sourceRecordID int64
		if err := rows.Scan(&ordinal, &sourceRecordID); err != nil {
			rows.Close()
			return fmt.Errorf("FI FileObservation source ID scan: %w", err)
		}
		if index >= len(pending) || ordinal != pending[index].ordinal || sourceRecordID <= 0 {
			rows.Close()
			return fmt.Errorf("FI FileObservation source ID mismatch at index %d", index)
		}
		pending[index].sourceRecordID = sourceRecordID
		index++
	}
	queryErr := rows.Err()
	rows.Close()
	if queryErr != nil {
		return fmt.Errorf("FI FileObservation source ID read: %w", queryErr)
	}
	if index != len(pending) {
		return fmt.Errorf("FI FileObservation source IDs: got %d expected %d", index, len(pending))
	}
	return nil
}

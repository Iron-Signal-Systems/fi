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
    "github.com/jackc/pgx/v5/pgtype"
)

// This is private benchmarking state, scoped to ONE SQL transaction. It does
// not divide the original signed batches, reset cross-window identities,
// publish journal outcomes, or establish intermediate durability checkpoints.
type backlogTypedChunkContextKey struct{}
type backlogTypedChunkDirective struct {
    state *backlogTypedChunkState
    finish bool
}
type backlogTypedChunkState struct {
    security []securityBulkRecord
    securityBytes int64
    files []fileSourceBulkRecord
    fileBytes int64
    fileBulk *fileObservationBulkState
}
func (s *backlogTypedChunkState) filesBytes() int64 {
    if s == nil { return -1 }
    return s.securityBytes+s.fileBytes+s.fileBulk.bytes
}
type backlogTypedChunkSample struct {
    firstBatch, endBatch, records int
    duration time.Duration
}

func bulkSourceBatchID(explicit, legacy int64) int64 {
    if explicit != 0 { return explicit }
    return legacy
}

func shouldFinishBacklogTypedChunk(rows, next, limit int) (bool,error) {
    if limit <= 0 || rows <= 0 || rows > limit || next < 0 || next > limit {
        return false, errors.New("FI typed chunk: impossible signed batch boundary")
    }
    return next == 0 || next > limit-rows,nil
}

// Source parent identities must be mapped by the original signed pair.
// No assumption that SQL sequence IDs are contiguous or preserve COPY order.
// Retain the original, fast single-batch lookup for production and legacy
// projection; use an ordinal-preserving keyed lookup only across batches.
func lookupBulkSourceRecordIDs(ctx context.Context, tx pgx.Tx, batchIDs, ordinals []int64) ([]int64, error) {
    if ctx == nil || tx == nil || len(batchIDs) == 0 || len(batchIDs) != len(ordinals) {
        return nil, errors.New("FI bulk source: invalid key lookup")
    }
    for i := range batchIDs {
        if batchIDs[i] <= 0 || ordinals[i] <= 0 {
            return nil, fmt.Errorf("FI bulk source: invalid key at %d", i)
        }
    }
    single := true
    for _, batchID := range batchIDs[1:] {
        if batchID != batchIDs[0] { single = false; break }
    }
    ids := make([]int64, len(batchIDs))
    if single {
        rows, err := tx.Query(ctx, `SELECT record_ordinal, source_record_id FROM fi.source_record
WHERE source_batch_id=$1 AND record_ordinal BETWEEN $2 AND $3 ORDER BY record_ordinal`,
            batchIDs[0], ordinals[0], ordinals[len(ordinals)-1])
        if err != nil { return nil, err }
        i := 0
        for rows.Next() {
            var ordinal, id int64
            if err := rows.Scan(&ordinal, &id); err != nil { rows.Close(); return nil, err }
            if i >= len(ids) || ordinal != ordinals[i] || id <= 0 {
                rows.Close(); return nil, errors.New("FI bulk source: single-batch identity mismatch")
            }
            ids[i] = id
            i++
        }
        err = rows.Err()
        rows.Close()
        if err != nil { return nil, err }
        if i != len(ids) { return nil, errors.New("FI bulk source: missing single-batch identities") }
        return ids, nil
    }
    rows, err := tx.Query(ctx, `WITH wanted AS (
  SELECT batch_id, ordinal, seq
  FROM unnest($1::bigint[], $2::bigint[]) WITH ORDINALITY AS w(batch_id, ordinal, seq)
)
SELECT w.seq, sr.source_record_id
FROM wanted w LEFT JOIN fi.source_record sr
  ON sr.source_batch_id=w.batch_id AND sr.record_ordinal=w.ordinal
ORDER BY w.seq`, batchIDs, ordinals)
    if err != nil { return nil, err }
    i := 0
    for rows.Next() {
        var seq int64
        var id pgtype.Int8
        if err := rows.Scan(&seq, &id); err != nil { rows.Close(); return nil, err }
        if seq != int64(i+1) || i >= len(ids) || !id.Valid || id.Int64 <= 0 {
            rows.Close(); return nil, errors.New("FI bulk source: cross-batch identity mismatch")
        }
        ids[i] = id.Int64
        i++
    }
    err = rows.Err()
    rows.Close()
    if err != nil { return nil, err }
    if i != len(ids) { return nil, errors.New("FI bulk source: incomplete cross-batch IDs") }
    return ids, nil
}

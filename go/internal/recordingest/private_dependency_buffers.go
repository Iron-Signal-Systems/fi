// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// Development-only W128/K32 dependency buffer. No authoritative ingest path
// or accepted H16 replay enables this context.
package recordingest

import (
    "context"
    "errors"
    "fmt"
    "time"

    "github.com/jackc/pgx/v5"
)

type privateDependencyBuffersKey struct{}

const (
    privateDependencyMaxRecords = 512
    privateDependencyMaxBytes int64 = 8 << 20
)

// Enable only after the already-gated private mixed-family context is selected
// by the disposable W128/K32/P3/F3 runner. Actual use additionally requires
// an active bounded typed chunk, checked by privateDependencyBuffersEnabled.
func WithPrivateDependencyBuffers(ctx context.Context) (context.Context, error) {
    if ctx == nil || ctx.Value(privateMixedFamilyBuffersKey{}) != true ||
        !usePrivateSinglePassSecurity(ctx) ||
        joinedBacklogChunkRecords(ctx) != 32768 ||
        fileBulkLimitsFromContext(ctx).Name != "F3" {
        return nil, errors.New("FI private dependency buffers require W128/K32/P3/F3 mixed-family private context")
    }
    return context.WithValue(ctx, privateDependencyBuffersKey{}, true), nil
}

func privateDependencyBuffersEnabled(ctx context.Context) bool {
    return ctx != nil && ctx.Value(privateDependencyBuffersKey{}) == true &&
        privateMixedFamilyBuffersEnabled(ctx)
}

func privateUSNDependentKind(kind string) bool {
    return kind == "USNReadBoundary" || kind == "USNObjectObservation"
}

// An original source identity, not a generated SQL sequence number, owns the
// queue position. For a single signed batch, ordinal must increase; across
// signed batches, the source loader itself supplies immutable batch ordering.
// Parent USN read boundaries always execute before following USN objects.
type privateDependencySourceRecord struct {
    sourceBatchID int64
    ordinal int64
    prepared SourceRecord
}

func privateDependencyShouldFlushBefore(rows int, bytes, incoming int64) bool {
    return rows >= privateDependencyMaxRecords ||
        (rows > 0 && incoming > privateDependencyMaxBytes-bytes)
}

func privateDependencyAppend(rows []privateDependencySourceRecord, bytes int64, sourceBatchID, ordinal int64,
    prepared SourceRecord) ([]privateDependencySourceRecord, int64, error) {
    if sourceBatchID <= 0 || ordinal <= 0 || prepared.RecordBytes <= 0 ||
        !privateUSNDependentKind(prepared.Record.RecordKind) ||
        len(rows) >= privateDependencyMaxRecords ||
        (len(rows) > 0 && int64(prepared.RecordBytes) > privateDependencyMaxBytes-bytes) {
        return nil, bytes, errors.New("FI private dependency queue: invalid kind, identity or bounded capacity")
    }
    if n := len(rows); n > 0 {
        prev := rows[n-1]
        if sourceBatchID < prev.sourceBatchID ||
            (sourceBatchID == prev.sourceBatchID && ordinal <= prev.ordinal) {
            return nil, bytes, errors.New("FI private dependency queue: source custody order reversed")
        }
    }
    rows = append(rows, privateDependencySourceRecord{
        sourceBatchID: sourceBatchID, ordinal: ordinal, prepared: prepared,
    })
    return rows, bytes+int64(prepared.RecordBytes), nil
}

// Each queued dependency already passed the normal signed-envelope decoder
// and recorded the original SHA-256 evidence. The existing, full USN projector
// still validates boundary identity, capture counts, nested NTFS and children.
// This function intentionally does NOT mark dependencies resolved merely
// because a later boundary exists: they execute in original collection order.
// Unmet or forward references fail closed under the W128 SQL transaction.
func flushPrivateDependencies(ctx context.Context, tx pgx.Tx, sourceID string,
    rows []privateDependencySourceRecord, profile *ingestStageProfile) error {
    if len(rows) == 0 {
        return nil
    }
    if !privateDependencyBuffersEnabled(ctx) || tx == nil || profile == nil ||
        sourceID == "" || len(rows) > privateDependencyMaxRecords {
        return errors.New("FI private dependency flush: invalid active private context")
    }
    for i := range rows {
        p := &rows[i]
        if p.sourceBatchID <= 0 || p.ordinal <= 0 || p.prepared.RecordBytes <= 0 ||
            !privateUSNDependentKind(p.prepared.Record.RecordKind) {
            return errors.New("FI private dependency flush: invalid source identity")
        }
        start := time.Now()
        var sourceRecordID int64
        err := tx.QueryRow(ctx, `
INSERT INTO fi.source_record (
 source_batch_id,record_ordinal,version,record_kind,scope_id,written_at,record_bytes,record_sha256,ingest_version
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
RETURNING source_record_id
`, p.sourceBatchID, p.ordinal, p.prepared.Record.Version, p.prepared.Record.RecordKind,
            p.prepared.Record.ScopeID, p.prepared.WrittenAtUTC,
            p.prepared.RecordBytes, p.prepared.RecordDigest[:], IngestVersion).Scan(&sourceRecordID)
        profile.SourceSQL += time.Since(start)
        if err != nil {
            return fmt.Errorf("FI private dependency source batch=%d ordinal=%d: %w",
                p.sourceBatchID, p.ordinal, err)
        }
        startedProjection := time.Now()
        projectCtx := ctx
        if p.prepared.Record.RecordKind == "USNObjectObservation" {
            projectCtx = context.WithValue(ctx, fileObservationBulkBytesContextKey{}, p.prepared.RecordBytes)
        }
        err = ProjectSourceRecord(projectCtx, tx, sourceID, sourceRecordID, p.prepared)
        elapsed := time.Since(startedProjection)
        profile.Projection += elapsed
        profile.OtherProjection += elapsed
        if err != nil {
            return fmt.Errorf("FI private dependency projection batch=%d ordinal=%d kind=%s: %w",
                p.sourceBatchID, p.ordinal, p.prepared.Record.RecordKind, err)
        }
    }
    return nil
}

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package recordingest

import (
    "context"
    "crypto/subtle"
    "encoding/hex"
    "errors"
    "fmt"
    "math"

    "github.com/jackc/pgx/v5"
)

// BacklogGenerationVerification is a read-only report about a fully staged
// private generation. It is NOT an Accepted ingest result or a publication token.
type BacklogGenerationVerification struct {
    SourceID         string
    GenerationID     string
    ReceiptSHA256    string
    ShadowGenerationID int64
    Windows          int
    Records          uint64
    DataBytes        uint64
}

// VerifyCompleteBacklogTypedGeneration verifies that every window from the
// original signed receipt has a matching artifact, source, and typed marker,
// and that those markers still agree with persisted source and typed rows.
// An incomplete or mismatched generation cannot pass.
//
// This only inspects the PRIVATE recovery schema in one read-only repeatable-
// read transaction; it never inserts an Accepted journal event, publishes
// projections or changes any authoritative fi.* row.
func VerifyCompleteBacklogTypedGeneration(
    ctx context.Context, conn *pgx.Conn, g *PreparedGeneration,
    limits BacklogWindowLimits,
) (BacklogGenerationVerification, error) {
    var empty BacklogGenerationVerification
    if ctx == nil || conn == nil {
        return empty, errors.New("FI backlog complete: context and connection required")
    }
    if err := ctx.Err(); err != nil { return empty, err }
    descriptors, err := DescribeBacklogWindows(g, limits)
    if err != nil { return empty, err }
    if len(descriptors) == 0 || g.Receipt.RecordCount > math.MaxInt64 ||
        g.Receipt.DataBytes > math.MaxInt64 {
        return empty, errors.New("FI backlog complete: invalid receipt SQL bounds")
    }
    d0 := descriptors[0]
    receipt, err := hex.DecodeString(d0.ReceiptSHA256)
    if err != nil { return empty, err }

    var role, db string
    if err := conn.QueryRow(ctx, "SELECT current_user,current_database()").Scan(&role, &db); err != nil {
        return empty, err
    }
    if role != "fi_ingest" || db != "fi" {
        return empty, errors.New("FI backlog complete: unexpected SQL identity")
    }
    tx, err := conn.BeginTx(ctx, pgx.TxOptions{
        IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly,
    })
    if err != nil { return empty, err }
    defer tx.Rollback(context.Background())

    var authoritative bool
    err = tx.QueryRow(ctx, `
SELECT EXISTS (SELECT 1 FROM fi.recorded_generation
WHERE source_id=$1 AND generation_id=$2)
`,d0.SourceID,d0.GenerationID).Scan(&authoritative)
    if err != nil { return empty, err }
    if authoritative {
        return empty, errors.New("FI backlog complete: generation already authoritative")
    }

    shadow := privateProjectionTx{Tx:tx}
    shadowID, found, err := lookupRecordedGeneration(ctx, shadow,
        d0.SourceID, d0.GenerationID, g.Receipt.TransferSHA256, g.ReceiptSHA256)
    if err != nil { return empty, err }
    if !found || shadowID <= 0 {
        return empty, errors.New("FI backlog complete: private generation missing")
    }

    var artifacts, sources, typed int64
    err = tx.QueryRow(ctx, `
SELECT
  (SELECT count(*) FROM fi_recovery.verified_artifact_window WHERE receipt_sha256=$1),
  (SELECT count(*) FROM fi_recovery.source_window WHERE receipt_sha256=$1),
  (SELECT count(*) FROM fi_recovery.typed_window WHERE receipt_sha256=$1)
`,receipt).Scan(&artifacts,&sources,&typed)
    if err != nil { return empty, err }
    if artifacts!=int64(len(descriptors)) || sources!=int64(len(descriptors)) ||
        typed!=int64(len(descriptors)) {
        return empty, fmt.Errorf("FI backlog complete: window markers incomplete artifact=%d source=%d typed=%d expected=%d",
            artifacts,sources,typed,len(descriptors))
    }

    var totalRecords,totalBytes uint64
    for i,d := range descriptors {
        if err := ctx.Err(); err != nil { return empty, err }
        if d.EndRecord>math.MaxInt64 || d.DataBytes>math.MaxInt64 {
            return empty, errors.New("FI backlog complete: window outside SQL bounds")
        }
        descHash, err := hex.DecodeString(d.DigestSHA256)
        if err != nil { return empty, err }
        prevHash, err := hex.DecodeString(d.PreviousDigestSHA256)
        if err != nil { return empty, err }
        transferHash, err := hex.DecodeString(d.TransferSHA256)
        if err != nil { return empty, err }

        var sourceID,generationID,version string
        var artifactTransfer,artifactDigest,artifactPrevious []byte
        var artifactStartBatch,artifactEndBatch,artifactStartRecord,artifactEndRecord,artifactBytes int64
        var sourceDigest,sourcePrevious,sourceRowsDigest []byte
        var sourceStartBatch,sourceEndBatch int
        var sourceStartRecord,sourceEndRecord,sourceRecords,sourceBytes int64
        var typedDigest []byte
        var typedShadowID,typedRecords,typedBytes int64
        var typedStartBatch,typedEndBatch int
        err = tx.QueryRow(ctx, `
SELECT a.source_id,a.generation_id,a.transfer_sha256,a.descriptor_sha256,
       a.previous_digest_sha256,a.start_batch,a.end_batch,a.start_record,a.end_record,a.data_bytes,
       s.descriptor_sha256,s.previous_digest_sha256,s.start_batch,s.end_batch,
       s.start_record,s.end_record,s.staged_records,s.staged_bytes,s.rows_digest_sha256,
       t.descriptor_sha256,t.shadow_generation_id,t.start_batch,t.end_batch,
       t.committed_records,t.committed_bytes,t.ingest_version
FROM fi_recovery.verified_artifact_window a
JOIN fi_recovery.source_window s USING(receipt_sha256,window_index)
JOIN fi_recovery.typed_window t USING(receipt_sha256,window_index)
WHERE a.receipt_sha256=$1 AND a.window_index=$2
`,receipt,i).Scan(
            &sourceID,&generationID,&artifactTransfer,&artifactDigest,&artifactPrevious,
            &artifactStartBatch,&artifactEndBatch,&artifactStartRecord,&artifactEndRecord,&artifactBytes,
            &sourceDigest,&sourcePrevious,&sourceStartBatch,&sourceEndBatch,
            &sourceStartRecord,&sourceEndRecord,&sourceRecords,&sourceBytes,&sourceRowsDigest,
            &typedDigest,&typedShadowID,&typedStartBatch,&typedEndBatch,
            &typedRecords,&typedBytes,&version)
        if err != nil { return empty,fmt.Errorf("FI backlog complete: window %d markers: %w",i,err) }
        wantRecords:=int64(d.EndRecord-d.StartRecord)
        if sourceID!=d.SourceID || generationID!=d.GenerationID ||
            subtle.ConstantTimeCompare(artifactTransfer,transferHash)!=1 ||
            subtle.ConstantTimeCompare(artifactDigest,descHash)!=1 ||
            subtle.ConstantTimeCompare(artifactPrevious,prevHash)!=1 ||
            artifactStartBatch!=int64(d.StartBatch) || artifactEndBatch!=int64(d.EndBatch) ||
            artifactStartRecord!=int64(d.StartRecord) || artifactEndRecord!=int64(d.EndRecord) ||
            artifactBytes!=int64(d.DataBytes) ||
            subtle.ConstantTimeCompare(sourceDigest,descHash)!=1 ||
            subtle.ConstantTimeCompare(sourcePrevious,prevHash)!=1 ||
            sourceStartBatch!=d.StartBatch || sourceEndBatch!=d.EndBatch ||
            sourceStartRecord!=int64(d.StartRecord) || sourceEndRecord!=int64(d.EndRecord) ||
            sourceRecords!=wantRecords || sourceBytes!=int64(d.DataBytes) ||
            subtle.ConstantTimeCompare(typedDigest,descHash)!=1 ||
            typedShadowID!=shadowID || typedStartBatch!=d.StartBatch ||
            typedEndBatch!=d.EndBatch || typedRecords!=wantRecords ||
            typedBytes!=int64(d.DataBytes) || version!=IngestVersion {
            return empty,fmt.Errorf("FI backlog complete: window %d identity/count mismatch",i)
        }

        dbHash,dbRecords,dbBytes,err:=hashBacklogDatabaseSourceRows(ctx,tx,receipt,i)
        if err!=nil{return empty,fmt.Errorf("FI backlog complete: window %d source digest: %w",i,err)}
        if dbRecords!=uint64(sourceRecords) || dbBytes!=uint64(sourceBytes) ||
            subtle.ConstantTimeCompare(dbHash,sourceRowsDigest)!=1 {
            return empty,fmt.Errorf("FI backlog complete: window %d source rows changed",i)
        }
        batches:=g.Batches[d.StartBatch:d.EndBatch]
        if err:=verifyBacklogShadowWindowCounts(ctx,shadow,shadowID,batches,wantRecords,int64(d.DataBytes));err!=nil{
            return empty,fmt.Errorf("FI backlog complete: window %d typed source counts: %w",i,err)
        }
        if err:=verifyBacklogSourceProjectionIdentity(ctx,tx,receipt,shadowID,i,d.StartBatch,batches,wantRecords);err!=nil {
            return empty,fmt.Errorf("FI backlog complete: window %d source/typed identity: %w",i,err)
        }
        totalRecords+=uint64(sourceRecords)
        totalBytes+=uint64(sourceBytes)
    }
    if totalRecords!=g.Receipt.RecordCount || totalBytes!=g.Receipt.DataBytes {
        return empty,errors.New("FI backlog complete: summed private records disagree with signed receipt")
    }
    var shadowBatches,shadowRecords int64
    err = tx.QueryRow(ctx, `
SELECT
 (SELECT count(*) FROM fi_recovery_projection.source_batch WHERE recorded_generation_id=$1),
 (SELECT count(*) FROM fi_recovery_projection.source_record AS sr
  JOIN fi_recovery_projection.source_batch AS sb ON sb.source_batch_id=sr.source_batch_id
  WHERE sb.recorded_generation_id=$1)
`,shadowID).Scan(&shadowBatches,&shadowRecords)
    if err!=nil{return empty,err}
    if shadowBatches!=int64(len(g.Batches)) || shadowRecords!=int64(totalRecords) {
        return empty,errors.New("FI backlog complete: unexpected private generation source rows/batches")
    }
    if err:=verifyGenerationProjectionCoverage(ctx,shadow,shadowID);err!=nil{return empty,err}
    if err:=verifyBacklogUSNCapturesComplete(ctx,shadow,shadowID);err!=nil{return empty,err}
    if err:=tx.Commit(ctx);err!=nil{return empty,err}
    return BacklogGenerationVerification{
        SourceID:d0.SourceID,GenerationID:d0.GenerationID,ReceiptSHA256:d0.ReceiptSHA256,
        ShadowGenerationID:shadowID,Windows:len(descriptors),
        Records:totalRecords,DataBytes:totalBytes,
    },nil
}

// A complete count alone cannot prove source identity. Every committed
// private pending envelope must match the actual projected source row, including
// ordinal, kind, scope, timestamp, size, and record SHA. The batch-index mapping
// comes only from the original signed generation's ordered manifests.
func verifyBacklogSourceProjectionIdentity(ctx context.Context,tx pgx.Tx,
    receipt []byte,shadowID int64,windowIndex,startBatch int,
    batches []PreparedBatch,wantRecords int64)error{
    ids:=make([]string,len(batches))
    for i,b:=range batches { ids[i]=b.BatchID }
    var got,bad int64
    err:=tx.QueryRow(ctx, `
WITH mapped_batches AS (
 SELECT b.batch_id, ($3::integer+b.ordinality::integer-1) AS batch_index
 FROM unnest($4::text[]) WITH ORDINALITY AS b(batch_id,ordinality)
)
SELECT count(*), count(*) FILTER(WHERE
 sr.source_record_id IS NULL OR
 sr.version IS DISTINCT FROM p.version OR
 sr.record_kind IS DISTINCT FROM p.record_kind OR
 sr.scope_id IS DISTINCT FROM p.scope_id OR
 sr.written_at IS DISTINCT FROM p.written_at OR
 sr.record_bytes IS DISTINCT FROM p.record_bytes OR
 sr.record_sha256 IS DISTINCT FROM p.record_sha256)
FROM fi_recovery.pending_source_record AS p
JOIN mapped_batches AS bm ON bm.batch_index=p.batch_index
JOIN fi_recovery_projection.source_batch AS sb
 ON sb.recorded_generation_id=$2 AND sb.batch_id=bm.batch_id
LEFT JOIN fi_recovery_projection.source_record AS sr
 ON sr.source_batch_id=sb.source_batch_id AND sr.record_ordinal=p.record_ordinal
WHERE p.receipt_sha256=$1 AND p.window_index=$5
`,receipt,shadowID,startBatch,ids,windowIndex).Scan(&got,&bad)
    if err!=nil{return err}
    if got!=wantRecords || bad!=0 {
        return fmt.Errorf("FI backlog complete: source/typed mismatches %d of %d expected %d",bad,got,wantRecords)
    }
    return nil
}

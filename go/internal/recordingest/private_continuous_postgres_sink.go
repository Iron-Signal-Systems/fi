// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// Development-only PostgreSQL family writer for already staged signed source.
// This is not wired to the accepted H16 worker or the authoritative SoR.
// The caller stages each verified source window BEFORE routing its records.
package recordingest

import (
    "context"
    "crypto/subtle"
    "encoding/binary"
    "encoding/hex"
    "errors"
    "fmt"

    "github.com/Iron-Signal-Systems/fi/go/internal/windows/ntfs"
    "github.com/jackc/pgx/v5"
)

type privateContinuousFamilyWriterKey struct{}

type privateContinuousPostgresSink struct {
    writer *pgx.Conn
    generation *PreparedGeneration
    windows []BacklogCheckpointDescriptor
    batchIDs []int64
    shadowGenerationID int64
    receipt []byte
}

// The shadow generation and original signed batch IDs are independent of
// projected source rows. Initialize them once, before the first family flush.
func newPrivateContinuousPostgresSink(ctx context.Context, writer *pgx.Conn,
    g *PreparedGeneration, limits BacklogWindowLimits) (*privateContinuousPostgresSink,error) {
    if ctx == nil || writer == nil || g == nil {
        return nil, errors.New("FI continuous SQL: missing context, connection or signed generation")
    }
    ds, err := DescribeBacklogWindows(g, limits)
    if err != nil || len(ds)==0 {
        return nil, fmt.Errorf("FI continuous SQL: invalid window descriptors: %w",err)
    }
    receipt, err := hex.DecodeString(ds[0].ReceiptSHA256)
    if err != nil || len(receipt)!=32 { return nil, errors.New("FI continuous SQL: invalid signed receipt") }
    var who,db string
    if err := writer.QueryRow(ctx,"SELECT current_user,current_database()").Scan(&who,&db);err!=nil {return nil,err}
    if who!="fi_ingest" || db!="fi" { return nil, errors.New("FI continuous SQL: expected isolated fi_ingest/fi PostgreSQL identity") }
    tx,err := writer.Begin(ctx)
    if err!=nil {return nil,err}
    defer tx.Rollback(context.Background())
    if _,err=tx.Exec(ctx,"SELECT pg_advisory_xact_lock($1::bigint)",int64(binary.BigEndian.Uint64(receipt[:8])));err!=nil{return nil,err}
    var authoritative bool
    if err=tx.QueryRow(ctx,`SELECT EXISTS (SELECT 1 FROM fi.recorded_generation WHERE source_id=$1 AND generation_id=$2)`,
        ds[0].SourceID,ds[0].GenerationID).Scan(&authoritative);err!=nil{return nil,err}
    if authoritative {return nil,errors.New("FI continuous SQL: authoritative generation already exists")}
    shadow:=privateProjectionTx{Tx:tx}
    id,found,err:=lookupRecordedGeneration(ctx,shadow,ds[0].SourceID,ds[0].GenerationID,
        g.Receipt.TransferSHA256,g.ReceiptSHA256)
    if err!=nil{return nil,err}
    if !found {
        id,err=insertRecordedGeneration(ctx,shadow,g)
        if err!=nil{return nil,err}
        var profile sourceBatchBulkProfile
        if _,err=copySourceBatches(ctx,shadow,id,g.Batches,&profile);err!=nil{return nil,err}
    }
    batchIDs,err:=lookupBacklogShadowBatchIDs(ctx,shadow,id,g.Batches)
    if err!=nil{return nil,err}
    if err=tx.Commit(ctx);err!=nil{return nil,err}
    return &privateContinuousPostgresSink{writer:writer,generation:g,windows:ds,
        batchIDs:batchIDs,shadowGenerationID:id,receipt:receipt},nil
}

func (s *privateContinuousPostgresSink) SourceWindowDurable(ctx context.Context, i int) error {
    if s==nil || ctx==nil || i<0 || i>=len(s.windows) {return errors.New("FI continuous SQL: invalid source-window index")}
    d:=s.windows[i]
    digest,err:=hex.DecodeString(d.DigestSHA256)
    if err!=nil{return err}
    var actual []byte
    var count,bytes int64
    var first,last int
    err=s.writer.QueryRow(ctx,`SELECT descriptor_sha256,staged_records,staged_bytes,start_batch,end_batch
        FROM fi_recovery.source_window WHERE receipt_sha256=$1 AND window_index=$2`,
        s.receipt,i).Scan(&actual,&count,&bytes,&first,&last)
    if err!=nil{return fmt.Errorf("FI continuous SQL: missing durable source window %d: %w",i,err)}
    if subtle.ConstantTimeCompare(actual,digest)!=1 ||
        count!=int64(d.EndRecord-d.StartRecord) || bytes!=int64(d.DataBytes) ||
        first!=d.StartBatch || last!=d.EndBatch {
        return errors.New("FI continuous SQL: source-window checkpoint differs from signed descriptor")
    }
    return nil
}

type privateContinuousSQLRow struct {
    item privateContinuousRecord
    id int64
    done bool
}

func (s *privateContinuousPostgresSink) FlushFamily(ctx context.Context,
    family privateContinuousFamily,batch []privateContinuousRecord) error {
    if s==nil || ctx==nil || len(batch)==0 || family<privateFamilySecurity ||
        family>privateFamilyOrderedOther {
        return errors.New("FI continuous SQL: invalid family flush")
    }
    tx,err:=s.writer.Begin(ctx)
    if err!=nil{return err}
    defer tx.Rollback(context.Background())
    if _,err=tx.Exec(ctx,"SELECT pg_advisory_xact_lock($1::bigint)",
        int64(binary.BigEndian.Uint64(s.receipt[:8])));err!=nil{return err}
    shadow:=privateProjectionTx{Tx:tx}
    rows:=make([]privateContinuousSQLRow,len(batch))
    for i,item:=range batch {
        if item.WindowIndex<0 || item.WindowIndex>=len(s.windows) ||
            item.SignedBatchIndex<0 || item.SignedBatchIndex>=len(s.batchIDs) ||
            item.SourceBatchID!=s.batchIDs[item.SignedBatchIndex] ||
            item.Prepared.RecordBytes<=0 || item.Ordinal<=0 {
            return fmt.Errorf("FI continuous SQL: bad original custody identity at row %d",i)
        }
        mapped,err:=privateFamilyForRecordKind(item.Prepared.Record.RecordKind)
        if err!=nil || mapped!=family{return fmt.Errorf("FI continuous SQL: family mismatch at row %d",i)}
        // A trusted source-window marker is required even on a replay. The
        // immutable staged metadata must agree with the exact signed row.
        var storedDigest []byte
        var storedBytes int
        var storedKind,storedScope,storedVersion string
        err=tx.QueryRow(ctx,`SELECT record_sha256,record_bytes,record_kind,scope_id,version
            FROM fi_recovery.pending_source_record
            WHERE receipt_sha256=$1 AND window_index=$2 AND batch_index=$3 AND record_ordinal=$4`,
            s.receipt,item.WindowIndex,item.SignedBatchIndex,item.Ordinal).
            Scan(&storedDigest,&storedBytes,&storedKind,&storedScope,&storedVersion)
        if err!=nil{return fmt.Errorf("FI continuous SQL: missing staged custody row %d: %w",i,err)}
        if subtle.ConstantTimeCompare(storedDigest,item.Prepared.RecordDigest[:])!=1 ||
            storedBytes!=item.Prepared.RecordBytes ||
            storedKind!=item.Prepared.Record.RecordKind ||
            storedScope!=item.Prepared.Record.ScopeID ||
            storedVersion!=item.Prepared.Record.Version {
            return fmt.Errorf("FI continuous SQL: signed source digest or envelope mismatch at row %d",i)
        }
        var prevDigest []byte
        var prevID int64
        err=tx.QueryRow(ctx,`SELECT record_sha256,shadow_source_record_id
            FROM fi_recovery.projected_source_record
            WHERE receipt_sha256=$1 AND batch_index=$2 AND record_ordinal=$3`,
            s.receipt,item.SignedBatchIndex,item.Ordinal).Scan(&prevDigest,&prevID)
        if err==nil {
            if subtle.ConstantTimeCompare(prevDigest,item.Prepared.RecordDigest[:])!=1 || prevID<=0 {
                return errors.New("FI continuous SQL: committed projection receipt collision")
            }
            var matched bool
            err=shadow.QueryRow(ctx,`SELECT EXISTS(SELECT 1 FROM fi.source_record
                WHERE source_record_id=$1 AND source_batch_id=$2 AND record_ordinal=$3
                AND record_sha256=$4 AND record_kind=$5 AND record_bytes=$6)`,
                prevID,item.SourceBatchID,item.Ordinal,item.Prepared.RecordDigest[:],
                item.Prepared.Record.RecordKind,item.Prepared.RecordBytes).Scan(&matched)
            if err!=nil || !matched {return errors.New("FI continuous SQL: committed receipt missing matching shadow source row")}
            rows[i]=privateContinuousSQLRow{item:item,id:prevID,done:true}
            continue
        }
        if !errors.Is(err,pgx.ErrNoRows) {return err}
        rows[i]=privateContinuousSQLRow{item:item}
    }

    // All deferred child writers live inside ONE family SQL transaction.
    // Do not carry their caches across commits or accept partial children.
    projectCtx:=context.WithValue(ctx,privateContinuousFamilyWriterKey{},true)
    projectCtx=context.WithValue(projectCtx,ntfsObjectCacheContextKey{},newNTFSObjectCache())
    projectCtx=context.WithValue(projectCtx,ntfsScopeIdentityCacheContextKey{},newNTFSScopeIdentityCache())
    hashCopy:=newContentHashCopyState()
    aceCopy:=newACECopyState()
    usnCopy:=newUSNChangeCopyState()
    projectCtx=context.WithValue(projectCtx,contentHashCopyContextKey{},hashCopy)
    projectCtx=context.WithValue(projectCtx,aceCopyContextKey{},aceCopy)
    projectCtx=context.WithValue(projectCtx,usnChangeCopyContextKey{},usnCopy)
    projectCtx=context.WithValue(projectCtx,usnCaptureContextKey{},
        newUSNCaptureState(s.windows[0].SourceID,s.windows[0].GenerationID))
    projectCtx=context.WithValue(projectCtx,backlogUSNCrossWindowContextKey{},true)
    fileBulk:=newFileObservationBulkState()
    projectCtx=context.WithValue(projectCtx,fileObservationBulkContextKey{},fileBulk)
    var profile ingestStageProfile
    switch family {
    case privateFamilySecurity:
        projectCtx,err=withFixedSecurityBulkProfile(projectCtx,"P3")
        if err!=nil{return err}
        pending:=make([]securityBulkRecord,0,len(batch))
        for i:=range rows {
            if rows[i].done {continue}
            item:=rows[i].item
            p,e:=prepareSecurityBulkRecord(item.Ordinal,item.Prepared,item.Prepared.RecordDigest[:])
            if e!=nil{return e}
            p.sourceBatchID=item.SourceBatchID
            pending=append(pending,p)
        }
        if len(pending)!=0 {
            if err=copySecurityBulk(projectCtx,shadow,pending[0].sourceBatchID,pending,&profile);err!=nil{return err}
            n:=0
            for i:=range rows {
                if rows[i].done {continue}
                rows[i].id=pending[n].sourceRecordID
                n++
            }
        }
    case privateFamilyFile:
        projectCtx,err=withFixedFileBulkProfile(projectCtx,"F3")
        if err!=nil{return err}
        pending:=make([]fileSourceBulkRecord,0,len(batch))
        for i:=range rows {
            if rows[i].done {continue}
            item:=rows[i].item
            pending=append(pending,fileSourceBulkRecord{sourceBatchID:item.SourceBatchID,
                ordinal:item.Ordinal,prepared:item.Prepared,digest:item.Prepared.RecordDigest[:]})
        }
        if len(pending)!=0 {
            if err=copyFileSourceBulk(projectCtx,shadow,pending[0].sourceBatchID,pending,&profile);err!=nil{return err}
            n:=0
            for i:=range rows {
                if rows[i].done {continue}
                item:=rows[i].item
                p:=&pending[n]
                rows[i].id=p.sourceRecordID
                var value fileObservationPayload
                if err=decodeStrictPayload(item.Prepared.Record.Payload,&value);err!=nil{return err}
                value.NTFS.ContentHashes=&value.ContentHashes
                if err=ntfs.ValidateObservation(value.NTFS);err!=nil{return err}
                if value.NTFS.GovernedRoot.ScopeID!=item.Prepared.Record.ScopeID {
                    return errors.New("FI continuous SQL: FileObservation scope mismatch")
                }
                if err=fileBulk.add(projectCtx,shadow,fileObservationBulkRecord{
                    sourceID:s.windows[0].SourceID,sourceRecordID:p.sourceRecordID,
                    ordinal:item.Ordinal,value:value.NTFS,hashes:&value.ContentHashes,
                    bytes:int64(item.Prepared.RecordBytes)});err!=nil{return err}
                n++
            }
            if err=fileBulk.flush(projectCtx,shadow);err!=nil{return err}
        }
    default:
        for i:=range rows {
            if rows[i].done {continue}
            item:=rows[i].item
            err=shadow.QueryRow(projectCtx,`INSERT INTO fi.source_record
                (source_batch_id,record_ordinal,version,record_kind,scope_id,written_at,
                 record_bytes,record_sha256,ingest_version)
                 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING source_record_id`,
                item.SourceBatchID,item.Ordinal,item.Prepared.Record.Version,
                item.Prepared.Record.RecordKind,item.Prepared.Record.ScopeID,item.Prepared.WrittenAtUTC,
                item.Prepared.RecordBytes,item.Prepared.RecordDigest[:],IngestVersion).Scan(&rows[i].id)
            if err!=nil{return err}
            childCtx:=projectCtx
            if item.Prepared.Record.RecordKind=="USNObjectObservation" {
                childCtx=context.WithValue(childCtx,fileObservationBulkBytesContextKey{},item.Prepared.RecordBytes)
            }
            if err=ProjectSourceRecord(childCtx,shadow,s.windows[0].SourceID,rows[i].id,item.Prepared);err!=nil{return err}
        }
    }
    if err=usnCopy.flushAll(projectCtx,shadow);err!=nil{return err}
    if err=hashCopy.flush(projectCtx,shadow);err!=nil{return err}
    if err=aceCopy.flushAll(projectCtx,shadow);err!=nil{return err}
    for i,row:=range rows {
        if row.done {continue}
        if row.id<=0 {return errors.New("FI continuous SQL: projected source missing generated ID")}
        _,err=tx.Exec(ctx,`INSERT INTO fi_recovery.projected_source_record
            (receipt_sha256,window_index,batch_index,record_ordinal,record_sha256,shadow_source_record_id)
            VALUES($1,$2,$3,$4,$5,$6)`,
            s.receipt,row.item.WindowIndex,row.item.SignedBatchIndex,row.item.Ordinal,
            row.item.Prepared.RecordDigest[:],row.id)
        if err!=nil{return err}
        _=i
    }
    return tx.Commit(ctx)
}

// Typed markers are separate from source checkpoints and buffer transactions.
// The marker is never created from the router's in-memory counters alone.
func (s *privateContinuousPostgresSink) MarkProjected(ctx context.Context,i int) error {
    if s==nil || ctx==nil || i<0 || i>=len(s.windows) {return errors.New("FI continuous SQL: invalid projection marker request")}
    d:=s.windows[i]
    digest,err:=hex.DecodeString(d.DigestSHA256)
    if err!=nil{return err}
    tx,err:=s.writer.Begin(ctx)
    if err!=nil{return err}
    defer tx.Rollback(context.Background())
    if _,err=tx.Exec(ctx,"SELECT pg_advisory_xact_lock($1::bigint)",int64(binary.BigEndian.Uint64(s.receipt[:8])));err!=nil{return err}
    shadow:=privateProjectionTx{Tx:tx}
    var sourceDigest []byte
    err=tx.QueryRow(ctx,`SELECT descriptor_sha256 FROM fi_recovery.source_window
        WHERE receipt_sha256=$1 AND window_index=$2`,s.receipt,i).Scan(&sourceDigest)
    if err!=nil{return err}
    if subtle.ConstantTimeCompare(sourceDigest,digest)!=1 {return errors.New("FI continuous SQL: durable source descriptor mismatch")}
    if i>0 {
        prior,err:=hex.DecodeString(d.PreviousDigestSHA256)
        if err!=nil{return err}
        var saved []byte
        if err=tx.QueryRow(ctx,`SELECT descriptor_sha256 FROM fi_recovery.typed_window
            WHERE receipt_sha256=$1 AND window_index=$2`,s.receipt,i-1).Scan(&saved);err!=nil{return err}
        if subtle.ConstantTimeCompare(prior,saved)!=1 {return errors.New("FI continuous SQL: prior typed marker digest mismatch")}
    }
    // The source ledger is the expected-set authority. Its primary key
    // guarantees no duplicated signed identity. Both the projection receipt
    // and exact shadow source row are required for each staged identity.
    var count,bytes int64
    err=tx.QueryRow(ctx,`SELECT count(*),coalesce(sum(p.record_bytes),0)::bigint
        FROM fi_recovery.pending_source_record p
        JOIN fi_recovery.projected_source_record r
          ON r.receipt_sha256=p.receipt_sha256 AND r.batch_index=p.batch_index
          AND r.record_ordinal=p.record_ordinal AND r.window_index=p.window_index
          AND r.record_sha256=p.record_sha256
        JOIN fi_recovery_projection.source_record sr
          ON sr.source_record_id=r.shadow_source_record_id
          AND sr.record_sha256=p.record_sha256
          AND sr.record_kind=p.record_kind
          AND sr.scope_id=p.scope_id
          AND sr.record_bytes=p.record_bytes
        WHERE p.receipt_sha256=$1 AND p.window_index=$2`,s.receipt,i).Scan(&count,&bytes)
    if err!=nil{return err}
    if count!=int64(d.EndRecord-d.StartRecord) || bytes!=int64(d.DataBytes) {
        return fmt.Errorf("FI continuous SQL: incomplete typed receipts window=%d got=%d/%d expected=%d/%d",
            i,count,bytes,d.EndRecord-d.StartRecord,d.DataBytes)
    }
    if err=verifyBacklogShadowWindowCounts(ctx,shadow,s.shadowGenerationID,
        s.generation.Batches[d.StartBatch:d.EndBatch],count,bytes);err!=nil{return err}
    if err=verifyBacklogWindowProjectionCoverage(ctx,shadow,s.shadowGenerationID,
        s.generation.Batches[d.StartBatch:d.EndBatch]);err!=nil{return err}
    var existing []byte
    var existingCount,existingBytes int64
    err=tx.QueryRow(ctx,`SELECT descriptor_sha256,committed_records,committed_bytes
        FROM fi_recovery.typed_window WHERE receipt_sha256=$1 AND window_index=$2`,
        s.receipt,i).Scan(&existing,&existingCount,&existingBytes)
    if err==nil {
        if subtle.ConstantTimeCompare(existing,digest)!=1 || existingCount!=count || existingBytes!=bytes {
            return errors.New("FI continuous SQL: conflicting existing typed marker")
        }
        return tx.Commit(ctx)
    }
    if !errors.Is(err,pgx.ErrNoRows) {return err}
    _,err=tx.Exec(ctx,`INSERT INTO fi_recovery.typed_window
        (receipt_sha256,window_index,descriptor_sha256,shadow_generation_id,
         start_batch,end_batch,committed_records,committed_bytes,ingest_version)
        VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
        s.receipt,i,digest,s.shadowGenerationID,d.StartBatch,d.EndBatch,count,bytes,IngestVersion)
    if err!=nil{return err}
    return tx.Commit(ctx)
}

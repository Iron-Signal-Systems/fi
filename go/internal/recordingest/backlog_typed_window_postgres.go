// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, in the repository root LICENSE file.

package recordingest

import (
    "context"
    "crypto/subtle"
    "encoding/binary"
    "encoding/hex"
    "errors"
    "fmt"
    "math"
    "path/filepath"

    "github.com/jackc/pgx/v5"
)

// StageBacklogTypedWindow is an opt-in isolated-fixture prototype. It commits
// one bounded window's actual typed projections to the PRIVATE relational
// shadow, together with its completed-window marker, in one transaction.
//
// Gate 3F explicitly permits only these independent record families. FI's
// Security, File, USN, and cross-batch state must be independently accepted
// before those families are allowed here. This path does not mark any
// generation Accepted or modify the canonical fi.* system of record.
func StageBacklogTypedWindow(
    ctx context.Context,
    reader, writer *pgx.Conn,
    generation *PreparedGeneration,
    limits BacklogWindowLimits,
    index int,
    privateRoot string,
) error {
    if ctx==nil||reader==nil||writer==nil||reader==writer {
        return errors.New("FI typed window: distinct reader and writer connections required")
    }
    if err:=ctx.Err();err!=nil{return err}
    descriptors,err:=DescribeBacklogWindows(generation,limits)
    if err!=nil{return err}
    if index<0||index>=len(descriptors){return errors.New("FI typed window: invalid index")}
    d:=descriptors[index]
    if d.EndRecord>math.MaxInt64||d.DataBytes>math.MaxInt64{
        return errors.New("FI typed window: SQL count limits exceeded")
    }

    // Replay checks the full committed private source identity and immutable
    // bytes before opening the typed-write transaction. Unsupported families
    // fail closed, rather than accidentally dropping their child projections.
    summary,err:=ReplayVerifiedBacklogSourceWindow(ctx,reader,generation,limits,index,privateRoot,
        func(_ int,_ int64,record SourceRecord)error{
            switch record.Record.RecordKind {
            case "NTFSCollectionError","SupportingSourceCollectionError":
                return nil
            default:
                return fmt.Errorf("FI typed window: family %q requires cross-window projection acceptance",record.Record.RecordKind)
            }
        })
    if err!=nil{return fmt.Errorf("FI typed window: source preflight: %w",err)}
    if summary.RecordCount!=d.EndRecord-d.StartRecord||summary.DataBytes!=d.DataBytes{
        return errors.New("FI typed window: preflight receipt totals disagree")
    }

    var who,db string
    if err:=writer.QueryRow(ctx,"SELECT current_user,current_database()").Scan(&who,&db);err!=nil{return err}
    if who!="fi_ingest"||db!="fi" {return errors.New("FI typed window: unexpected database identity")}
    receipt,err:=hex.DecodeString(d.ReceiptSHA256);if err!=nil{return err}
    digest,err:=hex.DecodeString(d.DigestSHA256);if err!=nil{return err}
    tx,err:=writer.Begin(ctx);if err!=nil{return err}
    defer tx.Rollback(context.Background())
    lockKey:=int64(binary.BigEndian.Uint64(receipt[:8]))
    if _,err:=tx.Exec(ctx,"SELECT pg_advisory_xact_lock($1::bigint)",lockKey);err!=nil{return err}
    var authoritative bool
    if err:=tx.QueryRow(ctx,`
SELECT EXISTS (SELECT 1 FROM fi.recorded_generation
 WHERE source_id=$1 AND generation_id=$2)
`,d.SourceID,d.GenerationID).Scan(&authoritative);err!=nil{return err}
    if authoritative{return errors.New("FI typed window: original generation already authoritative")}

    // Require committed exact source-window checkpoint, not merely the
    // existence of files or a prior attempted ingest.
    var sourceDigest []byte
    if err:=tx.QueryRow(ctx,`
SELECT descriptor_sha256 FROM fi_recovery.source_window
 WHERE receipt_sha256=$1 AND window_index=$2
`,receipt,index).Scan(&sourceDigest);err!=nil{return err}
    if subtle.ConstantTimeCompare(sourceDigest,digest)!=1{
        return errors.New("FI typed window: private source-window descriptor mismatch")
    }
    shadow:=privateProjectionTx{Tx:tx}

    // Already completed is never inferred from shadow rows alone.
    var completedDigest []byte
    var shadowID,committedRecords,committedBytes int64
    var fromBatch,toBatch int
    var version string
    err=tx.QueryRow(ctx,`
SELECT descriptor_sha256,shadow_generation_id,start_batch,end_batch,
       committed_records,committed_bytes,ingest_version
FROM fi_recovery.typed_window
WHERE receipt_sha256=$1 AND window_index=$2
`,receipt,index).Scan(&completedDigest,&shadowID,&fromBatch,&toBatch,
        &committedRecords,&committedBytes,&version)
    if err==nil{
        if subtle.ConstantTimeCompare(completedDigest,digest)!=1 ||
            fromBatch!=d.StartBatch||toBatch!=d.EndBatch||
            committedRecords!=int64(summary.RecordCount)||
            committedBytes!=int64(summary.DataBytes)||version!=IngestVersion{
            return errors.New("FI typed window: conflicting completed typed marker")
        }
        id,found,err:=lookupRecordedGeneration(ctx,shadow,d.SourceID,d.GenerationID,
            generation.Receipt.TransferSHA256,generation.ReceiptSHA256)
        if err!=nil{return err}
        if !found||id!=shadowID{return errors.New("FI typed window: shadow generation identity changed")}
        if err:=verifyBacklogShadowWindowCounts(ctx,shadow,id,generation.Batches[d.StartBatch:d.EndBatch],
            int64(summary.RecordCount),int64(summary.DataBytes));err!=nil{return err}
        if err:=verifyGenerationProjectionCoverage(ctx,shadow,id);err!=nil{return err}
        return tx.Commit(ctx)
    }
    if !errors.Is(err,pgx.ErrNoRows){return err}

    if index>0{
        var priorDigest []byte
        if err:=tx.QueryRow(ctx,`
SELECT descriptor_sha256 FROM fi_recovery.typed_window
WHERE receipt_sha256=$1 AND window_index=$2
`,receipt,index-1).Scan(&priorDigest);err!=nil{
            return fmt.Errorf("FI typed window: preceding typed window missing: %w",err)
        }
        prev,err:=hex.DecodeString(d.PreviousDigestSHA256);if err!=nil{return err}
        if subtle.ConstantTimeCompare(priorDigest,prev)!=1{
            return errors.New("FI typed window: preceding typed digest mismatch")
        }
    }

    id,found,err:=lookupRecordedGeneration(ctx,shadow,d.SourceID,d.GenerationID,
        generation.Receipt.TransferSHA256,generation.ReceiptSHA256)
    if err!=nil{return err}
    if index==0{
        if found{return errors.New("FI typed window: incomplete initial shadow generation without marker")}
        id,err=insertRecordedGeneration(ctx,shadow,generation)
        if err!=nil{return err}
        var profile sourceBatchBulkProfile
        if _,err:=copySourceBatches(ctx,shadow,id,generation.Batches,&profile);err!=nil{return err}
    }else if !found{
        return errors.New("FI typed window: previous shadow generation missing")
    }

    batchIDs,err:=lookupBacklogShadowBatchIDs(ctx,shadow,id,generation.Batches[d.StartBatch:d.EndBatch])
    if err!=nil{return err}
    var profile ingestStageProfile
    profile.coverageBuffer=newSecurityCoverageBulkState(&profile)
    var totalRecords int64
    var totalBytes int64
    stageDir:=filepath.Join(privateRoot,"receipt-"+d.ReceiptSHA256,fmt.Sprintf("window-%08d",index))
    for offset:=0;offset<len(batchIDs);offset++{
        globalIndex:=d.StartBatch+offset
        batch:=generation.Batches[globalIndex]
        batch.DataPath=filepath.Join(stageDir,fmt.Sprintf("batch-%08d.data",globalIndex))
        seen,err:=ingestSourceBatch(ctx,shadow,d.SourceID,batchIDs[offset],batch,&profile)
        if err!=nil{return fmt.Errorf("FI typed window: batch %d: %w",globalIndex,err)}
        totalRecords+=seen
        totalBytes+=batch.Manifest.DataBytes
    }
    if err:=profile.coverageBuffer.flush(ctx,shadow);err!=nil{return err}
    if totalRecords!=int64(summary.RecordCount)||totalBytes!=int64(summary.DataBytes){
        return errors.New("FI typed window: processed counts differ from signed receipt")
    }
    if err:=verifyBacklogShadowWindowCounts(ctx,shadow,id,generation.Batches[d.StartBatch:d.EndBatch],
        totalRecords,totalBytes);err!=nil{return err}
    if err:=verifyGenerationProjectionCoverage(ctx,shadow,id);err!=nil{return err}
    _,err=tx.Exec(ctx,`
INSERT INTO fi_recovery.typed_window (
 receipt_sha256,window_index,descriptor_sha256,shadow_generation_id,
 start_batch,end_batch,committed_records,committed_bytes,ingest_version
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
`,receipt,index,digest,id,d.StartBatch,d.EndBatch,totalRecords,totalBytes,IngestVersion)
    if err!=nil{return fmt.Errorf("FI typed window: atomic completion marker: %w",err)}
    return tx.Commit(ctx)
}

func lookupBacklogShadowBatchIDs(ctx context.Context,tx pgx.Tx,id int64,batches []PreparedBatch)([]int64,error){
    ids:=make([]string,len(batches))
    positions:=make(map[string]int,len(batches))
    for i,b:=range batches{
        if b.BatchID=="" {return nil,errors.New("FI typed window: empty batch ID")}
        if _,found:=positions[b.BatchID];found{return nil,errors.New("FI typed window: duplicated batch ID")}
        ids[i]=b.BatchID;positions[b.BatchID]=i
    }
    rows,err:=tx.Query(ctx,`
SELECT batch_id,source_batch_id FROM fi.source_batch
WHERE recorded_generation_id=$1 AND batch_id=ANY($2::text[])
`,id,ids)
    if err!=nil{return nil,err}
    defer rows.Close()
    found:=make([]int64,len(ids))
    n:=0
    for rows.Next(){
        var key string;var value int64
        if err:=rows.Scan(&key,&value);err!=nil{return nil,err}
        i,known:=positions[key]
        if !known||value<=0||found[i]!=0{return nil,errors.New("FI typed window: source-batch identity collision")}
        found[i]=value;n++
    }
    if err:=rows.Err();err!=nil{return nil,err}
    if n!=len(ids){return nil,errors.New("FI typed window: incomplete source-batch ID map")}
    return found,nil
}
func verifyBacklogShadowWindowCounts(ctx context.Context,tx pgx.Tx,id int64,batches []PreparedBatch,records,bytes int64)error{
    ids:=make([]string,len(batches))
    for i,b:=range batches{ids[i]=b.BatchID}
    var gotRecords,gotBytes int64
    err:=tx.QueryRow(ctx,`
SELECT count(*),coalesce(sum(sr.record_bytes),0)::bigint
FROM fi.source_record sr
JOIN fi.source_batch sb ON sb.source_batch_id=sr.source_batch_id
WHERE sb.recorded_generation_id=$1 AND sb.batch_id=ANY($2::text[])
`,id,ids).Scan(&gotRecords,&gotBytes)
    if err!=nil{return err}
    if gotRecords!=records||gotBytes!=bytes{
        return fmt.Errorf("FI typed window: projected source counts %d/%d differ from receipt %d/%d",
            gotRecords,gotBytes,records,bytes)
    }
    return nil
}

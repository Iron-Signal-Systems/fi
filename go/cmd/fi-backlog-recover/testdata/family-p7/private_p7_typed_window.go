// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// FI P7 PRIVATE W512 five PostgreSQL family writers, NOT the accepted
// single-transaction StageBacklogTypedWindow. This new entry point preserves
// the signed P5 prep/ordinal stream, verifies and COMMITS source custody
// first, then runs 5 family SQL backends, then publishes the marker only
// after the original relational/source/dependency checks pass.
// Any failure requires the entire private clone to be discarded.
package recordingest

import (
    "context"
    "errors"
    "fmt"
    "math"
    "os"
    "path/filepath"
    "time"

    "github.com/jackc/pgx/v5"
)

type privateP7SignedBatchIndexKey struct{}

func stagePrivateP7FiveWriterTypedWindow(
    ctx context.Context,reader,control *pgx.Conn,
    generation *PreparedGeneration,limits BacklogWindowLimits,
    index int,privateRoot string,
)error{
    if ctx==nil||reader==nil||control==nil||reader==control||
        generation==nil||privateRoot==""||
        !privateP7FiveWriterSelected(){
        return errors.New("FI P7: clone-only five-writer W512 stage not explicitly selected")
    }
    if err:=ctx.Err();err!=nil{return err}
    ds,err:=DescribeBacklogWindows(generation,limits)
    if err!=nil{return err}
    if index<=0||index>=len(ds){
        return errors.New("FI P7: only signed non-seed W512 windows are supported")
    }
    d:=ds[index]
    if d.EndRecord>math.MaxInt64||d.DataBytes>math.MaxInt64{
        return errors.New("FI P7: source window exceeds SQL record/byte limits")
    }
    dsn:=os.Getenv("FI_W512_P7_SQL_DSN")
    dataDir:=os.Getenv("FI_W512_P7_EXPECTED_PGDATA")
    if dsn==""||dataDir==""{
        return errors.New("FI P7: explicit private clone DSN and exact PGDATA path required")
    }
    if _,err:=privateP7VerifyCloneConnection(ctx,control,dataDir);err!=nil{
        return fmt.Errorf("FI P7: unsafe control/marker SQL connection: %w",err)
    }
    if _,err:=privateP7VerifyCloneConnection(ctx,reader,dataDir);err!=nil{
        return fmt.Errorf("FI P7: unsafe signed-source reader SQL connection: %w",err)
    }
    started:=time.Now()

    // The deferred-cache loader does not guarantee a physical private
    // window exists. The source ledger requires the fully verified copy.
    verifiedStageDir,err:=privateP7MaterializeSignedWindow(
        ctx,generation,limits,index,privateRoot,d)
    if err!=nil{return err}
    // Deferred joined-source replay may intentionally skip the separate
    // fi_recovery.verified_artifact_window checkpoint. P7 requires that
    // independently committed checkpoint BEFORE StageVerifiedBacklogSourceWindow
    // can create the signed pending-source ledger. Record it only after
    // physical materialization and complete original manifest/data hashing.
    // The existing artifact-ledger function verifies AGAIN and enforces
    // the exact preceding window, transfer/receipt identity and digest.
    if err:=RecordVerifiedBacklogArtifactWindow(ctx,control,generation,limits,
        index,privateRoot);err!=nil{
        return fmt.Errorf("FI P7: signed physical artifact checkpoint: %w",err)
    }
    fmt.Printf("FI P7 VERIFIED ARTIFACT CHECKPOINT COMMITTED index=%d signed_batches=%d records=%d source_rows=pending typed_marker=absent\n",
        index,d.EndBatch-d.StartBatch,d.EndRecord-d.StartRecord)
    // Five independent PostgreSQL family transactions require parents to
    // be durable first. The existing exact signed source-ledger stage
    // revalidates the artifact checkpoint and original source bytes before
    // it commits pending-source rows.
    if err:=StageVerifiedBacklogSourceWindow(ctx,control,generation,limits,
        index,privateRoot);err!=nil{
        return fmt.Errorf("FI P7: authenticated durable source pre-stage: %w",err)
    }
    fmt.Printf("FI P7 VERIFIED SOURCE CHECKPOINT COMMITTED index=%d signed_batches=%d records=%d artifact=committed typed_marker=absent\n",
        index,d.EndBatch-d.StartBatch,d.EndRecord-d.StartRecord)
    sourceStageElapsed:=time.Since(started)
    // Shadow generation and original source batch identity were already
    // created by the accepted seed W512=0. NEVER mint new batch IDs.
    readTx,err:=control.Begin(ctx)
    if err!=nil{return err}
    shadow:=privateProjectionTx{Tx:readTx}
    shadowGenerationID,found,err:=lookupRecordedGeneration(ctx,shadow,
        d.SourceID,d.GenerationID,generation.Receipt.TransferSHA256,
        generation.ReceiptSHA256)
    if err!=nil||!found{
        _=readTx.Rollback(context.Background())
        return errors.New("FI P7: original signed private shadow generation is missing")
    }
    batchIDs,err:=lookupBacklogShadowBatchIDs(ctx,shadow,shadowGenerationID,
        generation.Batches[d.StartBatch:d.EndBatch])
    if rollErr:=readTx.Rollback(ctx);rollErr!=nil{
        return fmt.Errorf("FI P7: close original source batch lookup: %w",rollErr)
    }
    if err!=nil{return fmt.Errorf("FI P7: original signed batch FK lookup: %w",err)}
    if len(batchIDs)!=d.EndBatch-d.StartBatch{
        return errors.New("FI P7: original source batch key count mismatch")
    }

    // The original joined W512 caller provides a typed-source sentinel.
    // Five-connection P7 already durably staged the source window above;
    // mask that sentinel so ingestSourceBatch NEVER attempts a second,
    // transaction-bound joined source_record COPY before the P7 handoff.
    ctx=context.WithValue(ctx,joinedBacklogSourceKey{},nil)

    // The File bulk proof and USN capture object are the ORIGINAL FI
    // validator/capture types. P7 must not generate synthetic receipts.
    ntfsTiming:=&ntfsStageTimingCounters{}
    ctx=context.WithValue(ctx,ntfsStageTimingContextKey{},ntfsTiming)
    captureState:=newUSNCaptureState(d.SourceID,d.GenerationID)
    ctx=context.WithValue(ctx,usnCaptureContextKey{},captureState)
    ctx=context.WithValue(ctx,backlogUSNCrossWindowContextKey{},true)
    ctx=context.WithValue(ctx,usnTimingContextKey{},&usnTimingCounters{})
    pool,err:=newPrivateP5Pool(ctx,index)
    if err!=nil{return fmt.Errorf("FI P7: P5 worker pool: %w",err)}
    defer pool.Close()
    ctx=context.WithValue(ctx,privateP5PoolContextKey{},pool)

    session,err:=newPrivateP7WindowSession(ctx,control,dsn,dataDir,
        generation,d,index,index==len(ds)-1)
    if err!=nil{return err}
    defer session.Close(context.Background())
    ctx=context.WithValue(ctx,privateP6WindowContextKey{},session.buffers)

    // This P6/P7 overlay uses P5's real optimized header-first ingester.
    // Its P7 signed batch index is explicitly carried by this context;
    // no joined-source transaction is opened and no duplicate parent
    // source_record COPY occurs in the preparation reader.
    sourceDir:=verifiedStageDir
    var profile ingestStageProfile
    profile.coverageBuffer=newSecurityCoverageBulkState(&profile)
    // Reuse the ORIGINAL signed-batch reader, LF/digest verification and
    // selected P5 preparation pipeline. Its P7 early-family handoff
    // intercept performs no SQL on this read-only, control-local tx.
    readOnlyTx,err:=control.BeginTx(ctx,pgx.TxOptions{AccessMode:pgx.ReadOnly})
    if err!=nil{return err}
    // Every error/cancellation must release this read-only snapshot.
    defer readOnlyTx.Rollback(context.Background())
    var records,bytes int64
    ingestStarted:=time.Now()
    for offset,sourceBatchID:=range batchIDs{
        globalIndex:=d.StartBatch+offset
        batch:=generation.Batches[globalIndex]
        batch.DataPath=filepath.Join(sourceDir,
            fmt.Sprintf("batch-%08d.data",globalIndex))
        if batch.Manifest.RecordCount<1{
            return errors.New("FI P7: empty signed source batch not allowed")
        }
        batchCtx:=context.WithValue(ctx,privateP7SignedBatchIndexKey{},globalIndex)
        // The clone-only P7 overlay intercepts this after the ORIGINAL
        // canonical signature/record preparation, before monolithic SQL.
        // Read-only control tx cannot accidentally persist a typed row.
        n,err:=ingestSourceBatch(batchCtx,privateProjectionTx{Tx:readOnlyTx},
            d.SourceID,sourceBatchID,batch,&profile)
        if err!=nil{
            return fmt.Errorf("FI P7: signed batch=%d: %w",globalIndex,err)
        }
        records+=n
        bytes+=batch.Manifest.DataBytes
    }
    ingestElapsed:=time.Since(ingestStarted)
    if records!=int64(d.EndRecord-d.StartRecord)||
        bytes!=int64(d.DataBytes){
        return fmt.Errorf("FI P7: signed source totals mismatch records=%d bytes=%d",records,bytes)
    }
    // This is issued only AFTER every original signed batch has passed
    // its real LF/row-count/bytes/SHA check and the signed W512 totals match.
    fmt.Printf("FI P7 SIGNED BATCH VERIFIED window=%d batches=%d records=%d bytes=%d manifest_sha_validated=true record_sha_validated=true\n",
        index,len(batchIDs),records,bytes)
    if err:=readOnlyTx.Rollback(ctx);err!=nil {
        return fmt.Errorf("FI P7: close signed reader snapshot before publish: %w",err)
    }
    publishStarted:=time.Now()
    // The capture verifier must run only AFTER session.Publish drains
    // every asynchronous SQL lane, never concurrently with USN SQL.
    published,err:=session.Publish(ctx,captureState.verify)
    if err!=nil{return fmt.Errorf("FI P7: five SQL family publication rejected: %w",err)}
    if published.SourceRows!=records||published.SourceBytes!=bytes{
        return errors.New("FI P7: publication result differs from signed batches")
    }
    publishElapsed:=time.Since(publishStarted)
    committedSource,committedTyped,peakBytes,families:=session.sink.Stats()
    if committedSource!=records||committedTyped!=records{
        return errors.New("FI P7: post-publication five-writer accounting changed")
    }
    for f,l:=range session.sink.lanes{
        pg,ok:=l.writer.(*privateP7PGFamily)
        if !ok||pg.totalRecords!=families[f]{
            return fmt.Errorf("FI P7: dedicated SQL writer %d lost typed rows",f)
        }
        fmt.Printf("FI P7 SQL FAMILY COMMITTED window=%d family=%s pg_backend=%d records=%d handoffs=%d sql_time=%s complete=true\n",
            index,privateP6FamilyNames[f],pg.conn.PgConn().PID(),pg.totalRecords,
            pg.totalHandoffs,pg.totalElapsed)
    }
    fmt.Printf("FI P7 PRIVATE STAGE PROFILE index=%d records=%d source_stage=%s p5_signed_ingest=%s five_writer_publish=%s total=%s max_queued_bytes=%d\n",
        index,records,sourceStageElapsed,ingestElapsed,publishElapsed,
        time.Since(started),peakBytes)
    fileWriter,ok:=session.sink.lanes[privateP6File].writer.(*privateP7PGFamily)
    if !ok||fileWriter.ntfsTiming==nil {
        return errors.New("FI P7: dedicated File SQL writer's native validation proof missing")
    }
    native:=fileWriter.ntfsTiming
    if native.FileSourceValidated!=families[privateP6File]||
       native.FileBulkValidationReused!=families[privateP6File] {
        return fmt.Errorf("FI P7: native File SQL proof missing source=%d reuse=%d committed=%d",
            native.FileSourceValidated,native.FileBulkValidationReused,families[privateP6File])
    }
    fmt.Printf("FI P7 FILE PROOF VERIFIED index=%d source_validated=%d bulk_reused=%d all_native=true\n",
        index,native.FileSourceValidated,native.FileBulkValidationReused)
    fmt.Printf("FI P7 REAL TYPED WINDOW index=%d records=%d bytes=%d sql_writers=5 signed_batches=%d file_validated=%d security_fields=%d ingest=%s total=%s\n",
        index,records,bytes,len(batchIDs),published.FileValidated,
        published.SecurityFields,ingestElapsed,time.Since(started))
    fmt.Printf("FI REAL TYPED WINDOW index=%d records=%d sql_writers=5 security_fields=%d ntfs_file_validated=%d\n",
        index,records,published.SecurityFields,published.FileValidated)
    return nil
}

 // privateP7MaterializeSignedWindow is an intentional hard boundary:
 // the authenticated deferred verified-cache mode may persist a signed
 // artifact checkpoint WITHOUT allocating window files. P7's durable
 // pending-source ledger scans physical signed files, so it MUST create
 // and independently hash-check its own private window before any SQL.
 // Never touch the cached source batch paths or bypass hash checking.
func privateP7MaterializeSignedWindow(ctx context.Context,g *PreparedGeneration,
    limits BacklogWindowLimits,index int,privateRoot string,
    d BacklogCheckpointDescriptor)(string,error){
    if ctx==nil||g==nil||privateRoot==""||index<1 {
        return "",errors.New("FI P7: materialized source window requires signed nonseed descriptor")
    }
    desc,err:=DescribeBacklogWindows(g,limits)
    if err!=nil{return "",err}
    if index>=len(desc)||desc[index]!=d{
        return "",errors.New("FI P7: signed W512 descriptor changed before physical source staging")
    }
    // The exact lower-level materializer cannot skip its filesystem copy
    // in the original deferred-materialization wrapper. No stage reuse of
    // caller-owned custody files is permitted (reuseStage=false).
    dir,err:=materializeBacklogWindow(ctx,g,limits,index,privateRoot,false)
    if err!=nil{
        return "",fmt.Errorf("FI P7: exact private signed window materialization: %w",err)
    }
    expected:=filepath.Join(privateRoot,"receipt-"+d.ReceiptSHA256,
        fmt.Sprintf("window-%08d",index))
    if dir!=expected{
        return "",fmt.Errorf("FI P7: signed window escaped private namespace got=%q expected=%q",
            dir,expected)
    }
    if err:=VerifyMaterializedBacklogWindow(ctx,g,limits,index,privateRoot);err!=nil{
        return "",fmt.Errorf("FI P7: exact physical source/manifest SHA verification: %w",err)
    }
    fmt.Printf("FI P7 PRIVATE MATERIALIZED WINDOW VERIFIED index=%d signed_batches=%d records=%d bytes=%d original_cache_unchanged=true\n",
        index,d.EndBatch-d.StartBatch,d.EndRecord-d.StartRecord,d.DataBytes)
    return dir,nil
}

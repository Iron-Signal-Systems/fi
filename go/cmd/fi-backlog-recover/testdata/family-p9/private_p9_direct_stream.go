// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// EXPERIMENTAL C220 CLONE ONLY. Direct P6 family stream with P7's five
// independent SQL writers. A verified-cache manifest is authenticated once,
// and the original signed JSONL is decoded exactly once by ingestSourceBatch.
// No materialized window, pending_source_record, source_window or new artifact
// SQL receipt is written for processed windows. Five bounded family queues and
// the P5 preparation pool survive every W512 reporting boundary. A capacity
// limit, File->USN dependency, or end-of-run flush is the only drain trigger.
// A failed multi-window attempt MUST discard the complete private clone.
package recordingest

import (
    "bytes"
    "context"
    "crypto/subtle"
    "encoding/binary"
    "encoding/hex"
    "errors"
    "fmt"
    "os"
    "path/filepath"
    "strconv"
    "time"

    "github.com/Iron-Signal-Systems/fi/go/internal/spool"
    "github.com/jackc/pgx/v5"
)

func privateP9DirectSelected() bool {
    return os.Getenv("FI_W512_P9_DIRECT_STREAM")=="1" &&
        os.Getenv("FI_W512_P8_REUSE")=="" && privateP7FiveWriterSelected()
}

func privateP9RunEnd(start,n int) (int,error) {
    if n<=start{return 0,errors.New("FI P9: empty private W512 stream")}
    stop:=os.Getenv("FI_W512_P9_STOP_WINDOWS")
    if stop=="" {return n,nil}
    count,err:=strconv.Atoi(stop)
    if err!=nil||count<1||count>n-start {
        return 0,errors.New("FI P9: explicit private test-stop window bound invalid")
    }
    return start+count,nil
}

func privateP9CacheBatch(ctx context.Context,cacheDir string,
    g *PreparedGeneration,i int)(PreparedBatch,error){
    var empty PreparedBatch
    if err:=ctx.Err();err!=nil{return empty,err}
    if i<0||i>=len(g.Batches){return empty,errors.New("FI P9: signed batch out of range")}
    b:=g.Batches[i]
    raw,err:=backlogVerifiedCacheManifest(cacheDir,i,b.ManifestSHA256,1<<20)
    if err!=nil{return empty,fmt.Errorf("FI P9: signed manifest %d: %w",i,err)}
    m,err:=spool.DecodeManifest(bytes.NewReader(raw))
    if err!=nil{return empty,fmt.Errorf("FI P9: signed manifest decoding %d: %w",i,err)}
    if m.BatchID!=b.BatchID || m.DataFile!=b.DataArtifactName ||
        m.Version!=b.Manifest.Version || m.DataSHA256!=b.Manifest.DataSHA256 ||
        m.DataBytes!=b.Manifest.DataBytes ||
        m.RecordCount!=b.Manifest.RecordCount ||
        m.TargetBatchSize!=b.Manifest.TargetBatchSize {
        return empty,fmt.Errorf("FI P9: signed manifest mismatch batch=%d",i)
    }
    b.DataPath=backlogCacheBatchData(cacheDir,i)
    b.ManifestRawBytes=raw
    // Data bytes are verified once by the original ingestSourceBatch path;
    // do not hash/copy/read the whole batch a second time here.
    return b,nil
}

func privateP9ReadBatchIDs(ctx context.Context,conn *pgx.Conn,
    g *PreparedGeneration,d BacklogCheckpointDescriptor)([]int64,error){
    tx,err:=conn.BeginTx(ctx,pgx.TxOptions{AccessMode:pgx.ReadOnly})
    if err!=nil{return nil,err}
    defer tx.Rollback(context.Background())
    shadow:=privateProjectionTx{Tx:tx}
    id,found,err:=lookupRecordedGeneration(ctx,shadow,
        d.SourceID,d.GenerationID,g.Receipt.TransferSHA256,g.ReceiptSHA256)
    if err!=nil{return nil,err}
    if !found||id<=0 {return nil,errors.New("FI P9: preexisting original source generation missing")}
    ids,err:=lookupBacklogShadowBatchIDs(ctx,shadow,id,g.Batches[d.StartBatch:d.EndBatch])
    if err!=nil{return nil,err}
    if len(ids)!=d.EndBatch-d.StartBatch{return nil,errors.New("FI P9: source batch ID map incomplete")}
    return ids,nil
}

func privateP9VerifyPrivatePrerequisites(ctx context.Context,
    conn *pgx.Conn,g *PreparedGeneration,descriptors []BacklogCheckpointDescriptor,
    start,end int)error{
    if start<1||end<=start||end>len(descriptors){return errors.New("FI P9: invalid selected signed windows")}
    var existing int64
    if err:=conn.QueryRow(ctx,`SELECT count(*) FROM fi_recovery.typed_window
WHERE window_index >= $1`,start).Scan(&existing);err!=nil{return err}
    if existing!=0{return errors.New("FI P9: private SQL clone already has typed windows at or past start")}
    if err:=conn.QueryRow(ctx,`SELECT count(*) FROM fi_recovery.source_window
WHERE window_index >= $1`,start).Scan(&existing);err!=nil{return err}
    if existing!=0{return errors.New("FI P9: duplicate source stage exists; use a fresh isolated seed")}
    if err:=conn.QueryRow(ctx,`SELECT count(*) FROM fi_recovery.verified_artifact_window
WHERE window_index >= $1`,start).Scan(&existing);err!=nil{return err}
    if existing!=0{return errors.New("FI P9: duplicate artifact stage exists; use a fresh isolated seed")}
    var defaultPart bool
    if err:=conn.QueryRow(ctx,`
SELECT EXISTS(SELECT 1 FROM pg_inherits i JOIN pg_class c ON c.oid=i.inhrelid
WHERE i.inhparent='fi_recovery_projection.windows_security_event_field'::regclass
AND c.relname='windows_security_event_field_continuous_default'
AND pg_get_expr(c.relpartbound,c.oid)='DEFAULT')`).Scan(&defaultPart);err!=nil{return err}
    if !defaultPart{return errors.New("FI P9: private direct Security-field DEFAULT partition not installed")}
    // W0 contains the existing signed seed; no P9 record can alter it.
    seed:=descriptors[start-1]
    want,err:=hex.DecodeString(seed.DigestSHA256)
    if err!=nil{return err}
    receipt,err:=hex.DecodeString(seed.ReceiptSHA256)
    if err!=nil{return err}
    var got []byte
    if err:=conn.QueryRow(ctx,`SELECT descriptor_sha256 FROM fi_recovery.typed_window
WHERE receipt_sha256=$1 AND window_index=$2`,receipt,start-1).Scan(&got);err!=nil{return err}
    if subtle.ConstantTimeCompare(got,want)!=1{
        return errors.New("FI P9: signed starting checkpoint differs from preexisting seed")
    }
    return nil
}

// Only the original typed-window marker remains. It certifies complete
// signed source parent/child writes after P6 queues and all five P7 writers
// have ACKed, and after original relational/capture/FK checks pass.
// The previous P6 pending_source_record duplicate table is never populated.
func privateP9CommitTypedWindows(ctx context.Context,conn *pgx.Conn,
    g *PreparedGeneration,ds []BacklogCheckpointDescriptor,
    start,end int)error{
    tx,err:=conn.Begin(ctx)
    if err!=nil{return err}
    defer tx.Rollback(context.Background())
    receipt,err:=hex.DecodeString(ds[start].ReceiptSHA256)
    if err!=nil{return err}
    if _,err=tx.Exec(ctx,"SELECT pg_advisory_xact_lock($1::bigint)",
        int64(binary.BigEndian.Uint64(receipt[:8])));err!=nil{return err}
    var accepted,authoritative bool
    if err:=tx.QueryRow(ctx,`SELECT EXISTS(SELECT 1 FROM fi.ingest_journal WHERE outcome='Accepted'),
EXISTS(SELECT 1 FROM fi.recorded_generation WHERE source_id=$1 AND generation_id=$2)`,
        ds[start].SourceID,ds[start].GenerationID).Scan(&accepted,&authoritative);err!=nil{return err}
    if accepted||authoritative{return errors.New("FI P9: authoritative or Accepted state detected in disposable clone")}
    shadow:=privateProjectionTx{Tx:tx}
    shadowID,found,err:=lookupRecordedGeneration(ctx,shadow,
        ds[start].SourceID,ds[start].GenerationID,
        g.Receipt.TransferSHA256,g.ReceiptSHA256)
    if err!=nil{return err}
    if !found||shadowID<=0{return errors.New("FI P9: private shadow generation missing")}
    for i:=start;i<end;i++{
        d:=ds[i]
        if err:=ctx.Err();err!=nil{return err}
        digest,err:=hex.DecodeString(d.DigestSHA256)
        if err!=nil{return err}
        previous,err:=hex.DecodeString(d.PreviousDigestSHA256)
        if err!=nil{return err}
        var prior []byte
        if err=tx.QueryRow(ctx,`SELECT descriptor_sha256 FROM fi_recovery.typed_window
WHERE receipt_sha256=$1 AND window_index=$2`,receipt,i-1).Scan(&prior);err!=nil{return err}
        if subtle.ConstantTimeCompare(prior,previous)!=1{
            return fmt.Errorf("FI P9: signed window %d predecessor changed",i)
        }
        if err=verifyBacklogShadowWindowCounts(ctx,shadow,shadowID,
            g.Batches[d.StartBatch:d.EndBatch],int64(d.EndRecord-d.StartRecord),
            int64(d.DataBytes));err!=nil {
            return fmt.Errorf("FI P9: window %d source/child count proof: %w",i,err)
        }
        if err=verifyBacklogWindowProjectionCoverage(ctx,shadow,shadowID,
            g.Batches[d.StartBatch:d.EndBatch]);err!=nil{
            return fmt.Errorf("FI P9: window %d relational graph proof: %w",i,err)
        }
        if i==len(ds)-1 {
            if err=verifyBacklogUSNCapturesComplete(ctx,shadow,shadowID);err!=nil{return err}
        }
        if _,err=tx.Exec(ctx,`INSERT INTO fi_recovery.typed_window
(receipt_sha256,window_index,descriptor_sha256,shadow_generation_id,
start_batch,end_batch,committed_records,committed_bytes,ingest_version)
VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
            receipt,i,digest,shadowID,d.StartBatch,d.EndBatch,
            int64(d.EndRecord-d.StartRecord),int64(d.DataBytes),IngestVersion);err!=nil{return err}
    }
    return tx.Commit(ctx)
}

func privateP9VerifyComplete(ctx context.Context,conn *pgx.Conn,
    g *PreparedGeneration,ds []BacklogCheckpointDescriptor,
)(BacklogGenerationVerification,error){
    var empty BacklogGenerationVerification
    tx,err:=conn.BeginTx(ctx,pgx.TxOptions{IsoLevel:pgx.RepeatableRead,
        AccessMode:pgx.ReadOnly})
    if err!=nil{return empty,err}
    defer tx.Rollback(context.Background())
    id,found,err:=lookupRecordedGeneration(ctx,privateProjectionTx{Tx:tx},
        ds[0].SourceID,ds[0].GenerationID,g.Receipt.TransferSHA256,g.ReceiptSHA256)
    if err!=nil{return empty,err}
    if !found{return empty,errors.New("FI P9: final private shadow generation missing")}
    var count,total int64
    if err=tx.QueryRow(ctx,`SELECT count(*),coalesce(sum(committed_records),0)
FROM fi_recovery.typed_window WHERE receipt_sha256=decode($1,'hex')`,
        ds[0].ReceiptSHA256).Scan(&count,&total);err!=nil{return empty,err}
    if count!=int64(len(ds))||uint64(total)!=g.Receipt.RecordCount{
        return empty,errors.New("FI P9: final signed typed marker count/records incomplete")
    }
    shadow:=privateProjectionTx{Tx:tx}
    if err=verifyGenerationProjectionCoverage(ctx,shadow,id);err!=nil{return empty,err}
    if err=verifyBacklogUSNCapturesComplete(ctx,shadow,id);err!=nil{return empty,err}
    if err=tx.Commit(ctx);err!=nil{return empty,err}
    return BacklogGenerationVerification{
        SourceID:ds[0].SourceID,GenerationID:ds[0].GenerationID,
        ReceiptSHA256:ds[0].ReceiptSHA256,ShadowGenerationID:id,
        Windows:len(ds),Records:g.Receipt.RecordCount,
        DataBytes:g.Receipt.DataBytes},nil
}

func privateP9RecoverDirect(ctx context.Context,reader,control *pgx.Conn,
    g *PreparedGeneration,limits BacklogWindowLimits,
    privateRoot string,startWindow int,cacheRoot string,
    ds []BacklogCheckpointDescriptor,report func(BacklogContinuousProgress),
)(BacklogGenerationVerification,error){
    var empty BacklogGenerationVerification
    if !privateP9DirectSelected()||ctx==nil||reader==nil||control==nil||
        reader==control||g==nil||privateRoot==""||len(ds)<2{
        return empty,errors.New("FI P9: isolated direct five-family stream not selected")
    }
    end,err:=privateP9RunEnd(startWindow,len(ds))
    if err!=nil{return empty,err}
    dsn,dataDir:=os.Getenv("FI_W512_P7_SQL_DSN"),os.Getenv("FI_W512_P7_EXPECTED_PGDATA")
    if dsn==""||dataDir==""{return empty,errors.New("FI P9: clone DSN and exact PGDATA required")}
    if _,err=privateP7VerifyCloneConnection(ctx,control,dataDir);err!=nil{return empty,err}
    if _,err=privateP7VerifyCloneConnection(ctx,reader,dataDir);err!=nil{return empty,err}
    if err=privateP9VerifyPrivatePrerequisites(ctx,control,g,ds,startWindow,end);err!=nil{return empty,err}
    cacheDir,err:=backlogVerifiedCacheOpen(cacheRoot,g.ReceiptSHA256,
        g.Receipt.TransferSHA256,g.Receipt.BatchCount,g.Receipt.RecordCount,g.Receipt.DataBytes)
    if err!=nil{return empty,err}
    started:=time.Now()
    usn:=newUSNCaptureState(ds[0].SourceID,ds[0].GenerationID)
    ctx=context.WithValue(ctx,usnCaptureContextKey{},usn)
    ctx=context.WithValue(ctx,ntfsStageTimingContextKey{},&ntfsStageTimingCounters{})
    ctx=context.WithValue(ctx,backlogUSNCrossWindowContextKey{},true)
    ctx=context.WithValue(ctx,usnTimingContextKey{},&usnTimingCounters{})
    // Exactly one P5 worker pool and one P6 family buffer set for the
    // entire selected stream: no W512/K32/signed-batch flush.
    pool,err:=newPrivateP5Pool(ctx,startWindow)
    if err!=nil{return empty,err}
    defer pool.Close()
    ctx=context.WithValue(ctx,privateP5PoolContextKey{},pool)
    sink,err:=newPrivateP7PostgresFiveWriter(ctx,dsn,ds[0].SourceID,"",dataDir)
    if err!=nil{return empty,err}
    defer sink.Close(context.Background())
    buffers,err:=newPrivateP6Buffers(startWindow,sink)
    if err!=nil{return empty,err}
    ctx=context.WithValue(ctx,privateP6WindowContextKey{},buffers)
    var profile ingestStageProfile
    profile.coverageBuffer=newSecurityCoverageBulkState(&profile)
    var totalRows,totalBytes int64
    perWindow:=make([]time.Duration,end-startWindow)
    for i:=startWindow;i<end;i++{
        d:=ds[i]
        tick:=time.Now()
        if err:=ctx.Err();err!=nil{return empty,err}
        ids,err:=privateP9ReadBatchIDs(ctx,control,g,d)
        if err!=nil{return empty,err}
        readTx,err:=control.BeginTx(ctx,pgx.TxOptions{AccessMode:pgx.ReadOnly})
        if err!=nil{return empty,err}
        windowRecords,windowBytes:=int64(0),int64(0)
        for j,sourceBatchID:=range ids {
            global:=d.StartBatch+j
            batch,readErr:=privateP9CacheBatch(ctx,cacheDir,g,global)
            if readErr!=nil { _=readTx.Rollback(context.Background());return empty,readErr}
            signedCtx:=privateP7CanonicalSignedBatchContext(ctx,global)
            n,readErr:=ingestSourceBatch(signedCtx,privateProjectionTx{Tx:readTx},
                d.SourceID,sourceBatchID,batch,&profile)
            if readErr!=nil { _=readTx.Rollback(context.Background());
                return empty,fmt.Errorf("FI P9: canonical signed batch %d: %w",global,readErr)}
            windowRecords+=n
            windowBytes+=batch.Manifest.DataBytes
        }
        if err:=readTx.Rollback(ctx);err!=nil{return empty,err}
        if windowRecords!=int64(d.EndRecord-d.StartRecord)||
            windowBytes!=int64(d.DataBytes){
            return empty,fmt.Errorf("FI P9: window %d signed counts rows=%d bytes=%d",i,windowRecords,windowBytes)
        }
        perWindow[i-startWindow]=time.Since(tick)
        totalRows+=windowRecords
        totalBytes+=windowBytes
        fmt.Printf("FI P9 DIRECT READ window=%d records=%d bytes=%d signed_batches=%d elapsed=%s pending_source_rows_added=0 artifact_copies=0\n",
            i,windowRecords,windowBytes,d.EndBatch-d.StartBatch,perWindow[i-startWindow])
    }
    ingestElapsed:=time.Since(started)
    // Only actual stream completion (or a capacity/dependency handoff)
    // drains pending family buffers. SQL receipts are real committed parents
    // and children; no separate source/record staging exists.
    if err=buffers.Finish(ctx);err!=nil{return empty,fmt.Errorf("FI P9: final five-family SQL drain: %w",err)}
    if end==len(ds){
        if err=usn.verify();err!=nil{return empty,fmt.Errorf("FI P9: final capture integrity: %w",err)}
    }
    s,committed,peak,families:=sink.Stats()
    if s!=totalRows||committed!=totalRows{
        return empty,fmt.Errorf("FI P9: signed parent/family mismatch source=%d typed=%d expected=%d",
            s,committed,totalRows)
    }
    fmt.Printf("FI P9 DIRECT FIVE WRITERS PASS records=%d signed_bytes=%d sql_committed=%d peak_queued_bytes=%d security=%d file=%d coverage=%d usn=%d other=%d\n",
        totalRows,totalBytes,committed,peak,families[0],families[1],families[2],families[3],families[4])
    if err=privateP9CommitTypedWindows(ctx,control,g,ds,startWindow,end);err!=nil{
        return empty,fmt.Errorf("FI P9: final typed-only SQL markers: %w",err)
    }
    elapsed:=time.Since(started)
    fmt.Printf("FI P9 DIRECT MULTIWINDOW COMMIT PASS start=%d windows=%d records=%d elapsed=%s ingestion=%s staging_reads=0 source_receipt_writes=0 artifact_receipt_writes=0 capacities_cross_windows=true\n",
        startWindow,end-startWindow,totalRows,elapsed,ingestElapsed)
    // Emit durable progress only after the final SQL transaction commits.
    // This also lets the C220 controlled-stop callback cancel AFTER proof.
    for i:=startWindow;i<end;i++{
        duration:=time.Duration(0)
        if i==end-1 {duration=elapsed}
        if report!=nil{
            report(BacklogContinuousProgress{
                BatchesSeen:ds[i].EndBatch,TotalBatches:len(g.Batches),
                RecordsInspected:uint64(totalRows),WindowCommitted:i,
                WindowRecords:ds[i].EndRecord-ds[i].StartRecord,
                TotalWindows:len(ds),RecordsDurable:ds[i].EndRecord,
                TypedDuration:duration,WindowDuration:duration,
                Elapsed:elapsed,
            })
        }
    }
    if end!=len(ds){
        if err:=ctx.Err();err!=nil{return empty,err}
        return empty,errors.New("FI P9: selected prefix complete; caller did not stop at committed private checkpoint")
    }
    return privateP9VerifyComplete(ctx,control,g,ds)
}

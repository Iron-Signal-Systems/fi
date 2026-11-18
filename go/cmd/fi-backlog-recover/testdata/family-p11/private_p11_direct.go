// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// P11 clean P6 direct-stream experiment. Receives the already admitted
// verified cache, checks each original manifest and its data exactly once,
// decodes the canonical signed record once, and hands it straight to the
// existing P6 buffers/source parent/family SQL. No window materialization,
// P7 bridge, pending source staging or extra source/artifact checkpoint.
package recordingest

import (
    "bufio"
    "bytes"
    "context"
    "crypto/sha256"
    "crypto/subtle"
    "encoding/hex"
    "errors"
    "fmt"
    "io"
    "os"
    "strconv"
    "time"

    "github.com/Iron-Signal-Systems/fi/go/internal/spool"
    "github.com/jackc/pgx/v5"
)

func privateP11StopIndex(start,total int)(int,error){
    if start<1||start>=total{return 0,errors.New("FI P11: invalid direct starting checkpoint")}
    requested:=os.Getenv("FI_W512_P11_STOP_WINDOWS")
    if requested==""{return total,nil}
    n,err:=strconv.Atoi(requested)
    if err!=nil||n<1||n>total-start{return 0,errors.New("FI P11: invalid test window limit")}
    return start+n,nil
}

func privateP11SignedCacheBatch(ctx context.Context,cacheDir string,
    g *PreparedGeneration,i int)(PreparedBatch,error){
    var empty PreparedBatch
    if err:=ctx.Err();err!=nil{return empty,err}
    if i<0||i>=len(g.Batches){return empty,errors.New("FI P11: signed batch index out of range")}
    b:=g.Batches[i]
    raw,err:=backlogVerifiedCacheManifest(cacheDir,i,b.ManifestSHA256,1<<20)
    if err!=nil{return empty,fmt.Errorf("FI P11: signed manifest %d: %w",i,err)}
    manifest,err:=spool.DecodeManifest(bytes.NewReader(raw))
    if err!=nil{return empty,fmt.Errorf("FI P11: signed manifest %d decode: %w",i,err)}
    if manifest.BatchID!=b.BatchID||manifest.DataFile!=b.DataArtifactName||
        manifest.Version!=b.Manifest.Version||
        manifest.DataSHA256!=b.Manifest.DataSHA256||
        manifest.DataBytes!=b.Manifest.DataBytes||
        manifest.RecordCount!=b.Manifest.RecordCount||
        manifest.TargetBatchSize!=b.Manifest.TargetBatchSize {
        return empty,fmt.Errorf("FI P11: original signed batch %d manifest changed",i)
    }
    b.ManifestRawBytes=raw
    b.DataPath=backlogCacheBatchData(cacheDir,i)
    return b,nil
}

func privateP11SourceBatchIDs(ctx context.Context,reader *pgx.Conn,
    g *PreparedGeneration,d BacklogCheckpointDescriptor)([]int64,error){
    tx,err:=reader.BeginTx(ctx,pgx.TxOptions{AccessMode:pgx.ReadOnly})
    if err!=nil{return nil,err}
    defer tx.Rollback(context.Background())
    shadow:=privateProjectionTx{Tx:tx}
    id,ok,err:=lookupRecordedGeneration(ctx,shadow,
        d.SourceID,d.GenerationID,g.Receipt.TransferSHA256,g.ReceiptSHA256)
    if err!=nil{return nil,err}
    if !ok||id<=0{return nil,errors.New("FI P11: original signed shadow generation missing")}
    ids,err:=lookupBacklogShadowBatchIDs(ctx,shadow,id,
        g.Batches[d.StartBatch:d.EndBatch])
    if err!=nil{return nil,err}
    if len(ids)!=d.EndBatch-d.StartBatch {
        return nil,errors.New("FI P11: original source batch identity lookup incomplete")
    }
    return ids,nil
}

// Original P5 pool and its bounded family dispatch are shared across ALL
// signed batches and BOTH W512 reporting windows, not reconstructed at a
// signed-batch/window boundary. The caller owns one reader and SHA-256 hasher.
type privateP11PrepTotals struct {
    batches int64
    records int64
    readerTime time.Duration
    workerTime time.Duration
    writerWait time.Duration
}

// Consume each P5 prepared result in exact original signed order, while the
// existing P6 buffers independently flush families at capacity/dependency.
// Kept separate for tests that prove a single streaming source and retained
// five-family P5 workers without needing PostgreSQL.
func privateP11ConsumePrepared(ctx context.Context,pool *privateP5Pool,
    reader *bufio.Reader,prepare privateHeaderPrepareFunc,
    accept func(privateParallelLine)error,totals *privateP11PrepTotals,
)(int64,int64,error){
    if ctx==nil||pool==nil||reader==nil||prepare==nil||accept==nil||totals==nil{
        return 0,0,errors.New("FI P11: P5 family preparation stream inputs missing")
    }
    stream,err:=pool.newStream(ctx,reader,prepare)
    if err!=nil{return 0,0,err}
    defer stream.Close()
    var ordinal,bytesSeen int64
    for{
        if err:=ctx.Err();err!=nil{return ordinal,bytesSeen,err}
        line,ok:=stream.Next()
        if !ok{break}
        if line.readErr!=nil{return ordinal,bytesSeen,fmt.Errorf("FI P11: P5 signed reader: %w",line.readErr)}
        if line.prepareErr!=nil{return ordinal,bytesSeen,fmt.Errorf("FI P11: P5 family preparation: %w",line.prepareErr)}
        if line.ordinal!=ordinal+1{return ordinal,bytesSeen,errors.New("FI P11: P5 reordered or skipped signed source ordinal")}
        ordinal++
        bytesSeen+=int64(len(line.raw))
        if err:=accept(line);err!=nil{return ordinal,bytesSeen,err}
    }
    totals.batches++
    totals.records+=ordinal
    totals.readerTime+=stream.readerTime
    totals.workerTime+=stream.workerTime
    totals.writerWait+=stream.waits
    return ordinal,bytesSeen,nil
}

func privateP11ReadSignedBatch(ctx context.Context,sourceID string,
    index int,sourceBatchID int64,batch PreparedBatch,
    buffers *privateP6Buffers,pool *privateP5Pool,
    totals *privateP11PrepTotals)(int64,int64,error){
    f,err:=os.Open(batch.DataPath)
    if err!=nil{return 0,0,err}
    defer f.Close()
    if st,err:=f.Stat();err!=nil||!st.Mode().IsRegular()||
        st.Size()!=batch.Manifest.DataBytes{
        return 0,0,fmt.Errorf("FI P11: signed data file bytes changed batch=%d: %v",index,err)
    }
    // TeeReader hashes bytes while the existing P5 block reader consumes
    // them. One physical read, one batch SHA-256 and one family preparer.
    hasher:=sha256.New()
    reader:=bufio.NewReaderSize(io.TeeReader(f,hasher),128<<10)
    ordinal,bytesSeen,err:=privateP11ConsumePrepared(
        ctx,pool,reader,privateHeaderFirstPrepare,
        func(line privateParallelLine)error{
            if line.source.RecordBytes!=len(line.raw)||
                len(line.source.RawRecordBytes)!=len(line.raw)||
                line.source.Record.RecordKind!=line.headerKind {
                return fmt.Errorf("FI P11: P5 signed family preparation changed original record at %d/%d",
                    index,line.ordinal)
            }
            return buffers.Add(ctx,privateP6Record{
                signedBatchIndex:index,sourceBatchID:sourceBatchID,ordinal:line.ordinal,
                prepared:line.source,selectedSinglePass:line.selected,
                singlePassSecurity:line.security,
            })
        },totals)
    if err!=nil{return ordinal,bytesSeen,err}
    if ordinal!=int64(batch.Manifest.RecordCount)||
        bytesSeen!=batch.Manifest.DataBytes||
        hex.EncodeToString(hasher.Sum(nil))!=batch.Manifest.DataSHA256{
        return ordinal,bytesSeen,fmt.Errorf("FI P11: original signed batch %d SHA/count/bytes invalid",index)
    }
    return ordinal,bytesSeen,nil
}

func privateP11MarkTyped(ctx context.Context,writer *pgx.Conn,
    g *PreparedGeneration,ds []BacklogCheckpointDescriptor,start,end int)error{
    tx,err:=writer.Begin(ctx)
    if err!=nil{return err}
    defer tx.Rollback(context.Background())
    shadow:=privateProjectionTx{Tx:tx}
    id,ok,err:=lookupRecordedGeneration(ctx,shadow,
        ds[0].SourceID,ds[0].GenerationID,
        g.Receipt.TransferSHA256,g.ReceiptSHA256)
    if err!=nil{return err}
    if !ok{return errors.New("FI P11: missing original shadow generation")}
    var already int64
    if err=tx.QueryRow(ctx,`SELECT count(*) FROM fi_recovery.typed_window WHERE window_index >= $1`,
        start).Scan(&already);err!=nil{return err}
    if already!=0{return errors.New("FI P11: destination already has typed markers")}
    receipt,err:=hex.DecodeString(ds[0].ReceiptSHA256)
    if err!=nil||len(receipt)!=32{return errors.New("FI P11: invalid signed generation receipt")}
    for i:=start;i<end;i++{
        d:=ds[i]
        if err=verifyBacklogShadowWindowCounts(ctx,shadow,id,g.Batches[d.StartBatch:d.EndBatch],
            int64(d.EndRecord-d.StartRecord),int64(d.DataBytes));err!=nil{
            return fmt.Errorf("FI P11: signed window %d source count check: %w",i,err)
        }
        if err=verifyBacklogWindowProjectionCoverage(ctx,shadow,id,
            g.Batches[d.StartBatch:d.EndBatch]);err!=nil{
            return fmt.Errorf("FI P11: signed window %d relational check: %w",i,err)
        }
        digest,err:=hex.DecodeString(d.DigestSHA256)
        if err!=nil||len(digest)!=32{return errors.New("FI P11: signed descriptor hash invalid")}
        previous,err:=hex.DecodeString(d.PreviousDigestSHA256)
        if err!=nil||len(previous)!=32{return errors.New("FI P11: signed predecessor hash invalid")}
        var preceding []byte
        if err=tx.QueryRow(ctx,`SELECT descriptor_sha256 FROM fi_recovery.typed_window
WHERE receipt_sha256=$1 AND window_index=$2`,receipt,i-1).Scan(&preceding);err!=nil{return err}
        if subtle.ConstantTimeCompare(preceding,previous)!=1{
            return fmt.Errorf("FI P11: signed predecessor mismatches window %d",i)
        }
        if _,err=tx.Exec(ctx,`INSERT INTO fi_recovery.typed_window
(receipt_sha256,window_index,descriptor_sha256,shadow_generation_id,
start_batch,end_batch,committed_records,committed_bytes,ingest_version)
VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
            receipt,i,digest,id,d.StartBatch,d.EndBatch,
            int64(d.EndRecord-d.StartRecord),int64(d.DataBytes),IngestVersion);err!=nil{return err}
    }
    // Only when this is the complete generation, not a test prefix.
    if end==len(ds){
        if err=verifyGenerationProjectionCoverage(ctx,shadow,id);err!=nil{return err}
    }
    return tx.Commit(ctx)
}

func privateP11RecoverDirect(ctx context.Context,reader,writer *pgx.Conn,
    g *PreparedGeneration,limits BacklogWindowLimits,
    privateRoot string,startWindow int,cacheRoot string,
    ds []BacklogCheckpointDescriptor,report func(BacklogContinuousProgress),
)(BacklogGenerationVerification,error){
    var empty BacklogGenerationVerification
    if !privateP11Enabled()||ctx==nil||g==nil||reader==nil||writer==nil||
        len(ds)<2||reader==writer{return empty,errors.New("FI P11: original P6 direct clone not selected")}
    end,err:=privateP11StopIndex(startWindow,len(ds))
    if err!=nil{return empty,err}
    var prevDigest []byte
    receipt,err:=hex.DecodeString(ds[startWindow-1].ReceiptSHA256)
    if err!=nil{return empty,err}
    if err=writer.QueryRow(ctx,`SELECT descriptor_sha256 FROM fi_recovery.typed_window
WHERE receipt_sha256=$1 AND window_index=$2`,receipt,startWindow-1).Scan(&prevDigest);err!=nil{return empty,err}
    want,err:=hex.DecodeString(ds[startWindow-1].DigestSHA256)
    if err!=nil||subtle.ConstantTimeCompare(prevDigest,want)!=1{
        return empty,errors.New("FI P11: existing signed seed checkpoint does not match")
    }
    // Keep the original P6 cross-batch USN and File identity semantics.
    // No reset or forced buffer flush at a W512 reporting boundary.
    usn:=newUSNCaptureState(ds[0].SourceID,ds[0].GenerationID)
    ctx=context.WithValue(ctx,usnCaptureContextKey{},usn)
    ctx=context.WithValue(ctx,usnTimingContextKey{},&usnTimingCounters{})
    ctx=context.WithValue(ctx,backlogUSNCrossWindowContextKey{},true)
    dsn,pgdata:=os.Getenv("FI_W512_P11_SQL_DSN"),os.Getenv("FI_W512_P11_EXPECTED_PGDATA")
    sink,err:=newPrivateP11FiveSQL(ctx,dsn,pgdata,ds[0].SourceID)
    if err!=nil{return empty,err}
    defer sink.Close()
    cacheDir,err:=backlogVerifiedCacheOpen(cacheRoot,g.ReceiptSHA256,
        g.Receipt.TransferSHA256,g.Receipt.BatchCount,g.Receipt.RecordCount,g.Receipt.DataBytes)
    if err!=nil{return empty,err}
    buffers,err:=newPrivateP6Buffers(startWindow,sink)
    if err!=nil{return empty,err}
    // One original P5 adaptive family worker pool for the whole run.
    // Do not reset its workers, credits, or P6 SQL-ready buffers at W512.
    pool,err:=newPrivateP5Pool(ctx,startWindow)
    if err!=nil{return empty,fmt.Errorf("FI P11: P5 persistent preparation pool: %w",err)}
    defer pool.Close()
    var prepTotals privateP11PrepTotals
    fmt.Printf("FI P11 P5 PREP POOL START lanes=5 min=2 max=16 persistent_across_signed_batches=true persistent_across_W512=true\n")
    started:=time.Now()
    var totalRows,totalBytes int64
    for wi:=startWindow;wi<end;wi++{
        d:=ds[wi]
        if err=ctx.Err();err!=nil{return empty,err}
        ids,err:=privateP11SourceBatchIDs(ctx,reader,g,d)
        if err!=nil{return empty,err}
        var seen,seenBytes int64
        for offset,id:=range ids {
            index:=d.StartBatch+offset
            b,err:=privateP11SignedCacheBatch(ctx,cacheDir,g,index)
            if err!=nil{return empty,err}
            n,bytes,err:=privateP11ReadSignedBatch(ctx,d.SourceID,index,id,b,buffers,pool,&prepTotals)
            if err!=nil{return empty,fmt.Errorf("FI P11: signed batch %d: %w",index,err)}
            seen+=n
            seenBytes+=bytes
        }
        if seen!=int64(d.EndRecord-d.StartRecord)||seenBytes!=int64(d.DataBytes){
            return empty,fmt.Errorf("FI P11: window %d signed source tally mismatched",wi)
        }
        totalRows+=seen
        totalBytes+=seenBytes
        fmt.Printf("FI P11 P6 DIRECT READ window=%d signed_batches=%d records=%d bytes=%d source_stage_rows=0 copied_artifacts=0\n",
            wi,d.EndBatch-d.StartBatch,seen,seenBytes)
    }
    // W512 is only a reporting boundary. The P6 buffers were never
    // drained or re-created inside the loop above.
    if err=buffers.Finish(ctx);err!=nil{return empty,fmt.Errorf("FI P11: P6 five-family drain: %w",err)}
    parents,children,family:=sink.Stats()
    if parents!=totalRows||children!=totalRows{
        return empty,fmt.Errorf("FI P11: source/child count mismatch source=%d typed=%d signed=%d",
            parents,children,totalRows)
    }
    if err=privateP11MarkTyped(ctx,writer,g,ds,startWindow,end);err!=nil{
        return empty,fmt.Errorf("FI P11: final signed relational marker: %w",err)
    }
    pool.Close()
    fmt.Printf("FI P11 P5 PREP COMPLETE batches=%d records=%d family_lanes=5 worker_min=2 worker_max=16 reader_time=%s parallel_worker_time_sum=%s consumer_wait=%s\n",
        prepTotals.batches,prepTotals.records,prepTotals.readerTime,
        prepTotals.workerTime,prepTotals.writerWait)
    elapsed:=time.Since(started)
    fmt.Printf("FI P11 P6 FIVE SQL PASS windows=%d records=%d bytes=%d families=5 parent=1 five_committed=%d security=%d file=%d coverage=%d usn=%d other=%d source_staging=none duration=%s\n",
        end-startWindow,totalRows,totalBytes,children,
        family[0],family[1],family[2],family[3],family[4],elapsed)
    // P11 has ONE durable marker barrier at test completion, not
    // intermediate window-barrier flushes. Report only committed state.
    if report!=nil{
        for wi:=startWindow;wi<end;wi++{
            d:=ds[wi]
            windowDuration:=time.Duration(0)
            if wi==end-1 {windowDuration=elapsed}
            report(BacklogContinuousProgress{
                BatchesSeen:d.EndBatch,TotalBatches:len(g.Batches),
                RecordsInspected:uint64(totalRows),WindowCommitted:wi,
                WindowRecords:d.EndRecord-d.StartRecord,
                TotalWindows:len(ds),RecordsDurable:d.EndRecord,
                TypedDuration:windowDuration,WindowDuration:windowDuration,
                Elapsed:elapsed,
            })
        }
    }
    // The two-window test intentionally stops after its durable private
    // prefix. Never fabricate a complete-generation acceptance.
    if end<len(ds){return empty,context.Canceled}
    verified,err:=VerifyCompleteBacklogTypedGeneration(ctx,reader,g,limits)
    if err!=nil{return empty,err}
    return verified,nil
}

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// C1 clean P6 direct-stream experiment. Receives the already admitted
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

func privateC1StopIndex(start,total int)(int,error){
    if start<1||start>=total{return 0,errors.New("FI C1: invalid direct starting checkpoint")}
    requested:=os.Getenv("FI_W512_C1_STOP_WINDOWS")
    if requested==""{return total,nil}
    n,err:=strconv.Atoi(requested)
    if err!=nil||n<1||n>total-start{return 0,errors.New("FI C1: invalid test window limit")}
    return start+n,nil
}

func privateC1SignedCacheBatch(ctx context.Context,cacheDir string,
    g *PreparedGeneration,i int)(PreparedBatch,error){
    var empty PreparedBatch
    if err:=ctx.Err();err!=nil{return empty,err}
    if i<0||i>=len(g.Batches){return empty,errors.New("FI C1: signed batch index out of range")}
    b:=g.Batches[i]
    raw,err:=backlogVerifiedCacheManifest(cacheDir,i,b.ManifestSHA256,1<<20)
    if err!=nil{return empty,fmt.Errorf("FI C1: signed manifest %d: %w",i,err)}
    manifest,err:=spool.DecodeManifest(bytes.NewReader(raw))
    if err!=nil{return empty,fmt.Errorf("FI C1: signed manifest %d decode: %w",i,err)}
    if manifest.BatchID!=b.BatchID||manifest.DataFile!=b.DataArtifactName||
        manifest.Version!=b.Manifest.Version||
        manifest.DataSHA256!=b.Manifest.DataSHA256||
        manifest.DataBytes!=b.Manifest.DataBytes||
        manifest.RecordCount!=b.Manifest.RecordCount||
        manifest.TargetBatchSize!=b.Manifest.TargetBatchSize {
        return empty,fmt.Errorf("FI C1: original signed batch %d manifest changed",i)
    }
    b.ManifestRawBytes=raw
    b.DataPath=backlogCacheBatchData(cacheDir,i)
    return b,nil
}

func privateC1SourceBatchIDs(ctx context.Context,reader *pgx.Conn,
    g *PreparedGeneration,d BacklogCheckpointDescriptor)([]int64,error){
    tx,err:=reader.BeginTx(ctx,pgx.TxOptions{AccessMode:pgx.ReadOnly})
    if err!=nil{return nil,err}
    defer tx.Rollback(context.Background())
    shadow:=privateProjectionTx{Tx:tx}
    id,ok,err:=lookupRecordedGeneration(ctx,shadow,
        d.SourceID,d.GenerationID,g.Receipt.TransferSHA256,g.ReceiptSHA256)
    if err!=nil{return nil,err}
    if !ok||id<=0{return nil,errors.New("FI C1: original signed shadow generation missing")}
    ids,err:=lookupBacklogShadowBatchIDs(ctx,shadow,id,
        g.Batches[d.StartBatch:d.EndBatch])
    if err!=nil{return nil,err}
    if len(ids)!=d.EndBatch-d.StartBatch {
        return nil,errors.New("FI C1: original source batch identity lookup incomplete")
    }
    return ids,nil
}

// C1's shared SQL workers commit individual family handoffs. They therefore
// cannot promise a single PostgreSQL transaction across six connections.
// Before any write, reject a clone containing partial source rows or a
// completion marker in the requested signed range. A failed/incomplete C1
// development run is restarted ONLY from a newly verified clean private clone;
// never replay into dirty relational tables or invent a typed checkpoint.
func privateC1CleanDestinationStatus(typedMarkers int64,sourceRowsFound bool) error {
    if typedMarkers<0{return errors.New("FI C1: invalid destination checkpoint count")}
    if typedMarkers!=0||sourceRowsFound {
        return fmt.Errorf("FI C1: partial or already projected destination markers=%d rows_present=%t; create a new verified private clone before replay",typedMarkers,sourceRowsFound)
    }
    return nil
}

func privateC1RequireCleanDestination(ctx context.Context,reader *pgx.Conn,
    g *PreparedGeneration,ds []BacklogCheckpointDescriptor,start,end int)error {
    if ctx==nil||reader==nil||g==nil||start<1||end<=start||end>len(ds){
        return errors.New("FI C1: invalid clean-start guard inputs")
    }
    var typedMarkers int64
    if err:=reader.QueryRow(ctx,`SELECT count(*) FROM fi_recovery.typed_window
WHERE window_index >= $1`,start).Scan(&typedMarkers);err!=nil {
        return fmt.Errorf("FI C1: typed prefix guard: %w",err)
    }
    if err:=privateC1CleanDestinationStatus(typedMarkers,false);err!=nil{return err}
    for wi:=start;wi<end;wi++ {
        ids,err:=privateC1SourceBatchIDs(ctx,reader,g,ds[wi])
        if err!=nil{return fmt.Errorf("FI C1: signed W%d parent identity guard: %w",wi,err)}
        if len(ids)==0{return fmt.Errorf("FI C1: signed W%d has no source batch identities",wi)}
        var existing bool
        if err=reader.QueryRow(ctx,`SELECT EXISTS(
SELECT 1 FROM fi_recovery_projection.source_record
WHERE source_batch_id = ANY($1::bigint[]))`,ids).Scan(&existing);err!=nil{
            return fmt.Errorf("FI C1: source parent guard W%d: %w",wi,err)
        }
        if err=privateC1CleanDestinationStatus(typedMarkers,existing);err!=nil{
            return fmt.Errorf("FI C1: signed W%d is not clean: %w",wi,err)
        }
    }
    fmt.Printf("FI C1 CLEAN START PASS windows=%d..%d signed_parents_absent=true typed_markers_absent=true restart_requires_fresh_clone=true\n",start,end-1)
    return nil
}

// Original P5 pool and its bounded family dispatch are shared across ALL
// signed batches and BOTH W512 reporting windows, not reconstructed at a
// signed-batch/window boundary. The caller owns one reader and SHA-256 hasher.
type privateC1PrepTotals struct {
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
func privateC1ConsumePrepared(ctx context.Context,pool *privateP5Pool,
    reader *bufio.Reader,prepare privateHeaderPrepareFunc,
    accept func(privateParallelLine)error,totals *privateC1PrepTotals,
)(int64,int64,error){
    if ctx==nil||pool==nil||reader==nil||prepare==nil||accept==nil||totals==nil{
        return 0,0,errors.New("FI C1: P5 family preparation stream inputs missing")
    }
    stream,err:=pool.newStream(ctx,reader,prepare)
    if err!=nil{return 0,0,err}
    defer stream.Close()
    var ordinal,bytesSeen int64
    for{
        if err:=ctx.Err();err!=nil{return ordinal,bytesSeen,err}
        line,ok:=stream.Next()
        if !ok{break}
        if line.readErr!=nil{return ordinal,bytesSeen,fmt.Errorf("FI C1: P5 signed reader: %w",line.readErr)}
        if line.prepareErr!=nil{return ordinal,bytesSeen,fmt.Errorf("FI C1: P5 family preparation: %w",line.prepareErr)}
        if line.ordinal!=ordinal+1{return ordinal,bytesSeen,errors.New("FI C1: P5 reordered or skipped signed source ordinal")}
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

func privateC1ReadSignedBatch(ctx context.Context,sourceID string,
    index int,sourceBatchID int64,batch PreparedBatch,
    buffers *privateP6Buffers,pool *privateP5Pool,
    totals *privateC1PrepTotals)(int64,int64,error){
    f,err:=os.Open(batch.DataPath)
    if err!=nil{return 0,0,err}
    defer f.Close()
    if st,err:=f.Stat();err!=nil||!st.Mode().IsRegular()||
        st.Size()!=batch.Manifest.DataBytes{
        return 0,0,fmt.Errorf("FI C1: signed data file bytes changed batch=%d: %v",index,err)
    }
    // TeeReader hashes bytes while the existing P5 block reader consumes
    // them. One physical read, one batch SHA-256 and one family preparer.
    hasher:=sha256.New()
    reader:=bufio.NewReaderSize(io.TeeReader(f,hasher),128<<10)
    ordinal,bytesSeen,err:=privateC1ConsumePrepared(
        ctx,pool,reader,privateHeaderFirstPrepare,
        func(line privateParallelLine)error{
            if line.source.RecordBytes!=len(line.raw)||
                len(line.source.RawRecordBytes)!=len(line.raw)||
                line.source.Record.RecordKind!=line.headerKind {
                return fmt.Errorf("FI C1: P5 signed family preparation changed original record at %d/%d",
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
        return ordinal,bytesSeen,fmt.Errorf("FI C1: original signed batch %d SHA/count/bytes invalid",index)
    }
    return ordinal,bytesSeen,nil
}

func privateC1MarkTyped(ctx context.Context,writer *pgx.Conn,
    g *PreparedGeneration,ds []BacklogCheckpointDescriptor,start,end int)error{
    tx,err:=writer.Begin(ctx)
    if err!=nil{return err}
    defer tx.Rollback(context.Background())
    shadow:=privateProjectionTx{Tx:tx}
    id,ok,err:=lookupRecordedGeneration(ctx,shadow,
        ds[0].SourceID,ds[0].GenerationID,
        g.Receipt.TransferSHA256,g.ReceiptSHA256)
    if err!=nil{return err}
    if !ok{return errors.New("FI C1: missing original shadow generation")}
    var already int64
    if err=tx.QueryRow(ctx,`SELECT count(*) FROM fi_recovery.typed_window WHERE window_index >= $1`,
        start).Scan(&already);err!=nil{return err}
    if already!=0{return errors.New("FI C1: destination already has typed markers")}
    receipt,err:=hex.DecodeString(ds[0].ReceiptSHA256)
    if err!=nil||len(receipt)!=32{return errors.New("FI C1: invalid signed generation receipt")}
    // Every group already has its independent committed-data relational
    // proof. This transaction only checks the immutable signed descriptor
    // chain and atomically inserts typed completion markers; NEVER rescan
    // all source and child tables or serialize ingestion on relational SQL.
    for i:=start;i<end;i++{
        d:=ds[i]
        digest,err:=hex.DecodeString(d.DigestSHA256)
        if err!=nil||len(digest)!=32{return errors.New("FI C1: signed descriptor hash invalid")}
        previous,err:=hex.DecodeString(d.PreviousDigestSHA256)
        if err!=nil||len(previous)!=32{return errors.New("FI C1: signed predecessor hash invalid")}
        var preceding []byte
        if err=tx.QueryRow(ctx,`SELECT descriptor_sha256 FROM fi_recovery.typed_window
WHERE receipt_sha256=$1 AND window_index=$2`,receipt,i-1).Scan(&preceding);err!=nil{return err}
        if subtle.ConstantTimeCompare(preceding,previous)!=1{
            return fmt.Errorf("FI C1: signed predecessor mismatches window %d",i)
        }
        if _,err=tx.Exec(ctx,`INSERT INTO fi_recovery.typed_window
(receipt_sha256,window_index,descriptor_sha256,shadow_generation_id,
start_batch,end_batch,committed_records,committed_bytes,ingest_version)
VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
            receipt,i,digest,id,d.StartBatch,d.EndBatch,
            int64(d.EndRecord-d.StartRecord),int64(d.DataBytes),IngestVersion);err!=nil{return err}
    }
    // The complete-generation signed receipt and anti-publication checks
    // follow in privateC1VerifyCompleteGroupedReplay, not as a repeated
    // synchronous relational scan inside this marker transaction.
    return tx.Commit(ctx)
}

func privateC1RecoverDirect(ctx context.Context,reader,writer *pgx.Conn,
    g *PreparedGeneration,limits BacklogWindowLimits,
    privateRoot string,startWindow int,cacheRoot string,
    ds []BacklogCheckpointDescriptor,report func(BacklogContinuousProgress),
)(BacklogGenerationVerification,error){
    var empty BacklogGenerationVerification
    if !privateC1Enabled()||ctx==nil||g==nil||reader==nil||writer==nil||
        len(ds)<2||reader==writer{return empty,errors.New("FI C1: original P6 direct clone not selected")}
    setupStarted:=time.Now()
    // C1 4GiB full-backlog is clone-only, preserving the original seed
    // descriptor. Bounded P5/P6/SQL workers persist across all groups.
    // Partial 8GiB experiments remain on their existing strict stop path.
    fullRun:=os.Getenv("FI_W512_C1_FULL_BACKLOG")=="1"
    if fullRun && (startWindow!=1 ||
        os.Getenv("FI_W512_C1_GROUP_GIB")!="4" ||
        os.Getenv("FI_W512_C1_STOP_WINDOWS")!=""){
        return empty,errors.New("FI C1 FULL: require seed start=1, 4GiB groups and no requested stop")
    }
    if group:=os.Getenv("FI_W512_C1_GROUP_GIB");group!=""{
        n,e:=strconv.Atoi(group)
        if e!=nil{return empty,fmt.Errorf("FI C1: invalid group size %q",group)}
        replanned,stop,rows,sourceBytes,e:=privateC1EightGiBGroups(g,ds,n)
        if e!=nil{return empty,e}
        if !fullRun && (startWindow!=1 ||
            os.Getenv("FI_W512_C1_STOP_WINDOWS")!=strconv.Itoa(stop)){
            return empty,errors.New("FI C1 8GiB: stop count must match 2GiB/4GiB signed grouping")
        }
        ds=replanned
        if fullRun{
            fmt.Printf("FI C1 FULL BACKLOG SIGNED PLAN group_gib=4 new_windows=%d new_records=%d new_source_bytes=%d first_batch=%d last_batch=%d signed_batches=%d seeded_records=%d seed_unchanged=true no_record_window_limit=true\n",
                len(ds)-1,g.Receipt.RecordCount-ds[0].EndRecord,
                g.Receipt.DataBytes-ds[0].DataBytes,ds[1].StartBatch,
                ds[len(ds)-1].EndBatch,len(g.Batches),ds[0].EndRecord)
        }else{
            fmt.Printf("FI C1 EIGHT GIB SIGNED PLAN group_gib=%d new_windows=%d new_records=%d new_source_bytes=%d first_batch=%d last_batch=%d seed_unchanged=true identical_prefix=true\n",
                n,stop,rows,sourceBytes,ds[1].StartBatch,ds[stop].EndBatch)
        }
    } else if fullRun {
        return empty,errors.New("FI C1 FULL: missing mandatory 4GiB source grouping")
    }
    end,err:=privateC1StopIndex(startWindow,len(ds))
    if err!=nil{return empty,err}
    var prevDigest []byte
    receipt,err:=hex.DecodeString(ds[startWindow-1].ReceiptSHA256)
    if err!=nil{return empty,err}
    if err=writer.QueryRow(ctx,`SELECT descriptor_sha256 FROM fi_recovery.typed_window
WHERE receipt_sha256=$1 AND window_index=$2`,receipt,startWindow-1).Scan(&prevDigest);err!=nil{return empty,err}
    want,err:=hex.DecodeString(ds[startWindow-1].DigestSHA256)
    if err!=nil||subtle.ConstantTimeCompare(prevDigest,want)!=1{
        return empty,errors.New("FI C1: existing signed seed checkpoint does not match")
    }
    // Guard every requested signed window BEFORE opening or writing through
    // the six SQL connections. Never continue an interrupted C1 run against
    // partially committed per-family rows.
    if err=privateC1RequireCleanDestination(ctx,reader,g,ds,startWindow,end);err!=nil{
        return empty,err
    }
    planningGuardElapsed:=time.Since(setupStarted)
    pipelineStarted:=time.Now()
    // Keep the original P6 cross-batch USN and File identity semantics.
    // No reset or forced buffer flush at a W512 reporting boundary.
    usn:=newUSNCaptureState(ds[0].SourceID,ds[0].GenerationID)
    ctx=context.WithValue(ctx,usnCaptureContextKey{},usn)
    ctx=context.WithValue(ctx,usnTimingContextKey{},&usnTimingCounters{})
    ctx=context.WithValue(ctx,backlogUSNCrossWindowContextKey{},true)
    // A owns its ingestion context. B is a separate asynchronous verifier
    // whose reported failures do not cancel, throttle or flush A. Publication
    // and completion markers are still withheld if the B proof fails.
    commitReady,e:=newPrivateC1CommitReady(ds,startWindow,end)
    if e!=nil{return empty,fmt.Errorf("FI C1: committed readiness init: %w",e)}
    dsn,pgdata:=os.Getenv("FI_W512_C1_SQL_DSN"),os.Getenv("FI_W512_C1_EXPECTED_PGDATA")
    sink,err:=newPrivateC1FiveSQL(ctx,dsn,pgdata,ds[0].SourceID)
    if err!=nil{return empty,err}
    sink.commitReady=commitReady
    defer sink.Close()
    cacheDir,err:=backlogVerifiedCacheOpen(cacheRoot,g.ReceiptSHA256,
        g.Receipt.TransferSHA256,g.Receipt.BatchCount,g.Receipt.RecordCount,g.Receipt.DataBytes)
    if err!=nil{return empty,err}
    buffers,err:=newPrivateP6Buffers(startWindow,sink)
    if err!=nil{return empty,err}
    // One original P5 adaptive family worker pool for the whole run.
    // Do not reset its workers, credits, or P6 SQL-ready buffers at W512.
    pool,err:=newPrivateP5Pool(ctx,startWindow)
    if err!=nil{return empty,fmt.Errorf("FI C1: P5 persistent preparation pool: %w",err)}
    defer pool.Close()
    var prepTotals privateC1PrepTotals
    fmt.Printf("FI C1 P5 PREP POOL START lanes=5 min=2 max=32 persistent_across_signed_batches=true persistent_across_W512=true\n")
    pipelineInitializeElapsed:=time.Since(pipelineStarted)
    manifestStarted:=time.Now()
    // Resolve the original signed manifest and exact shadow source identity
    // for every batch before opening the single continuous P5 session.
    // These are verified receiver-custody artifacts, NOT new source staging.
    signed:=make([]privateC1StreamBatch,0,len(g.Batches))
    for wi:=startWindow;wi<end;wi++{
        d:=ds[wi]
        if err=ctx.Err();err!=nil{return empty,err}
        ids,e:=privateC1SourceBatchIDs(ctx,reader,g,d)
        if e!=nil{return empty,e}
        for offset,id:=range ids{
            index:=d.StartBatch+offset
            batch,e:=privateC1SignedCacheBatch(ctx,cacheDir,g,index)
            if e!=nil{return empty,fmt.Errorf("FI C1: signed batch %d manifest: %w",index,e)}
            signed=append(signed,privateC1StreamBatch{
                Index:index,Window:wi,SourceBatchID:id,Batch:batch,
            })
        }
    }
    manifestElapsed:=time.Since(manifestStarted)
    verifierStarted:=time.Now()
    // Process B starts before A's P5/P6 loop, with an independent PID and
    // PostgreSQL session. Only bounded original group metadata and COMMIT-ready
    // receipts cross the one-way pipe; B never controls any P6 buffer.
    verifier,e:=privateC1StartProcessVerify(ctx,dsn,pgdata,g,ds,startWindow,end,
        commitReady.notifications,func(err error){
            fmt.Printf("FI C1 VERIFIER CALLBACK error=%v action=report_and_withhold_marker ingestion_cancelled=false verifier_process=separate\n",err)
        })
    if e!=nil{return empty,fmt.Errorf("FI C1: async relational verifier startup: %w",e)}
    defer verifier.Stop()
    verifierElapsed:=time.Since(verifierStarted)
    fmt.Printf("FI C1 PRE-INGEST SETUP elapsed=%s signed_group_planning_clean_guard=%s pipeline_initialize=%s signed_manifest_lookup=%s verifier_spawn=%s signed_batches=%d excluded_from_ingest_rate=true\n",
        time.Since(setupStarted),planningGuardElapsed,pipelineInitializeElapsed,manifestElapsed,verifierElapsed,len(signed))
    // P5 preparation no longer drains and recreates one stream per signed
    // batch. The signed reader still finishes and validates every original
    // batch's original manifest identity, byte count, record count and LF
    // boundary before opening the next; no duplicate SHA-256 over batch data. P6 remains continuous across all reporting windows.
    started:=time.Now()
    fmt.Printf("FI C1 INGEST CLOCK START utc=%s stage=Preparation_entry setup_excluded=true verifier_excluded=true\n",
        started.UTC().Format(time.RFC3339Nano))
    fmt.Printf("FI C1 RECORD PROCESSING CLOCK START utc=%s starts=Preparation ends=FamilyProcessing_All_SQL_ACKed preflight_excluded=true verifier_excluded=true\n",
        started.UTC().Format(time.RFC3339Nano))
    groupRows,groupBytes,e:=privateC1ConsumeContinuousSigned(
        ctx,pool,signed,buffers,&prepTotals,len(ds),privateHeaderFirstPrepare,commitReady.Seal)
    if e!=nil{return empty,fmt.Errorf("FI C1: continuous signed P5: %w",e)}
    var totalRows,totalBytes int64
    for wi:=startWindow;wi<end;wi++{
        d:=ds[wi]
        seen,seenBytes:=groupRows[wi],groupBytes[wi]
        if seen!=int64(d.EndRecord-d.StartRecord)||seenBytes!=int64(d.DataBytes){
            return empty,fmt.Errorf("FI C1: window %d signed source tally mismatched",wi)
        }
        totalRows+=seen
        totalBytes+=seenBytes
        fmt.Printf("FI C1 P6 DIRECT READ window=%d signed_batches=%d records=%d bytes=%d source_stage_rows=0 copied_artifacts=0\n",
            wi,d.EndBatch-d.StartBatch,seen,seenBytes)
    }
    // W512 is only a reporting boundary. The P6 buffers were never
    // drained or re-created inside the loop above.
    // Notify B that A entered its final drain, without waiting for B or
    // injecting SQL handoffs at the reporting group boundary.
    verifier.MarkDrained()
    fmt.Printf("FI C1 P6 FINAL DRAIN START records_admitted=%d marker_unwritten=true\n",totalRows)
    if err=buffers.Finish(ctx);err!=nil{return empty,fmt.Errorf("FI C1: P6 shared-pool five-family drain: %w",err)}
    processingElapsed:=time.Since(started)
    fmt.Printf("FI C1 P6 SQL DRAIN elapsed=%s records_admitted=%d verifier_independent=true\n",
        processingElapsed,totalRows)
    fmt.Printf("FI C1 FAMILY PROCESSING COMPLETE elapsed=%s records_committed=%d preparation_included=true verification_excluded=true preflight_excluded=true durable_sql_acks=true\n",
        processingElapsed,totalRows)
    if err=commitReady.FinishCommitted();err!=nil{
        return empty,fmt.Errorf("FI C1: complete signed SQL commit receipts: %w",err)
    }
    parents,children,family:=sink.Stats()
    if parents!=totalRows||children!=totalRows{
        return empty,fmt.Errorf("FI C1: source/child count mismatch source=%d typed=%d signed=%d",
            parents,children,totalRows)
    }
    // All source and family commits have ACKed. The independent verifier
    // must prove every signed group before any typed marker is written.
    // The old synchronous relational scans are intentionally removed.
    // B acknowledges the independently committed group proofs before A
    // writes private typed markers; it remains the SAME OS process while
    // A commits those markers and then performs its final read-only proof.
    if err=verifier.WaitGroups(ctx);err!=nil{
        return empty,fmt.Errorf("FI C1: independent committed-group proof: %w",err)
    }
    if err=privateC1MarkTyped(ctx,writer,g,ds,startWindow,end);err!=nil{
        return empty,fmt.Errorf("FI C1: final signed relational marker: %w",err)
    }
    verifiedByB,e:=verifier.Finish(ctx)
    if e!=nil{
        return empty,fmt.Errorf("FI C1: independent final generation proof: %w",e)
    }
    pool.Close()
    fmt.Printf("FI C1 P5 PREP COMPLETE batches=%d records=%d family_lanes=5 worker_min=2 worker_max=32 reader_time=%s parallel_worker_time_sum=%s consumer_wait=%s\n",
        prepTotals.batches,prepTotals.records,prepTotals.readerTime,
        prepTotals.workerTime,prepTotals.writerWait)
    elapsed:=time.Since(started)
    fmt.Printf("FI C1 P6 SHARED SQL PASS windows=%d records=%d bytes=%d families=5 parent=1 five_committed=%d security=%d file=%d coverage=%d usn=%d other=%d source_staging=none duration=%s\n",
        end-startWindow,totalRows,totalBytes,children,
        family[0],family[1],family[2],family[3],family[4],elapsed)
    // C1 has ONE durable marker barrier at test completion, not
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
    if end<len(ds){
        // Explicit two-group development prefix: fail closed on any incomplete
        // SQL/relational proof and NEVER report full generation verification.
        if os.Getenv("FI_C1_DEV_PREFIX8")!="1"{
            return empty,errors.New("FI C1: unexpected partial generation without explicit prefix mode")
        }
        // B already ran the exact original 8GiB prefix proof on its own
        // read-only connection after A's private typed marker transaction.
        return empty,context.Canceled
    }
    if !fullRun{
        return empty,errors.New("FI C1: complete-generation proof requires full mode")
    }
    // Validate B's structured result against the exact source generation.
    // This is metadata matching, not another SHA/data or relational pass.
    if verifiedByB.SourceID!=ds[0].SourceID||
        verifiedByB.GenerationID!=ds[0].GenerationID||
        verifiedByB.ReceiptSHA256!=g.ReceiptSHA256||
        verifiedByB.ShadowGenerationID<=0||
        verifiedByB.Windows!=len(ds)||
        verifiedByB.Records!=g.Receipt.RecordCount||
        verifiedByB.DataBytes!=g.Receipt.DataBytes{
        return empty,errors.New("FI C1: independent B result mismatches original generation receipt")
    }
    // Original complete-generation relational proof and its verified shadow
    // ID now come from the same independent B process, not from A's SQL.
    return verifiedByB,nil
}

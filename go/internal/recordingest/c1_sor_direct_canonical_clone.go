//go:build fi_c1_sor_dev

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// DEVELOPMENT CLONE ONLY: the existing C1 Preparation / Family Processing
// transactions write once to fi.*, B independently verifies those committed
// records, and ONLY B's successful final proof permits a tiny Accepted journal
// transaction. There is no Pending-to-canonical INSERT/SELECT, remapping,
// second family processing pass, or second signed-custody read at acceptance.
//
// IMPORTANT: until separate read-visibility and interrupted-prefix replay
// acceptance are proven, this mode MUST NEVER be enabled against the live SoR.
package recordingest

import (
    "bytes"
    "context"
    "crypto/rand"
    "encoding/hex"
    "errors"
    "fmt"

    "github.com/Iron-Signal-Systems/fi/go/internal/c1handoff"
    "github.com/jackc/pgx/v5"
)

func (s *C1SoRService) bootstrapDirectCanonicalClone(
    ctx context.Context, f c1handoff.Frame)([]int64,error){
    if s==nil||ctx==nil||f.Kind!=c1handoff.Start||f.StartBatchIndex!=0{
        return nil,errors.New("C1 direct clone: original full signed Start required")
    }
    if err:=f.Validate();err!=nil{return nil,err}
    s.mu.Lock()
    defer s.mu.Unlock()
    if s.pool!=nil||s.session!=nil||s.failed!=nil{
        return nil,errors.New("C1 direct clone: already processing a generation")
    }
    if !s.NativeBCustody.BenchmarkClone||s.NativeBCustody.VerifiedCacheRoot==""||
        s.CloneRoot==""||s.CloneSystemID==""||s.PublisherDSN==""{
        return nil,errors.New("C1 direct clone: explicit verified-cache and physical isolated PG18 clone required")
    }
    c:=C1SoRLocalConfig{
        SourceID:f.SourceID,WorkerDSN:s.DSN,PublisherDSN:s.PublisherDSN,
        SQLWorkersMax:s.MaxSQLWorkers,Custody:s.NativeBCustody,
        DirectCanonicalClone:true,
    }
    if err:=PreflightC1SoRBenchmarkClone(ctx,c,s.CloneRoot,s.CloneSystemID);err!=nil{
        return nil,fmt.Errorf("C1 direct clone: physical PostgreSQL authorization: %w",err)
    }
    // The exact receiver-recorded receipt and previously authenticated cache
    // roster are opened just as they are in the existing cache-backed C1 test.
    original,err:=c1SoRVerifiedCacheGeneration(ctx,f.SourceID,f.GenerationID,s.NativeBCustody)
    if err!=nil{return nil,err}
    if original.ReceiptSHA256!=f.ReceiptSHA256||
        uint64(f.ExpectedRecords)!=original.Receipt.RecordCount||
        len(original.Batches)!=len(f.BatchIDs){
        return nil,errors.New("C1 direct clone: authenticated original receipt does not match Start")
    }
    for i,b:=range original.Batches{
        if b.BatchID!=f.BatchIDs[i]{
            return nil,fmt.Errorf("C1 direct clone: signed batch roster changed at %d",i)
        }
    }
    if err=s.acquirePendingSessionLock(ctx);err!=nil{return nil,err}
    conn,_,err:=openC1SoRLocalSQL(ctx,s.DSN,"")
    if err!=nil{return nil,err}
    defer conn.Close(context.Background())
    tx,err:=conn.BeginTx(ctx,pgx.TxOptions{IsoLevel:pgx.ReadCommitted})
    if err!=nil{return nil,err}
    defer tx.Rollback(context.Background())
    var prior bool
    if err=tx.QueryRow(ctx,`SELECT EXISTS(SELECT 1 FROM fi.recorded_generation
       WHERE source_id=$1 AND generation_id=$2)`,f.SourceID,f.GenerationID).Scan(&prior);err!=nil{
        return nil,err
    }
    if prior{return nil,errors.New("C1 direct clone: existing canonical generation requires audited recovery, never blind replay")}
    ids,err:=c1StageOriginalCanonicalLedgerTx(ctx,tx,original)
    if err!=nil{return nil,err}
    if err=tx.Commit(ctx);err!=nil{
        return nil,fmt.Errorf("C1 direct clone: original signed metadata commit unknown: %w",err)
    }
    counts:=make([]int64,len(original.Batches))
    for i,b:=range original.Batches{counts[i]=int64(b.Manifest.RecordCount)}
    // Same ordered source writer and exact five SQL-family modules; only
    // their destination changes from fi_c1_pending to fi in this clone.
    pool,err:=newC1SQLWithOpener(ctx,s.DSN,"",f.SourceID,s.MaxSQLWorkers,false,
        openC1SoRLocalSQL,false,"fi")
    if err!=nil{return nil,err}
    pool.usnGenerationID=f.GenerationID
    handler,err:=newC1SoRCommitHandler(pool,f.SourceID,f.GenerationID,
        f.ReceiptSHA256,ids,counts,f.ExpectedRecords)
    if err!=nil{pool.Close();return nil,err}
    tracker,verifier,err:=startC1SoRParallelB(ctx,s.DSN,f,ids,pool,s.NativeBCustody)
    if err!=nil{pool.Close();return nil,err}
    s.pool=pool
    s.session=handler
    s.commitReady=tracker
    s.verifier=verifier
    fmt.Printf("FI C1 DIRECT CANONICAL CLONE START signed_batches=%d signed_records=%d destination=fi single_write=true independent_b=true no_second_copy=true live_sor_untouched=true\n",
        len(ids),f.ExpectedRecords)
    return append([]int64(nil),ids...),nil
}

func(s *C1SoRService)finalProofDirectCanonicalClone(ctx context.Context,
    f c1handoff.Frame)(c1handoff.FinalStatus,error){
    s.mu.Lock()
    if !s.independentlyVerified||s.session==nil||!s.session.drained||
        s.verifier==nil||s.pool==nil||s.publishing||
        f.SourceID!=s.session.sourceID||
        f.GenerationID!=s.session.generationID||
        f.ReceiptSHA256!=s.session.receipt {
        s.mu.Unlock()
        return c1handoff.FinalNone,errors.New("C1 direct clone: signed SQL and independent B final proof must both pass")
    }
    if err:=s.pendingLockHealthy(ctx);err!=nil{s.mu.Unlock();return c1handoff.FinalNone,err}
    commitment,err:=s.verifier.Commitment()
    if err!=nil{s.mu.Unlock();return c1handoff.FinalNone,err}
    s.publishing=true
    s.mu.Unlock()
    err=c1MarkDirectCanonicalAccepted(ctx,s.PublisherDSN,f,commitment)
    var status c1handoff.FinalStatus
    if err==nil{status,err=c1PostPublicationReadback(ctx,s.DSN,f.SourceID,f.GenerationID,f.ReceiptSHA256)}
    s.mu.Lock()
    s.publishing=false
    if err!=nil{s.failed=err}
    s.mu.Unlock()
    if err!=nil{return c1handoff.FinalNone,fmt.Errorf("C1 direct clone: B-final Accepted bookkeeping: %w",err)}
    if status!=c1handoff.FinalAccepted{return c1handoff.FinalNone,errors.New("C1 direct clone: Accepted journal not confirmed")}
    fmt.Printf("FI C1 DIRECT CANONICAL ACCEPTED records=%d verifier_b_sha256=%s source_written_once=true no_relation_reinsert=true\n",
        f.ExpectedRecords,commitment)
    return status,nil
}

// The final check IS Verifier B. This transaction records its result, not
// the records: no COPY, no INSERT...SELECT of relational data, no scan of
// fifteen million source rows. The B process has already checked each
// committed SourceParent and mandatory typed root against signed custody.
func c1MarkDirectCanonicalAccepted(ctx context.Context,publisherDSN string,
    f c1handoff.Frame,bProof string)error{
    if ctx==nil||f.Kind!=c1handoff.Drain||!canonicalDigest(bProof)||
        !canonicalDigest(f.ReceiptSHA256)||f.ExpectedRecords<=0{
        return errors.New("C1 direct clone: independent complete B result required")
    }
    publisher,err:=openC1SoRLocalPublisherSQL(ctx,publisherDSN)
    if err!=nil{return err}
    defer publisher.Close(context.Background())
    var attempt [16]byte
    if _,err=rand.Read(attempt[:]);err!=nil{return err}
    attemptID:="fi-c1-direct-"+hex.EncodeToString(attempt[:])
    if err=WriteAttemptStarted(ctx,publisher,attemptID,f.SourceID,f.GenerationID);err!=nil{return err}
    tx,err:=publisher.BeginTx(ctx,pgx.TxOptions{IsoLevel:pgx.ReadCommitted})
    if err!=nil{return err}
    defer tx.Rollback(context.Background())
    var recordedReceipt,transfer []byte
    var count,batches int64
    err=tx.QueryRow(ctx,`SELECT receipt_sha256,transfer_sha256,record_count,batch_count
       FROM fi.recorded_generation WHERE source_id=$1 AND generation_id=$2`,
        f.SourceID,f.GenerationID).Scan(&recordedReceipt,&transfer,&count,&batches)
    if err!=nil{return err}
    receipt,_:=hex.DecodeString(f.ReceiptSHA256)
    if !bytes.Equal(recordedReceipt,receipt)||len(transfer)!=32||
        count!=f.ExpectedRecords||batches!=int64(len(f.BatchIDs)){
        return errors.New("C1 direct clone: canonical signed generation metadata changed since B proof")
    }
    var accepted int64
    if err=tx.QueryRow(ctx,`SELECT count(*) FROM fi.ingest_journal
      WHERE source_id=$1 AND generation_id=$2 AND outcome='Accepted'`,
        f.SourceID,f.GenerationID).Scan(&accepted);err!=nil{return err}
    if accepted!=0{return errors.New("C1 direct clone: Accepted already exists; never duplicate")}
    // Group and per-record SQL proof has been completed by independent B.
    // Only exact signed generation metadata and the Accepted journal are
    // written here. Existing 49 canonical relational tables are untouched.
    tag,err:=tx.Exec(ctx,`INSERT INTO fi.ingest_journal
      (attempt_id,event_sequence,source_id,generation_id,transfer_sha256,
       outcome,stage,reason_code,detail,records_seen,records_committed,ingest_version)
      VALUES ($1,2,$2,$3,$4,'Accepted','AuthoritativeRecord',
              'C1_B_VERIFIED',$5,$6,$6,$7)`,
       attemptID,f.SourceID,f.GenerationID,transfer,
       "verifier_b_sha256="+bProof,f.ExpectedRecords,IngestVersion)
    if err!=nil{return err}
    if tag.RowsAffected()!=1{return errors.New("C1 direct clone: no Accepted marker inserted")}
    return tx.Commit(ctx)
}

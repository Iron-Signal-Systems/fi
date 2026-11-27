//go:build fi_c1_sor_dev

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// ONE C1 writer for normal READY consumption and a large signed backlog:
// receiver custody -> original P5/P6 -> committed fi SQL -> independent B ->
// ONE Accepted journal event. No Pending-to-canonical remapper, no second
// source/typed relation INSERT. No alternate C1 Preparation or SQL engine.
package recordingest

import (
    "context"
    "crypto/rand"
    "encoding/hex"
    "errors"
    "fmt"
    "strings"

    "github.com/Iron-Signal-Systems/fi/go/internal/c1handoff"
    "github.com/jackc/pgx/v5"
)

// Fail closed if the dedicated C1 worker has not been intentionally granted
// insert-only access to canonical fi. No GRANT or schema mutation here.
func c1PreflightDirectCanonicalSQL(ctx context.Context,dsn string)error{
    conn,_,err:=openC1SoRLocalSQL(ctx,dsn,"")
    if err!=nil{return err}
    defer conn.Close(context.Background())
    tx,err:=conn.BeginTx(ctx,pgx.TxOptions{IsoLevel:pgx.RepeatableRead,AccessMode:pgx.ReadOnly})
    if err!=nil{return err}
    defer tx.Rollback(context.Background())
    var role string
    var tables,denied,seqDenied int64
    var journalWrite,schemaCreate bool
    err=tx.QueryRow(ctx,`SELECT current_user,
       count(*) FILTER (WHERE c.relkind IN ('r','p') AND NOT c.relispartition)::bigint,
       count(*) FILTER (WHERE c.relkind IN ('r','p') AND NOT c.relispartition
           AND c.relname<>'ingest_journal'
           AND NOT (has_table_privilege(current_user,c.oid,'SELECT') AND
                    has_table_privilege(current_user,c.oid,'INSERT')
                    AND NOT has_table_privilege(current_user,c.oid,'UPDATE')
                    AND NOT has_table_privilege(current_user,c.oid,'DELETE')
                    AND NOT has_table_privilege(current_user,c.oid,'TRUNCATE')))::bigint,
       count(*) FILTER (WHERE c.relkind='S' AND
          NOT (has_sequence_privilege(current_user,c.oid,'USAGE')
              AND has_sequence_privilege(current_user,c.oid,'SELECT')))::bigint
       FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
       WHERE n.nspname='fi'`).Scan(&role,&tables,&denied,&seqDenied)
    if err!=nil{return err}
    err=tx.QueryRow(ctx,`SELECT has_table_privilege(current_user,'fi.ingest_journal','INSERT'),
      has_schema_privilege(current_user,'fi','CREATE')`).Scan(&journalWrite,&schemaCreate)
    if err!=nil{return err}
    if role!="fi_ingest"||tables!=49||denied!=0||seqDenied!=0||journalWrite||schemaCreate {
        return fmt.Errorf("C1 direct: canonical insert-only worker permissions missing/unsafe role=%s tables=%d denied=%d sequences_denied=%d journal_insert=%t schema_create=%t",
            role,tables,denied,seqDenied,journalWrite,schemaCreate)
    }
    return tx.Commit(ctx)
}

func(s *C1SoRService)bootstrapDirectCanonical(ctx context.Context,
    start c1handoff.Frame)([]int64,error){
    s.mu.Lock()
    defer s.mu.Unlock()
    if s.session!=nil||s.pool!=nil||s.failed!=nil{
        return nil,errors.New("C1 direct: session already active or failed")
    }
    if start.StartBatchIndex!=0||s.AllowC1Replay{
        return nil,errors.New("C1 direct: incomplete replay requires reconciliation; no blind duplicate SQL")
    }
    if err:=c1PreflightDirectCanonicalSQL(ctx,s.DSN);err!=nil{
        s.failed=err;return nil,err
    }
    if err:=c1PreflightLocalPublisher(ctx,s.PublisherDSN);err!=nil{
        s.failed=err;return nil,err
    }
    if err:=s.acquirePendingSessionLock(ctx);err!=nil{
        s.failed=err;return nil,err
    }
    ids,err:=s.stageOriginalCanonicalLedger(ctx,start)
    if err!=nil{s.failed=err;return nil,fmt.Errorf("C1 direct: original signed canonical ledger: %w",err)}
    counts,err:=s.loadSignedBatchRecordCounts(ctx,ids)
    if err!=nil{s.failed=err;return nil,err}
    pool,err:=newC1SoRSQLPool(ctx,s.DSN,start.SourceID,start.GenerationID,s.MaxSQLWorkers,true)
    if err!=nil{s.failed=err;return nil,err}
    handler,err:=newC1SoRCommitHandler(pool,start.SourceID,start.GenerationID,
        start.ReceiptSHA256,ids,counts,start.ExpectedRecords)
    if err!=nil{pool.Close();s.failed=err;return nil,err}
    if s.SharedRAMDir!=""{
        ram,e:=c1handoff.NewRAMStore(s.SharedRAMDir)
        if e!=nil{pool.Close();s.failed=e;return nil,e}
        handler.sharedRAM=ram
    }
    tracker,verifier,err:=startC1SoRParallelB(ctx,s.DSN,start,ids,pool,s.NativeBCustody)
    if err!=nil{pool.Close();s.failed=err;return nil,err}
    s.pool=pool
    s.session=handler
    s.commitReady=tracker
    s.verifier=verifier
    fmt.Printf("FI C1 DIRECT CANONICAL START source=%s generation=%s signed_batches=%d signed_records=%d target=fi same_p5_p6=true no_remap=true\n",
        start.SourceID,start.GenerationID,len(ids),start.ExpectedRecords)
    return append([]int64(nil),ids...),nil
}

// The direct canonical ledger MUST use the receiver-authenticated manifest
// roster, not a second complete signed transport extraction. This method
// neither accesses PostgreSQL nor treats the cache as final authentication:
// the independent B process validates original signed FIGT before Accepted.
func c1DirectCanonicalReceiverPlan(ctx context.Context,start c1handoff.Frame,
    custody c1NativeBCustodyConfig)(*PreparedGeneration,error){
    if ctx==nil||start.Kind!=c1handoff.Start||
        custody.BenchmarkClone||custody.VerifiedCacheRoot!=""||
        custody.ReceiverVerifiedCacheRoot==""{
        return nil,errors.New("C1 direct: original receiver-authenticated cache required for canonical bootstrap")
    }
    if err:=start.Validate();err!=nil{return nil,err}
    plan,err:=LoadC1SoRReceiverVerifiedCache(ctx,
        C1SoRLocalConfig{SourceID:start.SourceID,Custody:custody},
        start.GenerationID)
    if err!=nil{return nil,fmt.Errorf("C1 direct: receiver-authenticated source manifest: %w",err)}
    if plan.Receipt.Descriptor.SourceID!=start.SourceID||
        plan.Receipt.Descriptor.GenerationID!=start.GenerationID||
        plan.ReceiptSHA256!=start.ReceiptSHA256||
        int64(plan.Receipt.RecordCount)!=start.ExpectedRecords||
        len(plan.Batches)!=len(start.BatchIDs){
        return nil,errors.New("C1 direct: receiver verified cache changed original signed START")
    }
    for i,b:=range plan.Batches{
        if b.BatchID!=start.BatchIDs[i]{
            return nil,fmt.Errorf("C1 direct: cached signed batch order mismatch at %d",i)
        }
    }
    return plan,nil
}

func(s *C1SoRService)stageOriginalCanonicalLedger(ctx context.Context,
    start c1handoff.Frame)([]int64,error){
    if err:=start.Validate();err!=nil{return nil,err}
    // Original receiver custody is the only metadata authority.
    if s.NativeBCustody.VerifiedCacheRoot!=""{
        return nil,errors.New("C1 direct: original signed custody mandatory; benchmark cache prohibited")
    }
    // The receiver has already authenticated every batch and durably
    // published its receipt-bound cache. Read this exact bounded manifest
    // plan instead of decompressing the complete FIGT again BEFORE SQL.
    // Independent B reopens and cryptographically validates original signed
    // custody in parallel with the P5/P6 SQL stream; Accepted remains
    // impossible unless that separate original-custody proof passes.
    original,err:=c1DirectCanonicalReceiverPlan(ctx,start,s.NativeBCustody)
    if err!=nil{return nil,err}
    if original.Receipt.Descriptor.SourceID!=start.SourceID||
        original.Receipt.Descriptor.GenerationID!=start.GenerationID||
        original.ReceiptSHA256!=start.ReceiptSHA256||
        int64(original.Receipt.RecordCount)!=start.ExpectedRecords||
        len(original.Batches)!=len(start.BatchIDs){
        return nil,errors.New("C1 direct: immutable signed original differs from START")
    }
    for i,b:=range original.Batches{
        if b.BatchID!=start.BatchIDs[i]{
            return nil,fmt.Errorf("C1 direct: signed batch roster mismatch at %d",i)
        }
    }
    conn,_,err:=openC1SoRLocalSQL(ctx,s.DSN,"")
    if err!=nil{return nil,err}
    defer conn.Close(context.Background())
    tx,err:=conn.BeginTx(ctx,pgx.TxOptions{IsoLevel:pgx.ReadCommitted})
    if err!=nil{return nil,err}
    defer tx.Rollback(context.Background())

    var prior,unfinished,pending int64
    err=tx.QueryRow(ctx,`SELECT
       (SELECT count(*) FROM fi.recorded_generation WHERE source_id=$1 AND generation_id=$2),
       (SELECT count(*) FROM fi.recorded_generation g WHERE NOT EXISTS (
          SELECT 1 FROM fi.ingest_journal j WHERE j.source_id=g.source_id
          AND j.generation_id=g.generation_id AND j.outcome='Accepted'
          AND j.transfer_sha256=g.transfer_sha256 AND j.records_committed=g.record_count)),
       (SELECT count(*) FROM fi_c1_pending.generation_control)`,
        start.SourceID,start.GenerationID).Scan(&prior,&unfinished,&pending)
    if err!=nil{return nil,err}
    if prior!=0||unfinished!=0||pending!=0{
        return nil,fmt.Errorf("C1 direct: unaccepted/conflicting generation requires operator reconciliation prior=%d unfinished=%d pending=%d",prior,unfinished,pending)
    }
    ids,err:=c1StageOriginalCanonicalLedgerTx(ctx,tx,original)
    if err!=nil{return nil,err}
    if err=tx.Commit(ctx);err!=nil{
        return nil,fmt.Errorf("C1 direct: signed ledger commit uncertain, do not replay: %w",err)
    }
    return ids,nil
}

func(s *C1SoRService)finalProofDirectCanonical(ctx context.Context,
    f c1handoff.Frame)(c1handoff.FinalStatus,error){
    s.mu.Lock()
    if s.failed!=nil{err:=s.failed;s.mu.Unlock();return c1handoff.FinalNone,err}
    if !s.independentlyVerified||s.publishing||s.session==nil||!s.session.drained||
        s.pool==nil||s.verifier==nil||f.Kind!=c1handoff.Drain||
        f.SourceID!=s.session.sourceID||f.GenerationID!=s.session.generationID||
        f.ReceiptSHA256!=s.session.receipt{
        s.mu.Unlock()
        return c1handoff.FinalNone,errors.New("C1 direct: no matching committed SQL and independent B proof")
    }
    if err:=s.pendingLockHealthy(ctx);err!=nil{
        s.failed=err;s.mu.Unlock();return c1handoff.FinalNone,err
    }
    proof,err:=s.verifier.Commitment()
    if err!=nil||!canonicalDigest(proof){
        s.failed=errors.New("C1 direct: missing independent original signed B proof")
        s.mu.Unlock();return c1handoff.FinalNone,s.failed
    }
    s.publishing=true
    expected,batches,publisher,worker:=s.session.expectedRecords,len(s.session.sourceBatches),s.PublisherDSN,s.DSN
    plan:=s.verifier.plan
    s.mu.Unlock()

    err=c1DirectWriteAccepted(ctx,publisher,f,expected,batches,proof,plan)
    var status c1handoff.FinalStatus
    if err==nil {status,err=c1PostPublicationReadback(ctx,worker,f.SourceID,f.GenerationID,f.ReceiptSHA256)}
    s.mu.Lock()
    s.publishing=false
    if err!=nil{s.failed=err}
    s.mu.Unlock()
    if err!=nil{return c1handoff.FinalNone,fmt.Errorf("C1 direct: Accepted journal/readback: %w",err)}
    if status!=c1handoff.FinalAccepted{
        return c1handoff.FinalNone,errors.New("C1 direct: accepted journal not independently readable")
    }
    fmt.Printf("FI C1 DIRECT CANONICAL ACCEPTED source=%s generation=%s records=%d independent_B=true no_second_copy=true\n",
        f.SourceID,f.GenerationID,expected)
    return status,nil
}

// The publisher writes ONLY a compact journal row. All 49 canonical tables
// were already populated by C1's original SQL workers and proved by B.
// Hold canonical SHARE locks to prevent in-flight writes while finalizing.
func c1DirectWriteAccepted(ctx context.Context,dsn string,
    f c1handoff.Frame,expected int64,batches int,independentB string,
    plan c1NativeBPlan)error{
    if ctx==nil||f.Kind!=c1handoff.Drain||expected<=0||batches<=0||
        !canonicalDigest(independentB)||!canonicalDigest(f.ReceiptSHA256)||
        plan.SQLSchema!="fi"||plan.Start.Kind!=c1handoff.Start||
        plan.Start.SourceID!=f.SourceID||
        plan.Start.GenerationID!=f.GenerationID||
        plan.Start.ReceiptSHA256!=f.ReceiptSHA256||
        plan.Start.ExpectedRecords!=expected||len(plan.Batches)!=batches||
        len(plan.SQLIDs)!=batches {
        return errors.New("C1 direct: exact independent B plan, receipt, SQL counts and commitment required")
    }
    if err:=c1ValidateNativeBPlan(plan);err!=nil{return err}
    conn,err:=openC1SoRLocalPublisherSQL(ctx,dsn)
    if err!=nil{return err}
    defer conn.Close(context.Background())
    tx,err:=conn.BeginTx(ctx,pgx.TxOptions{IsoLevel:pgx.ReadCommitted})
    if err!=nil{return err}
    defer tx.Rollback(context.Background())
    // The publisher's MAINTAIN grant is intentionally separate from the
    // canonical insert-only SQL worker. Lock all root tables, including the
    // journal. Unexpected privilege or blocking aborts, never bypasses.
    rows,err:=tx.Query(ctx,`SELECT c.relname FROM pg_class c JOIN pg_namespace n
      ON n.oid=c.relnamespace
      WHERE n.nspname='fi' AND c.relkind IN ('r','p') AND NOT c.relispartition
      ORDER BY c.relname`)
    if err!=nil{return err}
    names:=make([]string,0,49)
    for rows.Next(){var name string;if err=rows.Scan(&name);err!=nil{break}
        names=append(names,pgx.Identifier{"fi",name}.Sanitize())}
    if err==nil{err=rows.Err()}
    rows.Close()
    if err!=nil{return err}
    if len(names)!=49{return errors.New("C1 direct: canonical relation set changed")}
    if _,err=tx.Exec(ctx,"LOCK TABLE "+strings.Join(names,",")+" IN SHARE MODE");err!=nil{return err}

    var id,count,batchCount,persisted,accepted int64
    var receipt,transfer []byte
    err=tx.QueryRow(ctx,`SELECT recorded_generation_id,record_count,batch_count,
       receipt_sha256,transfer_sha256 FROM fi.recorded_generation
       WHERE source_id=$1 AND generation_id=$2`,f.SourceID,f.GenerationID).
       Scan(&id,&count,&batchCount,&receipt,&transfer)
    if err!=nil{return fmt.Errorf("C1 direct: canonical signed ledger: %w",err)}
    if id<=0||count!=expected||batchCount!=int64(batches)||
        hex.EncodeToString(receipt)!=f.ReceiptSHA256||
        hex.EncodeToString(transfer)!=plan.Transfer {
        return errors.New("C1 direct: signed canonical identity changed after B proof")
    }
    err=tx.QueryRow(ctx,`SELECT count(*) FROM fi.source_batch
       WHERE recorded_generation_id=$1`,id).Scan(&persisted)
    if err!=nil{return err}
    if persisted!=batchCount{return errors.New("C1 direct: canonical signed batch count mismatch")}
    // Compare the entire signed per-batch ledger under the SAME table locks
    // as the source-row hash and Accepted journal. B's plan binds each SHA,
    // count and SQL identity; a changed source_batch must never survive
    // publication merely because its parent rows were unchanged.
    index:=make(map[int64]int,len(plan.SQLIDs))
    for i,signedID:=range plan.SQLIDs{
        if signedID<=0{return errors.New("C1 direct: nonpositive signed SQL batch ID")}
        if _,duplicate:=index[signedID];duplicate{
            return errors.New("C1 direct: duplicate signed SQL batch IDs")
        }
        index[signedID]=i
    }
    ledgerRows,e:=tx.Query(ctx,`SELECT source_batch_id,batch_id,record_count,
        data_bytes,manifest_sha256,data_sha256 FROM fi.source_batch
        WHERE recorded_generation_id=$1`,id)
    if e!=nil{return e}
    matched:=0
    for ledgerRows.Next(){
        var batchID,rowCount,dataBytes int64
        var name string
        var manifestSHA,dataSHA []byte
        if e=ledgerRows.Scan(&batchID,&name,&rowCount,&dataBytes,&manifestSHA,&dataSHA);e!=nil{break}
        i,ok:=index[batchID]
        if !ok{e=errors.New("C1 direct: unknown locked canonical batch identity");break}
        signed:=plan.Batches[i]
        if name!=signed.BatchID||rowCount!=int64(signed.Manifest.RecordCount)||
            dataBytes!=signed.Manifest.DataBytes||
            hex.EncodeToString(manifestSHA)!=signed.ManifestSHA256||
            hex.EncodeToString(dataSHA)!=signed.Manifest.DataSHA256{
            e=errors.New("C1 direct: locked canonical batch differs from original signed B plan")
            break
        }
        matched++
    }
    if e==nil{e=ledgerRows.Err()}
    ledgerRows.Close()
    if e!=nil{return e}
    if matched!=len(index){
        return errors.New("C1 direct: locked canonical batch ledger coverage incomplete")
    }
    err=tx.QueryRow(ctx,`SELECT count(*) FROM fi.ingest_journal
       WHERE source_id=$1 AND generation_id=$2 AND outcome='Accepted'`,
        f.SourceID,f.GenerationID).Scan(&accepted)
    if err!=nil{return err}
    if accepted!=0{return errors.New("C1 direct: duplicate canonical Accepted journal rejected")}
    // Recompute ORIGINAL B's signed source-row commitment from the same
    // canonical SQL transaction holding SHARE locks. A valid-looking hex
    // digest is never sufficient to publish Accepted, and mutations after B
    // are impossible while these locks are held.
    lockedProof,err:=c1NativeBLockedSQLRowCommitmentTx(ctx,tx,plan)
    if err!=nil{return fmt.Errorf("C1 direct: locked canonical identity proof: %w",err)}
    if lockedProof!=independentB{
        return errors.New("C1 direct: independently verified original B rows disagree with locked canonical source rows")
    }

    var attempt [16]byte
    if _,err=rand.Read(attempt[:]);err!=nil{return err}
    attemptID:="fi-c1-"+hex.EncodeToString(attempt[:])
    result,err:=tx.Exec(ctx,`INSERT INTO fi.ingest_journal(
       attempt_id,event_sequence,source_id,generation_id,
       transfer_sha256,outcome,stage,records_seen,records_committed,
       ingest_version,detail)
       VALUES($1,1,$2,$3,$4,'Accepted','AuthoritativeRecord',$5,$5,$6,$7)`,
       attemptID,f.SourceID,f.GenerationID,transfer,expected,IngestVersion,
       "independent original signed C1 verifier B passed; direct canonical single SQL write path")
    if err!=nil{return err}
    if result.RowsAffected()!=1{return errors.New("C1 direct: Accepted event not written exactly once")}
    if err=tx.Commit(ctx);err!=nil{
        return fmt.Errorf("C1 direct: Accepted COMMIT uncertain; reconcile read-only before any retry: %w",err)
    }
    return nil
}

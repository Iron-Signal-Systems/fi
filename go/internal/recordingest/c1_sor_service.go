//go:build fi_c1_sor_dev

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// Fi-sor proves the exact original signed generation and existing private
// source-batch SQL IDs, then runs the real C1 SourceParent and five-family
// engine on its LOCAL PostgreSQL socket. Canonical fi tables are never
// writable by this SQL pipeline; privateProjectionTx redirects every COPY.
package recordingest

import (
    "context"
    "encoding/hex"
    "errors"
    "fmt"
    "sync"

    "github.com/Iron-Signal-Systems/fi/go/internal/c1handoff"
    "github.com/jackc/pgx/v5"
)

type C1SoRService struct {
    DSN string
    MaxSQLWorkers int
    SharedRAMDir string // fi-sor read-only nullfs mount path
    // DEVELOPMENT ONLY: explicit opt-in to replay dirty private SQL state
    // from original signed custody. Never set for live SoR until accepted.
    AllowC1Replay bool
    replayMode bool
    replayRead *pgx.Conn
    mu sync.Mutex
    session *c1SoRCommitHandler
    pool *privateC1FiveSQL
    commitReady *privateC1CommitReady
    verifier *c1SoRNativeB
    independentlyVerified bool
    failed error
}

// Must run exclusively inside fi-sor, after the TLS server has authenticated
// the distinct fi-ingest client certificate. Only one active generation is
// permitted, since its C1 source and family buffers are transaction-bound.
func NewC1SoRService(dsn string,maxSQLWorkers int)(*C1SoRService,error){
    if maxSQLWorkers<1||maxSQLWorkers>32{return nil,errors.New("C1 fi-sor: SQL worker maximum must be 1..32")}
    if _,err:=c1SoRLocalConnectionConfig(dsn);err!=nil{return nil,err}
    return &C1SoRService{DSN:dsn,MaxSQLWorkers:maxSQLWorkers},nil
}

func(s *C1SoRService) Bootstrap(ctx context.Context,frame c1handoff.Frame)([]int64,error){
    if s==nil||ctx==nil||frame.Kind!=c1handoff.Start{
        return nil,errors.New("C1 fi-sor: unexpected or missing signed Start")
    }
    if err:=frame.Validate();err!=nil{return nil,err}
    s.mu.Lock()
    defer s.mu.Unlock()
    if s.pool!=nil||s.session!=nil||s.failed!=nil {
        return nil,errors.New("C1 fi-sor: generation already started or prior attempt failed; no automatic replay")
    }
    ids,err:=s.validateSignedPrivateStage(ctx,frame)
    if err!=nil{
        // A partial committed source/family transaction must NEVER be
        // silently replayed. The read-only audit reports the PostgreSQL
        // relational prefix while preserving the original rejection.
        // This does not flush family buffers or authorize restart.
        audit,auditErr:=AuditC1SoRPrivateRecovery(ctx,s.DSN,frame)
        if auditErr==nil {
            fmt.Printf("FI C1 RECOVERY AUDIT source=%s generation=%s complete_parent_batches=%d complete_relational_batches=%d first_unresolved_batch=%d existing_parents=%d dirty_tail=%t automatic_replay=false canonical_unchanged=true\n",
                audit.SourceID,audit.GenerationID,audit.SourceCompletePrefix,
                audit.RelationalCompletePrefix,audit.FirstUnresolvedBatch,
                audit.TotalExistingParents,audit.DirtyTail)
        }else{
            fmt.Printf("FI C1 RECOVERY AUDIT BLOCKED read_only=true reason=%v\n",auditErr)
        }
        s.failed=err
        return nil,err
    }
    counts,err:=s.loadSignedBatchRecordCounts(ctx,ids)
    if err!=nil{s.failed=err;return nil,err}
    pool,err:=newC1SoRSQLPool(ctx,s.DSN,frame.SourceID,s.MaxSQLWorkers)
    if err!=nil{s.failed=err;return nil,err}
    handler,err:=newC1SoRCommitHandler(pool,frame.SourceID,frame.GenerationID,
        frame.ReceiptSHA256,ids,counts,frame.ExpectedRecords)
    if err!=nil{
        pool.Close();s.failed=err
        return nil,err
    }
    if s.SharedRAMDir!=""{
        reader,e:=c1handoff.NewRAMStore(s.SharedRAMDir)
        if e!=nil{pool.Close();s.failed=e;return nil,e}
        handler.sharedRAM=reader
    }
    tracker,verifier,err:=startC1SoRParallelB(ctx,s.DSN,frame,ids,pool)
    if err!=nil{
        pool.Close();s.failed=err
        return nil,fmt.Errorf("C1 fi-sor: independent parallel verifier startup: %w",err)
    }
    if s.replayMode{
        read,_,e:=openC1SoRLocalSQL(ctx,s.DSN,"")
        if e!=nil{
            verifier.Stop();pool.Close();s.failed=e
            return nil,fmt.Errorf("C1 fi-sor: replay read-only SQL session: %w",e)
        }
        s.replayRead=read
    }
    handler.minBatchIndex=frame.StartBatchIndex
    s.pool=pool
    s.session=handler
    s.commitReady=tracker
    s.verifier=verifier
    return append([]int64(nil),ids...),nil
}

func(s *C1SoRService) validateSignedPrivateStage(ctx context.Context,frame c1handoff.Frame)([]int64,error){
    conn,_,err:=openC1SoRLocalSQL(ctx,s.DSN,"")
    if err!=nil{return nil,err}
    defer conn.Close(context.Background())
    tx,err:=conn.BeginTx(ctx,pgx.TxOptions{AccessMode:pgx.ReadOnly})
    if err!=nil{return nil,err}
    defer tx.Rollback(context.Background())
    digest,err:=hex.DecodeString(frame.ReceiptSHA256)
    if err!=nil||len(digest)!=32{return nil,errors.New("C1 fi-sor: original receipt SHA invalid")}
    var canonicalExists bool
    err=tx.QueryRow(ctx,`SELECT EXISTS(SELECT 1 FROM fi.recorded_generation
        WHERE source_id=$1 AND generation_id=$2)`,frame.SourceID,frame.GenerationID).
        Scan(&canonicalExists)
    if err!=nil{return nil,err}
    if canonicalExists{return nil,errors.New("C1 fi-sor: signed generation already exists in authoritative SoR")}
    var generationID,storedRecords,storedBatches int64
    err=tx.QueryRow(ctx,`SELECT recorded_generation_id,record_count,batch_count
        FROM fi_recovery_projection.recorded_generation
        WHERE source_id=$1 AND generation_id=$2 AND receipt_sha256=$3`,
        frame.SourceID,frame.GenerationID,digest).
        Scan(&generationID,&storedRecords,&storedBatches)
    if err!=nil{return nil,fmt.Errorf("C1 fi-sor: original signed shadow generation missing: %w",err)}
    if generationID<=0||storedRecords<=0||storedBatches!=int64(len(frame.BatchIDs)) {
        return nil,errors.New("C1 fi-sor: signed batch count or generation identity mismatches private SoR staging")
    }
    var sourceBatches int64
    err=tx.QueryRow(ctx,`SELECT count(*) FROM fi_recovery_projection.source_batch
        WHERE recorded_generation_id=$1`,generationID).Scan(&sourceBatches)
    if err!=nil{return nil,err}
    if sourceBatches!=storedBatches{
        return nil,errors.New("C1 fi-sor: incomplete or duplicate private source-batch ledger")
    }
    // C1 SQL writer must never mix one signed replay with another
    // relational generation. The immutable seed remains read-only.
    var generations int64
    if err=tx.QueryRow(ctx,`SELECT count(*) FROM fi_recovery_projection.recorded_generation`).
        Scan(&generations);err!=nil{return nil,err}
    if generations!=1 {
        return nil,errors.New("C1 fi-sor: multiple private generations require separate isolated staging")
    }
    original:=make([]PreparedBatch,len(frame.BatchIDs))
    for i,name:=range frame.BatchIDs{original[i].BatchID=name}
    ids,err:=lookupBacklogShadowBatchIDs(ctx,privateProjectionTx{Tx:tx},generationID,original)
    if err!=nil{return nil,fmt.Errorf("C1 fi-sor: signed name to SQL batch mapping: %w",err)}
    var existingSeed,otherMarkers int64
    err=tx.QueryRow(ctx,`SELECT count(*),coalesce(sum(committed_records),0)::bigint
        FROM fi_recovery.typed_window
        WHERE receipt_sha256=$1 AND window_index=0`,digest).
        Scan(&existingSeed,&otherMarkers)
    if err!=nil{return nil,err}
    if existingSeed>1{return nil,errors.New("C1 fi-sor: duplicate verified seed marker")}
    seedRecords:=otherMarkers
    err=tx.QueryRow(ctx,`SELECT count(*) FROM fi_recovery.typed_window
        WHERE receipt_sha256=$1 AND window_index>0`,digest).Scan(&otherMarkers)
    if err!=nil{return nil,err}
    if otherMarkers!=0{
        return nil,errors.New("C1 fi-sor: previous partial typed C1 projection exists; requires isolated reconciliation")
    }
    if seedRecords<0||seedRecords>=storedRecords||
        storedRecords-seedRecords!=frame.ExpectedRecords||
        (seedRecords>0&&frame.StartBatchIndex==0)||
        (seedRecords==0&&frame.StartBatchIndex!=0) {
        return nil,errors.New("C1 fi-sor: signed receipt, verified seed and requested record count disagree")
    }
    if int(frame.StartBatchIndex)>=len(ids){return nil,errors.New("C1 fi-sor: invalid signed seed boundary")}
    // Verify seed length against actual PostgreSQL source-batch
    // manifests, not merely a claimed typed-window counter. The exact
    // remaining source record count must also agree with the signed START.
    var totalDeclared int64
    if err=tx.QueryRow(ctx,`SELECT coalesce(sum(record_count),0)::bigint
        FROM fi_recovery_projection.source_batch WHERE recorded_generation_id=$1`,
        generationID).Scan(&totalDeclared);err!=nil{return nil,err}
    if totalDeclared!=storedRecords{
        return nil,errors.New("C1 fi-sor: receipt source-record total differs from private signed batch manifests")
    }
    if frame.StartBatchIndex>0{
        var seededDeclared int64
        if err=tx.QueryRow(ctx,`SELECT coalesce(sum(record_count),0)::bigint
            FROM fi_recovery_projection.source_batch
            WHERE source_batch_id=ANY($1::bigint[])`,
            ids[:frame.StartBatchIndex]).Scan(&seededDeclared);err!=nil{return nil,err}
        if seededDeclared!=seedRecords {
            return nil,errors.New("C1 fi-sor: private seed marker does not match original signed batch manifest totals")
        }
    }
    var foreignTyped int64
    if err=tx.QueryRow(ctx,`SELECT count(*) FROM fi_recovery.typed_window
        WHERE receipt_sha256<>$1`,digest).Scan(&foreignTyped);err!=nil{return nil,err}
    if foreignTyped>0{
        return nil,errors.New("C1 fi-sor: unrelated typed checkpoint exists in private stage")
    }
    // Prefix parents must match the verified seed EXACTLY. New C1 batches
    // must have NO source rows. Never overwrite, truncate or clean them.
    var committedPrefix,newParents int64
    if frame.StartBatchIndex>0{
        err=tx.QueryRow(ctx,`SELECT count(*) FROM fi_recovery_projection.source_record
            WHERE source_batch_id=ANY($1::bigint[])`,ids[:frame.StartBatchIndex]).
            Scan(&committedPrefix)
        if err!=nil{return nil,err}
    }
    err=tx.QueryRow(ctx,`SELECT count(*) FROM fi_recovery_projection.source_record
        WHERE source_batch_id=ANY($1::bigint[])`,ids[frame.StartBatchIndex:]).
        Scan(&newParents)
    if err!=nil{return nil,err}
    if committedPrefix!=seedRecords{
        return nil,errors.New("C1 fi-sor: immutable verified seed SourceParent prefix changed")
    }
    if newParents>0 {
        if !s.AllowC1Replay{
            return nil,fmt.Errorf("C1 fi-sor: private stage has %d partially committed C1 parents; recovery opt-in and read-only reconciliation required",newParents)
        }
        // Separate READ-ONLY REPEATABLE READ snapshot: source order and
        // typed roots are surveyed before any new SQL writer is created.
        // The SQL identity of each skipped record is additionally matched
        // against original signed custody on each recovered handoff.
        audit,e:=AuditC1SoRPrivateRecovery(ctx,s.DSN,frame)
        if e!=nil{return nil,fmt.Errorf("C1 fi-sor: recovery audit failed closed: %w",e)}
        if audit.TotalExistingParents!=committedPrefix+newParents||
            audit.SourceCompletePrefix<int(frame.StartBatchIndex)||
            audit.RelationalCompletePrefix<int(frame.StartBatchIndex)||
            audit.FirstUnresolvedBatch<int(frame.StartBatchIndex)||
            audit.AutomaticReplayAuthorized{
            return nil,errors.New("C1 fi-sor: inconsistent immutable seed or private PostgreSQL recovery evidence")
        }
        s.replayMode=true
        fmt.Printf("FI C1 PRIVATE REPLAY RECONCILED read_only_audit=true signed_batches=%d existing_parents=%d first_unresolved_batch=%d original_custody_replay_required=true no_ram_journal=true canonical_unchanged=true\\n",
            audit.SignedBatches,newParents,audit.FirstUnresolvedBatch)
    }
    if err=tx.Commit(ctx);err!=nil{return nil,err}
    return ids,nil
}

// loadSignedBatchRecordCounts uses the fi-sor LOCAL read-only database
// to bind each network row ordinal to the immutable original signed
// source_batch manifest. No client-supplied count can enlarge a batch.
func(s *C1SoRService)loadSignedBatchRecordCounts(ctx context.Context,ids []int64)([]int64,error){
    if ctx==nil||len(ids)==0{return nil,errors.New("C1 fi-sor: signed source batch IDs required")}
    conn,_,err:=openC1SoRLocalSQL(ctx,s.DSN,"")
    if err!=nil{return nil,err}
    defer conn.Close(context.Background())
    tx,err:=conn.BeginTx(ctx,pgx.TxOptions{AccessMode:pgx.ReadOnly})
    if err!=nil{return nil,err}
    defer tx.Rollback(context.Background())
    records:=make([]int64,len(ids))
    index:=make(map[int64]int,len(ids))
    for i,id:=range ids{
        if id<=0{return nil,errors.New("C1 fi-sor: nonpositive signed SQL batch identity")}
        if _,exists:=index[id];exists{return nil,errors.New("C1 fi-sor: duplicate signed SQL batch identity")}
        index[id]=i
    }
    rows,err:=tx.Query(ctx,`SELECT source_batch_id,record_count
        FROM fi_recovery_projection.source_batch
        WHERE source_batch_id=ANY($1::bigint[])`,ids)
    if err!=nil{return nil,err}
    found:=0
    for rows.Next(){
        var id,count int64
        if err=rows.Scan(&id,&count);err!=nil{break}
        i,ok:=index[id]
        if !ok||count<=0||records[i]!=0{
            err=errors.New("C1 fi-sor: invalid original signed per-batch record count")
            break
        }
        records[i]=count
        found++
    }
    if err==nil{err=rows.Err()}
    rows.Close()
    if err!=nil{return nil,err}
    if found!=len(ids){return nil,errors.New("C1 fi-sor: missing source_batch rows for original signed identity")}
    if err=tx.Commit(ctx);err!=nil{return nil,err}
    return records,nil
}

// Dispatch accepts signed C1 SQL work in original transport order and
// returns the exact future for THIS PostgreSQL transaction. A's reader
// must not wait for unrelated family commits; B observes committed groups.
func(s *C1SoRService)Dispatch(ctx context.Context,f c1handoff.Frame)(<-chan error,error){
    if s==nil||ctx==nil{return nil,errors.New("C1 fi-sor: unavailable SQL dispatcher")}
    s.mu.Lock()
    defer s.mu.Unlock()
    if s.failed!=nil{return nil,s.failed}
    if s.session==nil||s.pool==nil||s.commitReady==nil{
        return nil,errors.New("C1 fi-sor: START preflight not complete")
    }
    var future <-chan error
    var err error
    if s.replayMode{
        if s.replayRead==nil{return nil,errors.New("C1 fi-sor: replay state missing read-only session")}
        future,err=s.session.EnqueueReplay(ctx,f,s.replayRead)
    }else{
        future,err=s.session.Enqueue(ctx,f)
    }
    if err!=nil{s.failed=err;return nil,err}
    return future,nil
}
func(s *C1SoRService) Commit(ctx context.Context,f c1handoff.Frame)error{
    if s==nil{return errors.New("C1 fi-sor: no service")}
    s.mu.Lock()
    defer s.mu.Unlock()
    if s.failed!=nil{return s.failed}
    if s.session==nil||s.commitReady==nil||s.verifier==nil{
        return errors.New("C1 fi-sor: signed Start and independent B not accepted")
    }
    if err:=f.Validate();err!=nil{return err}
    if f.SourceID!=s.session.sourceID||f.GenerationID!=s.session.generationID||
        f.ReceiptSHA256!=s.session.receipt {
        return errors.New("C1 fi-sor: signed generation changed after B initialization")
    }
    if f.Kind==c1handoff.Seal{
        // Signed reader seal never invokes an SQL family flush.
        if err:=s.commitReady.Seal(int(f.SealedGroup));err!=nil{
            s.failed=err
            return err
        }
        return nil
    }
    if err:=s.session.Commit(ctx,f);err!=nil{
        s.failed=err
        return err
    }
    if f.Kind==c1handoff.Drain{
        // A's final SQL drain is complete. B has been verifying committed
        // groups in parallel; only final publication waits for its proof.
        if err:=s.commitReady.FinishCommitted();err!=nil{
            s.failed=err;return err
        }
        if err:=s.verifier.Finish(ctx);err!=nil{
            s.failed=err;return fmt.Errorf("C1 fi-sor: independent B proof: %w",err)
        }
        s.independentlyVerified=true
    }
    return nil
}
func(s *C1SoRService)Close(){
    if s==nil{return}
    s.mu.Lock()
    defer s.mu.Unlock()
    if s.verifier!=nil{s.verifier.Stop();s.verifier=nil}
    if s.pool!=nil{s.pool.Close();s.pool=nil}
    if s.replayRead!=nil{
        _=s.replayRead.Close(context.Background())
        s.replayRead=nil
    }
}

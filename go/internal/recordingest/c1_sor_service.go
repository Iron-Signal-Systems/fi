//go:build fi_c1_sor_dev

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// Fi-sor validates the original signed generation against governed pending
// metadata, then runs the real C1 SourceParent/five-family SQL engine over
// its LOCAL PostgreSQL socket. Canonical fi tables are never written by
// these independently committed pending SQL/COPY lanes.
package recordingest

import (
    "context"
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
    NativeBCustody c1NativeBCustodyConfig
    AllowC1Replay bool
    replayMode bool
    replayRead *pgx.Conn
    mu sync.Mutex
    session *c1SoRCommitHandler
    pool *privateC1FiveSQL
    commitReady *privateC1CommitReady
    verifier *c1SoRNativeB
    independentlyVerified bool
    publishing bool // serialize FinalProof publication in this SoR session
    // Unexported test seam; production always uses the local PostgreSQL
    // read-only canonical/journal snapshot, never a client status flag.
    canonicalReadback func(context.Context,string,string,string,string)(c1handoff.FinalStatus,error)
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
    // The active two-jail worker must use governed pending relational rows,
    // never the deleted fi_recovery_projection development stage.
    if err:=c1PreflightLocalGovernedPendingSQL(ctx,s.DSN);err!=nil{
        s.failed=err
        return nil,fmt.Errorf("C1 fi-sor: governed pending SQL preflight: %w",err)
    }
    // Dirty pending replay is not yet accepted. Preserve original custody
    // and READY; never silently fall back to the old SQL ingester.
    if frame.StartBatchIndex!=0{
        err:=errors.New("C1 fi-sor: governed pending restart requires read-only reconciliation; no blind replay")
        s.failed=err
        return nil,err
    }
    if err:=StageC1SignedPendingMetadata(ctx,s.DSN,frame,s.NativeBCustody);err!=nil{
        s.failed=err
        return nil,fmt.Errorf("C1 fi-sor: original signed Pending bootstrap: %w",err)
    }
    ids,err:=s.validateSignedPendingStage(ctx,frame)
    if err!=nil{
        s.failed=err
        return nil,fmt.Errorf("C1 fi-sor: signed Pending readback blocked: %w",err)
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
    tracker,verifier,err:=startC1SoRParallelB(ctx,s.DSN,frame,ids,pool,
        s.NativeBCustody)
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
        FROM fi_c1_pending.source_batch
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
// FinalProof is bound to the authenticated Drain ACK and invoked ONLY
// after all SQL COMMIT futures and independent B's original signed-custody
// verification have succeeded. Canonical Accepted still requires one
// atomic publication transaction and an independent read-only readback.
func(s *C1SoRService)FinalProof(ctx context.Context,f c1handoff.Frame)(
    c1handoff.FinalStatus,error,
){
    if s==nil||ctx==nil||f.Kind!=c1handoff.Drain{
        return c1handoff.FinalNone,errors.New("C1 fi-sor: final proof requires signed Drain")
    }
    s.mu.Lock()
    if s.failed!=nil{
        err:=s.failed
        s.mu.Unlock()
        return c1handoff.FinalNone,err
    }
    if !s.independentlyVerified||s.session==nil||!s.session.drained||
        s.pool==nil||s.verifier==nil||
        f.SourceID!=s.session.sourceID||
        f.GenerationID!=s.session.generationID||
        f.ReceiptSHA256!=s.session.receipt{
        s.mu.Unlock()
        return c1handoff.FinalNone,errors.New("C1 fi-sor: SQL or independent B proof not complete")
    }
    if s.publishing {
        s.mu.Unlock()
        return c1handoff.FinalNone,errors.New("C1 fi-sor: canonical publication already in progress")
    }
    dsn,readback,custody:=s.DSN,s.canonicalReadback,s.NativeBCustody
    // The controlled test seam cannot publish, and preserves original
    // unit tests; production has no callback and always uses real SQL.
    if readback!=nil {
        s.mu.Unlock()
        status,err:=readback(ctx,dsn,f.SourceID,f.GenerationID,f.ReceiptSHA256)
        if err!=nil{return c1handoff.FinalNone,err}
        if status!=c1handoff.FinalVerified&&status!=c1handoff.FinalAccepted{
            return c1handoff.FinalNone,errors.New("C1 fi-sor: invalid test readback state")
        }
        return status,nil
    }
    s.publishing=true
    s.mu.Unlock()
    // The independently completed B process is a prerequisite, never an
    // authority to accept. The remapper repeats complete signed proof
    // under table locks, commits all canonical rows + Accepted atomically,
    // then a fresh read-only snapshot proves the actual journal.
    _,err:=PublishC1VerifiedPendingGeneration(ctx,dsn,custody,
        f.SourceID,f.GenerationID,f.ReceiptSHA256)
    var status c1handoff.FinalStatus
    if err==nil {
        status,err=c1PostPublicationReadback(ctx,dsn,
            f.SourceID,f.GenerationID,f.ReceiptSHA256)
    }
    s.mu.Lock()
    s.publishing=false
    if err!=nil{s.failed=err}
    s.mu.Unlock()
    if err!=nil{return c1handoff.FinalNone,fmt.Errorf("C1 fi-sor: canonical publication/Accepted readback: %w",err)}
    return status,nil
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

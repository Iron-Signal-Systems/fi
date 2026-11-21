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
    mu sync.Mutex
    session *c1SoRCommitHandler
    pool *privateC1FiveSQL
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
    if err!=nil{s.failed=err;return nil,err}
    pool,err:=newC1SoRSQLPool(ctx,s.DSN,frame.SourceID,s.MaxSQLWorkers)
    if err!=nil{s.failed=err;return nil,err}
    handler,err:=newC1SoRCommitHandler(pool,frame.SourceID,frame.GenerationID,
        frame.ReceiptSHA256,ids,frame.ExpectedRecords)
    if err!=nil{
        pool.Close();s.failed=err
        return nil,err
    }
    s.pool=pool
    s.session=handler
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
    if committedPrefix!=seedRecords||newParents!=0{
        return nil,fmt.Errorf("C1 fi-sor: private stage is not clean (seed=%d expected=%d new=%d)",
            committedPrefix,seedRecords,newParents)
    }
    if err=tx.Commit(ctx);err!=nil{return nil,err}
    return ids,nil
}

func(s *C1SoRService) Commit(ctx context.Context,f c1handoff.Frame)error{
    if s==nil{return errors.New("C1 fi-sor: no service")}
    s.mu.Lock()
    defer s.mu.Unlock()
    if s.failed!=nil{return s.failed}
    if s.session==nil{return errors.New("C1 fi-sor: signed Start not accepted")}
    if err:=s.session.Commit(ctx,f);err!=nil{
        s.failed=err
        return err
    }
    return nil
}
func(s *C1SoRService)Close(){
    if s==nil{return}
    s.mu.Lock()
    defer s.mu.Unlock()
    if s.pool!=nil{s.pool.Close();s.pool=nil}
}

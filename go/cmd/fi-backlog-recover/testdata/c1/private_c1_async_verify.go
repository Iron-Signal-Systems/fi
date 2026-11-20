// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// C1 C220 PRIVATE-CLONE DEVELOPMENT. No polling or SHA-only queued work.
// A signed group is verified once, after P6 proves ALL of its ordered
// source-parent and five-family SQL transactions committed successfully.
// The verifier uses a distinct read-only PG session. It cannot create or
// modify typed markers, Accepted, or authoritative publication.
package recordingest

import (
    "context"
    "errors"
    "fmt"
    "os"
    "sync"
    "time"

    "github.com/jackc/pgx/v5"
)

type privateC1AsyncVerifier struct {
    ctx context.Context
    cancel context.CancelFunc
    ready <-chan int
    finalDrain chan struct{}
    markDrain sync.Once
    done chan struct{}
    start,end int
    checked []bool
    passed chan int // bounded proof-completion receipts for tests and diagnostics
    during int
    check func(context.Context,int)error
    onFailure func(error)
    requireDuring bool
    err error // worker-owned; read only after <-done
}

func newPrivateC1AsyncVerifier(ctx context.Context,start,end int,
    ready <-chan int,check func(context.Context,int)error,
    onFailure func(error),requireDuring bool,
)(*privateC1AsyncVerifier,error){
    if ctx==nil||ready==nil||check==nil||start<1||end<=start{
        return nil,errors.New("FI C1 commit-ready verifier: invalid input")
    }
    own,cancel:=context.WithCancel(ctx)
    v:=&privateC1AsyncVerifier{
        ctx:own,cancel:cancel,ready:ready,
        start:start,end:end,checked:make([]bool,end),
        passed:make(chan int,end-start),
        finalDrain:make(chan struct{}),done:make(chan struct{}),
        check:check,onFailure:onFailure,requireDuring:requireDuring,
    }
    go v.run()
    return v,nil
}

func(v *privateC1AsyncVerifier) run(){
    defer close(v.done)
    for {
        var wi int
        select{
        case <-v.ctx.Done():
            v.err=v.ctx.Err()
            return
        case next,ok:=<-v.ready:
            if !ok{return}
            wi=next
        }
        if wi<v.start||wi>=v.end||v.checked[wi]{
            v.fail(fmt.Errorf("FI C1 commit-ready verifier: duplicate/invalid group %d",wi))
            return
        }
        started:=time.Now()
        // Read-only REPEATABLE READ snapshot. Readiness is a durable
        // SQL commitment condition, not a speculative retry condition.
        if err:=v.check(v.ctx,wi);err!=nil{
            v.fail(fmt.Errorf("FI C1 commit-ready verifier: group %d relational proof: %w",wi,err))
            return
        }
        phase:="during_ingest"
        select{
        case <-v.finalDrain:
            phase="after_drain"
        default:
            v.during++
        }
        v.checked[wi]=true
        fmt.Printf("FI C1 ASYNC VERIFY PASS window=%d attempts=1 phase=%s duration=%s read_only=true independent_connection=true commit_ready=true\n",
            wi,phase,time.Since(started))
        v.passed<-wi
    }
}

func(v *privateC1AsyncVerifier) fail(err error){
    v.err=err
    fmt.Printf("FI C1 ASYNC VERIFY FAIL error=%v read_only=true fail_closed=true\n",err)
    if v.onFailure!=nil{v.onFailure(err)}
}

func(v *privateC1AsyncVerifier) MarkDrained(){
    if v!=nil{v.markDrain.Do(func(){close(v.finalDrain)})}
}

// Caller must first finalize P6 and close the commit-ready notification
// channel. No marker is inserted until every read-only group proof passes.
// In the 8GiB test, at least Group 1 must pass BEFORE final SQL drain.
func(v *privateC1AsyncVerifier) Finish(ctx context.Context)error{
    if v==nil||ctx==nil{return errors.New("FI C1 commit-ready verifier: invalid final gate")}
    v.MarkDrained()
    select{
    case <-ctx.Done():return ctx.Err()
    case <-v.done:
    }
    if v.err!=nil{return v.err}
    for wi:=v.start;wi<v.end;wi++{
        if !v.checked[wi]{
            return fmt.Errorf("FI C1 commit-ready verifier: group %d lacks relational proof",wi)
        }
    }
    if v.requireDuring&&v.during==0{
        return errors.New("FI C1 commit-ready verifier: architecture FAIL: no group passed DURING ongoing P5/P6 ingestion")
    }
    fmt.Printf("FI C1 ASYNC VERIFY COMPLETE groups=%d during_ingest=%d after_drain=%d independent_read_only=true committed_ready=true original_relational_rescans=removed final_marker_gate=preserved\n",
        v.end-v.start,v.during,v.end-v.start-v.during)
    return nil
}

func(v *privateC1AsyncVerifier) Stop(){
    if v==nil{return}
    v.cancel()
    <-v.done
}

func privateC1AsyncVerifyGroup(ctx context.Context,conn *pgx.Conn,
    g *PreparedGeneration,ds []BacklogCheckpointDescriptor,wi int,
)error{
    if ctx==nil||conn==nil||g==nil||wi<1||wi>=len(ds){
        return errors.New("FI C1 commit-ready verifier: invalid original signed group")
    }
    d:=ds[wi]
    tx,err:=conn.BeginTx(ctx,pgx.TxOptions{IsoLevel:pgx.RepeatableRead,AccessMode:pgx.ReadOnly})
    if err!=nil{return err}
    defer tx.Rollback(context.Background())
    shadow:=privateProjectionTx{Tx:tx}
    id,ok,err:=lookupRecordedGeneration(ctx,shadow,
        ds[0].SourceID,ds[0].GenerationID,g.Receipt.TransferSHA256,g.ReceiptSHA256)
    if err!=nil{return err}
    if !ok||id<=0{return errors.New("FI C1 commit-ready verifier: signed shadow generation missing")}
    if err=verifyBacklogShadowWindowCounts(ctx,shadow,id,
        g.Batches[d.StartBatch:d.EndBatch],
        int64(d.EndRecord-d.StartRecord),int64(d.DataBytes));err!=nil{
        return fmt.Errorf("group %d source-count proof: %w",wi,err)
    }
    if err=verifyBacklogWindowProjectionCoverage(ctx,shadow,id,
        g.Batches[d.StartBatch:d.EndBatch]);err!=nil{
        return fmt.Errorf("group %d relational-coverage proof: %w",wi,err)
    }
    return tx.Commit(ctx)
}

func privateC1StartAsyncVerify(ctx context.Context,dsn,pgdata string,
    g *PreparedGeneration,ds []BacklogCheckpointDescriptor,start,end int,
    ready <-chan int,onFailure func(error),
)(*privateC1AsyncVerifier,error){
    if !privateC1Enabled()||os.Getenv("FI_C1_DEV_ASYNC_VERIFY")!="1"||
        g==nil||start<1||end>len(ds){
        return nil,errors.New("FI C1 commit-ready verifier: private clone and explicit dev flag required")
    }
    conn,pid,err:=privateC1CloneConnection(ctx,dsn,pgdata)
    if err!=nil{return nil,err}
    v,err:=newPrivateC1AsyncVerifier(ctx,start,end,ready,
        func(c context.Context,wi int)error{
            return privateC1AsyncVerifyGroup(c,conn,g,ds,wi)
        },onFailure,true)
    if err!=nil{_ =conn.Close(context.Background());return nil,err}
    go func(){<-v.done;_ =conn.Close(context.Background())}()
    fmt.Printf("FI C1 ASYNC VERIFY START groups=%d postgres_pid=%d read_only=true independent_connection=true trigger=durable_sql_acks one_attempt_per_ready_group=true\n",
        end-start,pid)
    return v,nil
}

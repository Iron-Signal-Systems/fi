// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// C1 C220 PRIVATE-CLONE EXPERIMENT ONLY: independently connected,
// read-only background relational verification of hash-sealed signed groups.
// It NEVER emits typed/source/artifact completion markers or Accepted.
// PostgreSQL source and family commits still obey all existing ACK fences.
// Final marker transaction MUST retain the original transactional checks
// until a separate correctness experiment explicitly replaces them.
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

const privateC1AsyncVerifyRetry = 3 * time.Second

// All fields except results and err are owned by the single worker, or
// are initialized before it starts. Seal is called ONLY by the signed
// reader; Finish is called ONLY by the main C1 ingestion goroutine.
type privateC1AsyncVerifier struct {
    ctx context.Context
    cancel context.CancelFunc
    sealed chan int
    finalDrain chan struct{}
    done chan struct{}
    once sync.Once
    nextSeal int
    end int
    start int
    checked []bool
    check func(context.Context,int) error
    retry time.Duration
    err error  // readable only after <-done
}

func newPrivateC1AsyncVerifier(ctx context.Context,start,end int,
    check func(context.Context,int)error,
)(*privateC1AsyncVerifier,error){
    if ctx==nil||check==nil||start<1||end<=start{
        return nil,errors.New("FI C1 async verifier: invalid signed-group bounds")
    }
    workerCtx,cancel:=context.WithCancel(ctx)
    v:=&privateC1AsyncVerifier{
        ctx:workerCtx,cancel:cancel,start:start,end:end,nextSeal:start,
        sealed:make(chan int,end-start),
        finalDrain:make(chan struct{}),
        done:make(chan struct{}),
        checked:make([]bool,end),
        check:check,retry:privateC1AsyncVerifyRetry,
    }
    go v.run()
    return v,nil
}

// After a signed batch SHA/count/bytes/LF passes, the reader may signal
// a complete 4GiB reporting group. The bounded send NEVER waits for SQL,
// verification, or PostgreSQL. The verification worker handles SQL itself.
func(v *privateC1AsyncVerifier) Seal(wi int)error{
    if v==nil||wi!=v.nextSeal||wi>=v.end{
        return fmt.Errorf("FI C1 async verifier: out-of-order sealed group %d",wi)
    }
    select {
    case <-v.ctx.Done():return v.ctx.Err()
    case v.sealed<-wi:
        v.nextSeal++
        return nil
    default:
        return errors.New("FI C1 async verifier: bounded group receipt queue full")
    }
}

func(v *privateC1AsyncVerifier) run(){
    defer close(v.done)
    for {
        var wi int
        select {
        case <-v.ctx.Done():
            v.err=v.ctx.Err()
            return
        case next,ok:=<-v.sealed:
            if !ok{return}
            wi=next
        }
        attempts:=0
        started:=time.Now()
        for {
            attempts++
            checkErr:=v.check(v.ctx,wi)
            if checkErr==nil {
                v.checked[wi]=true
                phase:="during_ingest"
                select{case <-v.finalDrain:phase="after_drain";default:}
                fmt.Printf("FI C1 ASYNC VERIFY PASS window=%d attempts=%d phase=%s duration=%s read_only=true independent_connection=true\n",
                    wi,attempts,phase,time.Since(started))
                break
            }
            // An incomplete group is normal while P6 still has queued SQL.
            // SQL/relational failures are NOT treated as PASS or durable.
            select {
            case <-v.ctx.Done():
                v.err=v.ctx.Err()
                return
            case <-v.finalDrain:
                // All P6 SQL commits have now ACKed. A final read-only
                // snapshot must pass; any discrepancy is fatal.
                attempts++
                if err:=v.check(v.ctx,wi);err!=nil{
                    v.err=fmt.Errorf("FI C1 async verifier: post-drain group %d proof failed: %w",wi,err)
                    return
                }
                v.checked[wi]=true
                fmt.Printf("FI C1 ASYNC VERIFY PASS window=%d attempts=%d phase=after_drain duration=%s read_only=true independent_connection=true\n",
                    wi,attempts,time.Since(started))
                break
            case <-time.After(v.retry):
            }
            if v.checked[wi]{break}
        }
    }
}

// Finish is a final fail-closed gate AFTER buffers.Finish / all P6 SQL ACKs.
// It waits for background receipts but does not run SQL on the P5/P6 thread.
func(v *privateC1AsyncVerifier) Finish(ctx context.Context)error{
    if v==nil||ctx==nil{return errors.New("FI C1 async verifier: invalid final gate")}
    if v.nextSeal!=v.end{
        return fmt.Errorf("FI C1 async verifier: not all signed groups hash sealed %d/%d",
            v.nextSeal-v.start,v.end-v.start)
    }
    v.once.Do(func(){close(v.finalDrain);close(v.sealed)})
    select {
    case <-ctx.Done():return ctx.Err()
    case <-v.done:
    }
    if v.err!=nil{return v.err}
    for i:=v.start;i<v.end;i++{
        if !v.checked[i]{
            return fmt.Errorf("FI C1 async verifier: group %d has no successful relational proof",i)
        }
    }
    fmt.Printf("FI C1 ASYNC VERIFY COMPLETE groups=%d independent_read_only=true sealed_sha=true final_marker_unchanged=true\n",
        v.end-v.start)
    return nil
}

func(v *privateC1AsyncVerifier) Stop(){
    if v==nil{return}
    v.cancel()
    // An aborted run may leave the receiver sending fewer group receipts.
    // Close isn't needed: cancellation interrupts both verifier waits and
    // any PostgreSQL query using the verifier-owned context.
    <-v.done
}

// Every attempted snapshot is transactionally consistent and read-only.
// A mismatch while ingest is active is pending, not accepted or published.
func privateC1AsyncVerifyGroup(ctx context.Context,conn *pgx.Conn,
    g *PreparedGeneration,ds []BacklogCheckpointDescriptor,wi int,
)error{
    if ctx==nil||conn==nil||g==nil||wi<1||wi>=len(ds){
        return errors.New("FI C1 async verifier: invalid original signed group")
    }
    d:=ds[wi]
    tx,err:=conn.BeginTx(ctx,pgx.TxOptions{IsoLevel:pgx.RepeatableRead,AccessMode:pgx.ReadOnly})
    if err!=nil{return err}
    defer tx.Rollback(context.Background())
    shadow:=privateProjectionTx{Tx:tx}
    id,ok,err:=lookupRecordedGeneration(ctx,shadow,
        ds[0].SourceID,ds[0].GenerationID,g.Receipt.TransferSHA256,g.ReceiptSHA256)
    if err!=nil{return err}
    if !ok||id<=0{return errors.New("FI C1 async verifier: signed shadow generation missing")}
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
)(*privateC1AsyncVerifier,error){
    if !privateC1Enabled()||os.Getenv("FI_C1_DEV_ASYNC_VERIFY")!="1"||
        g==nil||start<1||end>len(ds){
        return nil,errors.New("FI C1 async verifier: private clone and explicit experiment flag required")
    }
    conn,pid,err:=privateC1CloneConnection(ctx,dsn,pgdata)
    if err!=nil{return nil,err}
    // This connection is owned by exactly one independent worker. Its
    // closure is tied to worker lifetime, not to any P6 family transaction.
    v,err:=newPrivateC1AsyncVerifier(ctx,start,end,func(c context.Context,wi int)error{
        return privateC1AsyncVerifyGroup(c,conn,g,ds,wi)
    })
    if err!=nil{_ =conn.Close(context.Background());return nil,err}
    workerDone:=v.done
    // Close the verifier SQL session only after the worker has stopped.
    go func(){<-workerDone;_ =conn.Close(context.Background())}()
    fmt.Printf("FI C1 ASYNC VERIFY START groups=%d postgres_pid=%d read_only=true independent_connection=true no_marker_writes=true\n",
        end-start,pid)
    return v,nil
}

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// PRIVATE CLONE ONLY: five truly independent PostgreSQL family writers.
// The signed parent ledger commits before the family rows are admitted.
// Family writes MUST NOT create the W512 typed/Accepted completion marker:
// only a separate final verification transaction can do so.
//
// This engine supplies bounded, asynchronous handoffs and fail-closed
// accounting. The five-connection SQL integration is staged separately;
// never substitute this for P6's single-transaction production path.
package recordingest

import (
    "context"
    "errors"
    "fmt"
    "sync"
)

const (
    privateP7QueueSlots=2
    privateP7MaxQueuedBytes int64=256 << 20
)

type privateP7SourceLedger interface{
    Source(ctx context.Context,rows []privateP6Record)error
    Close(ctx context.Context)error
}
type privateP7FamilyWriter interface{
    Write(ctx context.Context,rows []privateP6Record)error
    Close(ctx context.Context)error
}
type privateP7WriterFactory func(ctx context.Context,family privateP6Family)(
    privateP7FamilyWriter,error,
)
type privateP7SourceKey struct{Batch int64;Ordinal int64}
type privateP7Proof struct{
    Digest [32]byte
    Family privateP6Family
    Bytes int
}
type privateP7Job struct{
    rows []privateP6Record
    bytes int64
}
type privateP7Lane struct{
    writer privateP7FamilyWriter
    jobs chan privateP7Job
    queued int64
    committed int64
    handoffs int64
    committedHandoffs int64
    peakQueued int64
    peakBytes int64
}
type privateP7FiveWriter struct{
    ctx context.Context
    cancel context.CancelCauseFunc
    ledger privateP7SourceLedger
    lanes [privateP6FamilyCount]*privateP7Lane
    wg sync.WaitGroup
    mu sync.Mutex
    changed chan struct{}
    usedBytes int64
    peakBytes int64
    sourceRows int64
    typedRows int64
    sourceCommitted map[privateP7SourceKey]privateP7Proof
    failed error
    finished bool
    closed bool
}

func newPrivateP7FiveWriter(
    ctx context.Context,ledger privateP7SourceLedger,factory privateP7WriterFactory,
)(*privateP7FiveWriter,error){
    if ctx==nil||ledger==nil||factory==nil{
        return nil,errors.New("FI five-writer: missing parent ledger, factory or context")
    }
    workerCtx,cancel:=context.WithCancelCause(ctx)
    s:=&privateP7FiveWriter{
        ctx:workerCtx,cancel:cancel,ledger:ledger,changed:make(chan struct{}),
        sourceCommitted:make(map[privateP7SourceKey]privateP7Proof),
    }
    for f:=privateP6Family(0);f<privateP6FamilyCount;f++{
        w,err:=factory(workerCtx,f)
        if err!=nil||w==nil{
            if err==nil{err=errors.New("nil dedicated PostgreSQL family connection")}
            s.fail(err)
            s.Close(context.Background())
            return nil,fmt.Errorf("FI five-writer: %s connection: %w",
                privateP6FamilyNames[f],err)
        }
        s.lanes[f]=&privateP7Lane{
            writer:w,jobs:make(chan privateP7Job,privateP7QueueSlots),
        }
        s.wg.Add(1)
        go s.run(f)
    }
    return s,nil
}
func(s *privateP7FiveWriter) signalLocked(){
    close(s.changed)
    s.changed=make(chan struct{})
}
func(s *privateP7FiveWriter) fail(err error){
    if err==nil{return}
    s.mu.Lock()
    if s.failed==nil{
        s.failed=err
        s.cancel(err)
    }
    s.signalLocked()
    s.mu.Unlock()
}
func(s *privateP7FiveWriter) errorLocked()error{
    if s.failed!=nil{return s.failed}
    if err:=context.Cause(s.ctx);err!=nil{return err}
    if s.closed{return errors.New("FI five-writer: already closed")}
    return nil
}
func(s *privateP7FiveWriter) reserve(ctx context.Context,n int64)error{
    if n<1||n>privateP7MaxQueuedBytes{
        return fmt.Errorf("FI five-writer: handoff exceeds 256MiB bound: %d",n)
    }
    for{
        s.mu.Lock()
        if err:=s.errorLocked();err!=nil{s.mu.Unlock();return err}
        if n<=privateP7MaxQueuedBytes-s.usedBytes{
            s.usedBytes+=n
            if s.usedBytes>s.peakBytes{s.peakBytes=s.usedBytes}
            s.mu.Unlock()
            return nil
        }
        changed:=s.changed
        s.mu.Unlock()
        select{
        case <-ctx.Done():return ctx.Err()
        case <-s.ctx.Done():return context.Cause(s.ctx)
        case <-changed:
        }
    }
}
func(s *privateP7FiveWriter) release(n int64){
    s.mu.Lock()
    s.usedBytes-=n
    if s.usedBytes<0{
        s.mu.Unlock()
        panic("FI five-writer: negative bounded handoff bytes")
    }
    s.signalLocked()
    s.mu.Unlock()
}
func(s *privateP7FiveWriter) run(f privateP6Family){
    defer s.wg.Done()
    l:=s.lanes[f]
    for{
        select{
        case <-s.ctx.Done():
            // A private failed attempt is never published; the caller must
            // dispose its isolated clone rather than retry half-written data.
            for{
                select{
                case job:=<-l.jobs:
                    s.release(job.bytes)
                    s.mu.Lock()
                    l.queued-=int64(len(job.rows))
                    s.signalLocked()
                    s.mu.Unlock()
                default:return
                }
            }
        case job:=<-l.jobs:
            if len(job.rows)==0 {s.fail(errors.New("FI five-writer: empty SQL job"));continue}
            // A distinct single-writer PG connection is owned by this lane.
            err:=l.writer.Write(s.ctx,job.rows)
            s.mu.Lock()
            l.queued-=int64(len(job.rows))
            if err==nil{
                l.committed+=int64(len(job.rows))
                l.committedHandoffs++
            }
            s.signalLocked()
            s.mu.Unlock()
            s.release(job.bytes)
            if err!=nil{
                s.fail(fmt.Errorf("FI five-writer: %s relational transaction: %w",
                    privateP6FamilyNames[f],err))
                return
            }
        }
    }
}

// Signed source parents are committed in strictly increasing original
// (source_batch_id,ordinal) order BEFORE a family may commit any child.
func(s *privateP7FiveWriter) Source(ctx context.Context,rows []privateP6Record)error{
    if s==nil||ctx==nil||len(rows)==0{return errors.New("FI five-writer: invalid source batch")}
    s.mu.Lock()
    err:=s.errorLocked()
    if err==nil&&s.finished{err=errors.New("FI five-writer: source after barrier")}
    s.mu.Unlock()
    if err!=nil{return err}
    local:=make(map[privateP7SourceKey]privateP7Proof,len(rows))
    for _,r:=range rows{
        if !r.valid(){return errors.New("FI five-writer: bad signed source record")}
        f,err:=privateP6KindFamily(r.prepared.Record.RecordKind)
        if err!=nil{return err}
        key:=privateP7SourceKey{r.sourceBatchID,r.ordinal}
        if _,found:=local[key];found{return errors.New("FI five-writer: duplicate signed source in COPY")}
        local[key]=privateP7Proof{r.prepared.RecordDigest,f,r.prepared.RecordBytes}
    }
    s.mu.Lock()
    for key:=range local {
        if _,exists:=s.sourceCommitted[key];exists{
            s.mu.Unlock()
            return errors.New("FI five-writer: signed parent inserted twice")
        }
    }
    s.mu.Unlock()
    // This call is SYNCHRONOUS and its PostgreSQL transaction MUST commit
    // before Source returns. Family writer transactions can then see FKs.
    if err:=s.ledger.Source(ctx,rows);err!=nil{
        s.fail(fmt.Errorf("FI five-writer: parent source ledger COPY: %w",err))
        return err
    }
    s.mu.Lock()
    for k,v:=range local{s.sourceCommitted[k]=v}
    s.sourceRows+=int64(len(rows))
    s.signalLocked()
    s.mu.Unlock()
    return nil
}

func(s *privateP7FiveWriter) waitFamily(ctx context.Context,f privateP6Family)error{
    for{
        s.mu.Lock()
        if err:=s.errorLocked();err!=nil{s.mu.Unlock();return err}
        if s.lanes[f].queued==0{s.mu.Unlock();return nil}
        ch:=s.changed
        s.mu.Unlock()
        select{
        case <-ctx.Done():return ctx.Err()
        case <-s.ctx.Done():return context.Cause(s.ctx)
        case <-ch:
        }
    }
}

// Family owns the SQL-ready batch after admission, so the caller may
// promptly refill its same-family buffer without waiting for PostgreSQL.
// A USN write fences prior File work only; it never drains Security etc.
func(s *privateP7FiveWriter) Family(ctx context.Context,
    f privateP6Family,rows []privateP6Record)error{
    if s==nil||ctx==nil||f>=privateP6FamilyCount||len(rows)==0{
        return errors.New("FI five-writer: invalid family SQL handoff")
    }
    if f==privateP6USN{
        if err:=s.waitFamily(ctx,privateP6File);err!=nil{return err}
    }
    copyRows:=append([]privateP6Record(nil),rows...)
    var n int64
    local:=make(map[privateP7SourceKey]struct{},len(copyRows))
    for _,r:=range copyRows{
        if !r.valid(){return errors.New("FI five-writer: invalid signed child row")}
        actual,err:=privateP6KindFamily(r.prepared.Record.RecordKind)
        if err!=nil||actual!=f{return errors.New("FI five-writer: family mismatch")}
        key:=privateP7SourceKey{r.sourceBatchID,r.ordinal}
        if _,ok:=local[key];ok{return errors.New("FI five-writer: duplicate child in handoff")}
        local[key]=struct{}{}
        n+=int64(r.prepared.RecordBytes)
    }
    if err:=s.reserve(ctx,n);err!=nil{return err}
    s.mu.Lock()
    err:=s.errorLocked()
    if err==nil&&s.finished{err=errors.New("FI five-writer: handoff after completion")}
    if err==nil{
        for _,r:=range copyRows{
            key:=privateP7SourceKey{r.sourceBatchID,r.ordinal}
            proof,ok:=s.sourceCommitted[key]
            if !ok||proof.Digest!=r.prepared.RecordDigest||
                proof.Family!=f||proof.Bytes!=r.prepared.RecordBytes{
                err=errors.New("FI five-writer: child lacks exact committed signed parent")
                break
            }
        }
    }
    if err!=nil{s.mu.Unlock();s.release(n);return err}
    for key:=range local{delete(s.sourceCommitted,key)}
    l:=s.lanes[f]
    l.queued+=int64(len(copyRows))
    l.handoffs++
    s.typedRows+=int64(len(copyRows))
    if l.queued>l.peakQueued{l.peakQueued=l.queued}
    if n>l.peakBytes{l.peakBytes=n}
    s.signalLocked()
    s.mu.Unlock()
    select{
    case <-ctx.Done():
        s.fail(ctx.Err())
        return ctx.Err()
    case <-s.ctx.Done():
        return context.Cause(s.ctx)
    case l.jobs<-privateP7Job{rows:copyRows,bytes:n}:
        return nil
    }
}

// Drain is a REQUIRED precondition of the W512 final verification/marker.
// In-memory P6 buffer totals cannot substitute for committed SQL receipts.
func(s *privateP7FiveWriter) Drain(ctx context.Context)error{
    if s==nil||ctx==nil{return errors.New("FI five-writer: nil final barrier")}
    s.mu.Lock()
    if err:=s.errorLocked();err!=nil{s.mu.Unlock();return err}
    if s.finished{s.mu.Unlock();return errors.New("FI five-writer: repeated window barrier")}
    s.finished=true
    for{
        if err:=s.errorLocked();err!=nil{s.mu.Unlock();return err}
        var pending int64
        var committed int64
        for _,l:=range s.lanes{pending+=l.queued;committed+=l.committed}
        if pending==0{
            if committed!=s.sourceRows||committed!=s.typedRows||
                len(s.sourceCommitted)!=0||s.usedBytes!=0{
                err:=fmt.Errorf("FI five-writer: incomplete relational barrier source=%d typed=%d committed=%d unowned=%d bytes=%d",
                    s.sourceRows,s.typedRows,committed,len(s.sourceCommitted),s.usedBytes)
                s.mu.Unlock()
                s.fail(err)
                return err
            }
            s.mu.Unlock()
            return nil
        }
        ch:=s.changed
        s.mu.Unlock()
        select{
        case <-ctx.Done():s.fail(ctx.Err());return ctx.Err()
        case <-s.ctx.Done():return context.Cause(s.ctx)
        case <-ch:
        }
        s.mu.Lock()
    }
}

func(s *privateP7FiveWriter) Stats() (sourceRows,committedRows,peakBytes int64,
    committedByFamily [privateP6FamilyCount]int64){
    s.mu.Lock()
    defer s.mu.Unlock()
    sourceRows=s.sourceRows;peakBytes=s.peakBytes
    for f,l:=range s.lanes{
        committedByFamily[f]=l.committed
        committedRows+=l.committed
    }
    return
}
func(s *privateP7FiveWriter) Close(ctx context.Context)error{
    if s==nil{return nil}
    s.mu.Lock()
    if s.closed{s.mu.Unlock();return errors.New("FI five-writer: Close called twice")}
    s.closed=true
    s.cancel(errors.New("FI five-writer: closed"))
    s.signalLocked()
    s.mu.Unlock()
    s.wg.Wait()
    var out error
    for _,l:=range s.lanes{
        if l!=nil&&l.writer!=nil {
            if err:=l.writer.Close(ctx);err!=nil{out=errors.Join(out,err)}
        }
    }
    if err:=s.ledger.Close(ctx);err!=nil{out=errors.Join(out,err)}
    return out
}

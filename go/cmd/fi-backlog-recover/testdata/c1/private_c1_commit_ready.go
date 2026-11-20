// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// Clone-only C1: independent P6 COMMIT-readiness accounting. Group boundaries
// are NOT P5/P6 flush or restart boundaries. An original receiver-verified
// group becomes eligible for read-only verification after all of its cached
// batch boundaries pass count/byte/LF checks, every source-parent SQL
// transaction commits, and every typed-family SQL transaction commits. These are transactional success receipts, not merely
// enqueued jobs or ACKs waiting in the reader's FIFO.
package recordingest

import (
    "errors"
    "fmt"
    "sort"
    "sync"
)

type privateC1CommittedGroup struct {
    firstBatch, endBatch int
    expected int64
    source int64
    typed int64
    sealed bool
    ready bool
}

type privateC1CommitReady struct {
    mu sync.Mutex
    start int
    groups []privateC1CommittedGroup
    notifications chan int
    lastSeal int
    finished bool
    failed error
}

// Exactly one indexed entry per requested group. A bounded channel permits
// workers to publish readiness without waiting for the verifier's SQL queries.
func newPrivateC1CommitReady(ds []BacklogCheckpointDescriptor,start,end int)(
    *privateC1CommitReady,error,
){
    if start<1||end<=start||end>len(ds){
        return nil,errors.New("FI C1 committed readiness: invalid signed group range")
    }
    t:=&privateC1CommitReady{
        start:start,lastSeal:start,
        groups:make([]privateC1CommittedGroup,end-start),
        notifications:make(chan int,end-start),
    }
    for i:=start;i<end;i++{
        d:=ds[i]
        prev:=ds[i-1]
        if d.StartBatch!=prev.EndBatch||d.StartRecord!=prev.EndRecord||
            d.EndBatch<=d.StartBatch||d.EndRecord<=d.StartRecord||
            d.ReceiptSHA256!=ds[0].ReceiptSHA256||
            d.PreviousDigestSHA256!=prev.DigestSHA256{
            return nil,fmt.Errorf("FI C1 committed readiness: invalid signed descriptor %d",i)
        }
        t.groups[i-start]=privateC1CommittedGroup{
            firstBatch:d.StartBatch,endBatch:d.EndBatch,
            expected:int64(d.EndRecord-d.StartRecord),
        }
    }
    return t,nil
}

// Called by the continuous custody-bound reader, never by SQL workers.
func(t *privateC1CommitReady) Seal(wi int)error{
    if t==nil{return errors.New("FI C1 committed readiness: nil tracker")}
    t.mu.Lock()
    defer t.mu.Unlock()
    if t.failed!=nil{return t.failed}
    if t.finished||wi!=t.lastSeal||wi<t.start||
        wi>=t.start+len(t.groups){
        return fmt.Errorf("FI C1 committed readiness: signed seal out of order %d",wi)
    }
    t.groups[wi-t.start].sealed=true
    t.lastSeal++
    return t.readyLocked(wi)
}

// Commit only after PostgreSQL's transaction commit returned success. Any
// transaction spanning reporting groups updates both groups atomically.
// This does not alter parent ACK order, family handoffs, or P6 buffer policy.
func(t *privateC1CommitReady) CommitSource(rows []privateP6Record)error{
    return t.committed(rows,true)
}
func(t *privateC1CommitReady) CommitFamily(rows []privateP6Record)error{
    return t.committed(rows,false)
}
func(t *privateC1CommitReady) committed(rows []privateP6Record,parent bool)error{
    if t==nil||len(rows)==0{
        return errors.New("FI C1 committed readiness: empty durable SQL receipt")
    }
    // Count outside the mutex to avoid adding per-record lock contention.
    counts:=make([]int64,len(t.groups))
    for _,row:=range rows{
        idx:=sort.Search(len(t.groups),func(i int)bool{
            return row.signedBatchIndex<t.groups[i].endBatch
        })
        if idx>=len(t.groups)||
            row.signedBatchIndex<t.groups[idx].firstBatch||
            row.signedBatchIndex>=t.groups[idx].endBatch{
            return fmt.Errorf("FI C1 committed readiness: committed batch %d outside signed groups",
                row.signedBatchIndex)
        }
        counts[idx]++
    }
    t.mu.Lock()
    defer t.mu.Unlock()
    if t.failed!=nil{return t.failed}
    if t.finished{return errors.New("FI C1 committed readiness: SQL commit after completion")}
    for idx,n:=range counts{
        if n==0{continue}
        g:=&t.groups[idx]
        if parent{g.source+=n}else{g.typed+=n}
        if g.source>g.expected||g.typed>g.expected{
            t.failed=fmt.Errorf("FI C1 committed readiness: group %d overcommitted source=%d typed=%d expected=%d",
                idx+t.start,g.source,g.typed,g.expected)
            return t.failed
        }
    }
    for idx,n:=range counts{
        if n>0{
            if err:=t.readyLocked(idx+t.start);err!=nil{return err}
        }
    }
    return nil
}

func(t *privateC1CommitReady) readyLocked(wi int)error{
    if t.failed!=nil{return t.failed}
    g:=&t.groups[wi-t.start]
    if !g.ready&&g.sealed&&g.source==g.expected&&g.typed==g.expected{
        g.ready=true
        select{
        case t.notifications<-wi:
            fmt.Printf("FI C1 COMMIT READY window=%d source_committed=%d typed_committed=%d custody_batch_sealed=true no_group_flush=true\n",
                wi,g.source,g.typed)
        default:
            t.failed=errors.New("FI C1 committed readiness: bounded verifier queue unexpectedly full")
            return t.failed
        }
    }
    return nil
}

// Must be called after P6's normal final ACK drain. A premature Finish cannot
// turn a partial group into a completion receipt. The verifier owns the only
// reader of notifications, and this is the only place that closes the queue.
func(t *privateC1CommitReady) FinishCommitted()error{
    if t==nil{return errors.New("FI C1 committed readiness: missing tracker")}
    t.mu.Lock()
    defer t.mu.Unlock()
    if t.failed!=nil{return t.failed}
    if t.finished{return errors.New("FI C1 committed readiness: duplicate final drain")}
    if t.lastSeal!=t.start+len(t.groups){
        return errors.New("FI C1 committed readiness: incomplete signed seals")
    }
    for i,g:=range t.groups{
        if !g.ready||!g.sealed||g.source!=g.expected||g.typed!=g.expected{
            return fmt.Errorf("FI C1 committed readiness: incomplete group=%d source=%d typed=%d expected=%d sealed=%t",
                t.start+i,g.source,g.typed,g.expected,g.sealed)
        }
    }
    t.finished=true
    close(t.notifications)
    return nil
}

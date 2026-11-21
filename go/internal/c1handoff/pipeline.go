// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// C1 keeps the native SQL pool asynchronous across the jail boundary:
// multiple signed handoffs can be in flight over ONE authenticated TLS
// session. Replies carry their original sequence and are routed to their
// specific waiters, never treated as a generic enqueue success.
package c1handoff

import (
    "context"
    "errors"
    "fmt"
    "io"
    "net"
    "sync"
)

const MaxHandoffsInFlight = 64

type ClientPipeline struct {
    conn net.Conn
    source,generation,receipt string
    mu sync.Mutex
    writer sync.Mutex
    next uint64
    pending map[uint64]chan error
    permits chan struct{}
    firstError error
    readerDone chan struct{}
}

// NewClientPipeline switches an already-authenticated, START-acknowledged
// C1 Client to bounded concurrent SQL handoffs. Never run Client.Send in
// parallel with this reader; the pipeline has sole ownership of the socket.
func NewClientPipeline(ctx context.Context,c *Client,maxOutstanding int)(*ClientPipeline,error){
    if ctx==nil||c==nil||c.conn==nil||c.next<2||
        c.source==""||c.generation==""||c.receipt==""||
        len(c.batchIDs)==0||maxOutstanding<1||maxOutstanding>MaxHandoffsInFlight{
        return nil,errors.New("C1 pipeline: authenticated signed START and bounded in-flight count required")
    }
    p:=&ClientPipeline{
        conn:c.conn,source:c.source,generation:c.generation,receipt:c.receipt,
        next:c.next,pending:make(map[uint64]chan error,maxOutstanding),
        permits:make(chan struct{},maxOutstanding),readerDone:make(chan struct{}),
    }
    go p.read()
    go func(){
        select{
        case <-ctx.Done(): p.failAll(ctx.Err())
        case <-p.readerDone:
        }
    }()
    return p,nil
}
func (p *ClientPipeline) failAll(err error){
    if p==nil{return}
    if err==nil{err=errors.New("C1 pipeline: unknown transport failure")}
    p.mu.Lock()
    if p.firstError==nil{p.firstError=err}
    for seq,ch:=range p.pending{
        delete(p.pending,seq)
        ch<-p.firstError
        close(ch)
        select{case <-p.permits:default:}
    }
    p.mu.Unlock()
    _=p.conn.Close()
}
func(p *ClientPipeline)read(){
    defer close(p.readerDone)
    for {
        f,err:=ReadFrame(p.conn)
        if err!=nil{p.failAll(fmt.Errorf("C1 pipeline: SQL commit outcomes uncertain: %w",err));return}
        if f.Kind!=Ack||f.SourceID!=p.source||f.GenerationID!=p.generation||
            f.ReceiptSHA256!=p.receipt||f.Sequence==0 {
            p.failAll(errors.New("C1 pipeline: untrusted or unmatched SQL commit acknowledgment"))
            return
        }
        p.mu.Lock()
        ch,ok:=p.pending[f.Sequence]
        if ok{
            delete(p.pending,f.Sequence)
            var outcome error
            if !f.Committed{
                outcome=fmt.Errorf("C1 pipeline: SQL buffer %d rejected: %s",f.Sequence,f.Error)
                if p.firstError==nil{p.firstError=outcome}
            }
            ch<-outcome
            close(ch)
            select{case <-p.permits:default:}
        }
        p.mu.Unlock()
        if !ok{
            p.failAll(fmt.Errorf("C1 pipeline: duplicate, late or forged ACK sequence %d",f.Sequence))
            return
        }
        if !f.Committed{
            // Any failed SQL COMMIT blocks further C1 admission; a new
            // connection must first reconcile the private source ledger.
            p.failAll(fmt.Errorf("C1 pipeline: failed SQL handoff sequence %d",f.Sequence))
            return
        }
    }
}

// Submit returns a future that resolves ONLY when the matching fi-sor
// transaction commits. It does not hold the preparation consumer waiting
// on unrelated SQL jobs. The bounded credit pool applies backpressure.
func(p *ClientPipeline)Submit(ctx context.Context,f Frame)(<-chan error,error){
    if p==nil||ctx==nil{return nil,errors.New("C1 pipeline: missing client or context")}
    if err:=ctx.Err();err!=nil{return nil,err}
    select{
    case p.permits<-struct{}{}:
    case <-ctx.Done():return nil,ctx.Err()
    case <-p.readerDone:return nil,errors.New("C1 pipeline: SQL ACK reader stopped")
    }
    p.writer.Lock()
    defer p.writer.Unlock()
    p.mu.Lock()
    if p.firstError!=nil {
        err:=p.firstError
        p.mu.Unlock()
        <-p.permits
        return nil,err
    }
    if f.Sequence!=p.next||f.SourceID!=p.source||
        f.GenerationID!=p.generation||f.ReceiptSHA256!=p.receipt||
        f.Kind==Start||f.Kind==Ack {
        p.mu.Unlock()
        <-p.permits
        return nil,errors.New("C1 pipeline: missing, repeated or re-ordered signed handoff")
    }
    if err:=f.Validate();err!=nil{
        p.mu.Unlock()
        <-p.permits
        return nil,err
    }
    ch:=make(chan error,1)
    p.pending[f.Sequence]=ch
    p.next++
    p.mu.Unlock()
    if err:=WriteFrame(p.conn,f);err!=nil{
        // On a partial write the server may already have committed. Never
        // resume blindly; fail all outstanding receipts and close TLS.
        p.failAll(fmt.Errorf("C1 pipeline: SQL handoff commit uncertain: %w",err))
        return nil,err
    }
    return ch,nil
}

// WaitAll does not trigger a P6 buffer flush. The caller invokes it ONLY
// after the original signed reader and all five family buffers drain.
// Source and family ACKs may arrive in any order.
func(p *ClientPipeline)WaitAll(ctx context.Context)error{
    if p==nil||ctx==nil{return errors.New("C1 pipeline: invalid final ACK barrier")}
    for{
        p.mu.Lock()
        err:=p.firstError
        remaining:=len(p.pending)
        p.mu.Unlock()
        if err!=nil{return err}
        if remaining==0{return nil}
        select{
        case <-ctx.Done():return ctx.Err()
        case <-p.readerDone:return errors.New("C1 pipeline: no SQL ACK reader at drain")
        default:
        }
        // Readiness is signaled by per-handoff future closure. Avoid
        // polling and avoid an unbounded goroutine per pending result.
        p.mu.Lock()
        var wait <-chan error
        for _,ch:=range p.pending {wait=ch;break}
        p.mu.Unlock()
        if wait==nil{continue}
        select{
        case err:=<-wait:
            if err!=nil{return err}
        case <-ctx.Done():return ctx.Err()
        }
    }
}

// Send is supported for final Drain convenience but still waits for the
// EXACT matching commit/verification ACK. All earlier SQL handoffs remain
// concurrently in flight until WaitAll proves their completion.
func(p *ClientPipeline)Send(ctx context.Context,f Frame)error{
    ch,err:=p.Submit(ctx,f)
    if err!=nil{return err}
    select{
    case err:=<-ch:return err
    case <-ctx.Done():return ctx.Err()
    }
}
func(p *ClientPipeline)Close()error{
    if p==nil{return nil}
    p.failAll(io.EOF)
    <-p.readerDone
    return nil
}

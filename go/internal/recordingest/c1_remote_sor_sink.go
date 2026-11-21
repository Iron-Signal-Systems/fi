//go:build fi_c1_sor_dev

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// This is the actual fi-ingest side of C1's cross-jail SQL handoff.
// The five P5/P6 family buffers remain in the ingest jail; their SQL
// batches cross mutually authenticated transport to the fi-sor jail.
// There is no local PostgreSQL writer or SQL pool on this code path.
package recordingest

import (
    "context"
    "errors"
    "fmt"
    "strings"
    "sync"

    "github.com/Iron-Signal-Systems/fi/go/internal/c1handoff"
)
type c1HandoffSender interface {
    Send(context.Context,c1handoff.Frame)error
}
type c1RemoteSoRSink struct {
    mu sync.Mutex // group seal arrives from signed reader, SQL buffers from consumer
    sender c1HandoffSender
    sharedStore *c1handoff.RAMStore
    sharedSlots chan struct{}
    sharedCleanups sync.WaitGroup
    sharedMu sync.Mutex
    sharedErr error
    sourceID, generationID, receiptSHA256 string
    next uint64
    drained bool
}
func newC1RemoteSoRSink(sender c1HandoffSender,sourceID,generationID,receiptSHA256 string)(*c1RemoteSoRSink,error){
    if sender==nil || sourceID=="" || generationID=="" || len(receiptSHA256)!=64 {
        return nil,errors.New("C1 remote SoR: signed source, generation and authenticated client required")
    }
    return &c1RemoteSoRSink{sender:sender,sourceID:sourceID,
        generationID:generationID,receiptSHA256:strings.ToLower(receiptSHA256),
        next:1},nil
}
func(s *c1RemoteSoRSink)EnableSharedRAM(store *c1handoff.RAMStore)error{
    if s==nil||store==nil||s.sharedStore!=nil||s.next!=2{
        return errors.New("C1 RAM: configure exactly once immediately after signed START")
    }
    s.sharedStore=store
    s.sharedSlots=make(chan struct{},c1handoff.MaxSharedRAMInflight)
    return nil
}
// emit admits work without waiting for an unrelated SQL connection's
// COMMIT; final WaitAll and Drain require durable acknowledgments.
func(s *c1RemoteSoRSink)emit(ctx context.Context,f c1handoff.Frame)error{
    if pipeline,ok:=s.sender.(interface{
        Submit(context.Context,c1handoff.Frame)(<-chan error,error)
    });ok{
        future,err:=pipeline.Submit(ctx,f)
        if err!=nil{return err}
        if f.Shared.Name!=""{
            // An asynchronous transport that supplies no matching SQL
            // COMMIT future cannot ever authorize RAM reclamation.
            // The original signed custody is the only recovery source.
            if future==nil{
                return errors.New("C1 RAM: missing SQL COMMIT future; retain uncertain buffer for signed replay")
            }
            s.sharedCleanups.Add(1)
            go func(ref c1handoff.SharedRAMRef,committed <-chan error){
                defer s.sharedCleanups.Done()
                outcome,ok:=<-committed
                // A missing or rejected ACK is NOT a durable SQL commit.
                // Keep that volatile buffer until controlled restart/replay.
                if !ok || outcome!=nil{
                    // Never allow a misleading sender.WaitAll success to
                    // mask one rejected/uncertain SQL buffer. Keep its RAM
                    // object until an isolated PostgreSQL replay audit.
                    if !ok{
                        outcome=errors.New("C1 RAM: SQL COMMIT future closed without an outcome")
                    }
                    s.sharedMu.Lock()
                    if s.sharedErr==nil{s.sharedErr=fmt.Errorf("C1 RAM: SQL COMMIT not confirmed for %s: %w",ref.Name,outcome)}
                    s.sharedMu.Unlock()
                }else if e:=s.sharedStore.Remove(ref);e!=nil{
                    s.sharedMu.Lock()
                    if s.sharedErr==nil{s.sharedErr=fmt.Errorf("C1 RAM: committed handoff %s cleanup failed: %w",ref.Name,e)}
                    s.sharedMu.Unlock()
                }
                <-s.sharedSlots
            }(f.Shared,future)
        }
        return nil
    }
    err:=s.sender.Send(ctx,f)
    if err==nil&&f.Shared.Name!=""{err=s.sharedStore.Remove(f.Shared)}
    if f.Shared.Name!=""{<-s.sharedSlots}
    return err
}
func (s *c1RemoteSoRSink) WaitAll(ctx context.Context)error{
    if s==nil||s.sender==nil||ctx==nil{
        return errors.New("C1 remote SoR: missing final source/family ACK barrier")
    }
    if p,ok:=s.sender.(interface{WaitAll(context.Context)error});ok{
        if err:=p.WaitAll(ctx);err!=nil{return err}
    }
    if s.sharedStore!=nil{
        done:=make(chan struct{})
        go func(){s.sharedCleanups.Wait();close(done)}()
        select{
        case <-done:
        case <-ctx.Done():return ctx.Err()
        }
        s.sharedMu.Lock()
        err:=s.sharedErr
        s.sharedMu.Unlock()
        if err!=nil{return fmt.Errorf("C1 RAM: committed buffer cleanup: %w",err)}
    }
    return nil
}
func (s *c1RemoteSoRSink) submit(ctx context.Context,kind c1handoff.Kind,records []privateP6Record)error{
    s.mu.Lock()
    defer s.mu.Unlock()
    if s==nil||s.sender==nil||ctx==nil||s.drained {return errors.New("C1 remote SoR: invalid or closed commit handoff")}
    frame:=c1handoff.Frame{
        Kind:kind,SourceID:s.sourceID,GenerationID:s.generationID,
        ReceiptSHA256:s.receiptSHA256,Sequence:s.next,
    }
    for i,r:=range records {
        if !r.valid(){
            return fmt.Errorf("C1 remote SoR: unvalidated prepared source %d",i)
        }
        family,err:=privateP6KindFamily(r.prepared.Record.RecordKind)
        if err!=nil{return err}
        if kind!=c1handoff.Source && kind!=c1handoff.Kind(family+2){
            return fmt.Errorf("C1 remote SoR: signed kind %q crossed incorrect SQL lane",r.prepared.Record.RecordKind)
        }
        if s.sharedStore==nil{
            frame.Rows=append(frame.Rows,c1handoff.Row{
                SignedBatchIndex:uint32(r.signedBatchIndex),
                SourceBatchID:r.sourceBatchID,Ordinal:r.ordinal,
                RawRecord:r.prepared.RawRecordBytes,Digest:r.prepared.RecordDigest,
            })
        }
    }
    if s.sharedStore!=nil{
        // At most sixteen outstanding buffers: 16 x 128 MiB = 2 GiB.
        // This bounds the RAM transport independently of the SQL pool.
        select{
        case s.sharedSlots<-struct{}{}:
        case <-ctx.Done():return ctx.Err()
        }
        prepared,err:=encodeC1PreparedRAMRows(records)
        if err!=nil{<-s.sharedSlots;return err}
        ref,err:=s.sharedStore.Put(prepared,len(records))
        if err!=nil{<-s.sharedSlots;return err}
        frame.Shared=ref
    }
    if err:=s.emit(ctx,frame);err!=nil {
        // An uncertain SQL admission must not erase the RAM object while
        // fi-sor may still be reading it. Replay comes from signed custody.
        if frame.Shared.Name!=""{<-s.sharedSlots}
        return fmt.Errorf("C1 remote SoR: signed SQL handoff admission failed: %w",err)
    }
    // A pooled handoff may still be committing in fi-sor. Never treat
    // enqueue as a successful COMMIT; WaitAll/Drain own final ACK proof.
    s.next++
    return nil
}
// File prerequisites are enforced by the original fi-sor C1 USN
// dispatcher, not by forcing unrelated ingest family buffers to drain.
func(s *c1RemoteSoRSink)AsyncUSNDependencies()bool{return s!=nil}

func (s *c1RemoteSoRSink) Source(ctx context.Context,rows []privateP6Record)error{
    return s.submit(ctx,c1handoff.Source,rows)
}
func (s *c1RemoteSoRSink) Family(ctx context.Context,f privateP6Family,rows []privateP6Record)error{
    if f>=privateP6FamilyCount{return errors.New("C1 remote SoR: unknown SQL family")}
    return s.submit(ctx,c1handoff.Kind(f+2),rows)
}
func (s *c1RemoteSoRSink) Seal(ctx context.Context,group int)error{
    s.mu.Lock()
    defer s.mu.Unlock()
    if s==nil||s.sender==nil||ctx==nil||s.drained||group<1 {
        return errors.New("C1 remote SoR: invalid signed reporting group seal")
    }
    frame:=c1handoff.Frame{Kind:c1handoff.Seal,
        SourceID:s.sourceID,GenerationID:s.generationID,
        ReceiptSHA256:s.receiptSHA256,Sequence:s.next,
        SealedGroup:uint32(group)}
    if err:=s.emit(ctx,frame);err!=nil{return err}
    s.next++
    return nil
}
func (s *c1RemoteSoRSink) Drain(ctx context.Context)error{
    s.mu.Lock()
    defer s.mu.Unlock()
    if s==nil||s.drained||s.sender==nil||ctx==nil{return errors.New("C1 remote SoR: invalid final drain")}
    frame:=c1handoff.Frame{Kind:c1handoff.Drain,
        SourceID:s.sourceID,GenerationID:s.generationID,
        ReceiptSHA256:s.receiptSHA256,Sequence:s.next}
    if err:=s.WaitAll(ctx);err!=nil{return err}
    if err:=s.sender.Send(ctx,frame);err!=nil{return err}
    s.next++
    s.drained=true
    return nil
}
var _ privateP6SQLHandoff=(*c1RemoteSoRSink)(nil)

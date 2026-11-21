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

    "github.com/Iron-Signal-Systems/fi/go/internal/c1handoff"
)
type c1HandoffSender interface {
    Send(context.Context,c1handoff.Frame)error
}
type c1RemoteSoRSink struct {
    sender c1HandoffSender
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
func (s *c1RemoteSoRSink) submit(ctx context.Context,kind c1handoff.Kind,records []privateP6Record)error{
    if s==nil||s.sender==nil||ctx==nil||s.drained {return errors.New("C1 remote SoR: invalid or closed commit handoff")}
    frame:=c1handoff.Frame{
        Kind:kind,SourceID:s.sourceID,GenerationID:s.generationID,
        ReceiptSHA256:s.receiptSHA256,Sequence:s.next,
        Rows:make([]c1handoff.Row,0,len(records)),
    }
    for i,r:=range records {
        if !r.valid(){
            return fmt.Errorf("C1 remote SoR: unvalidated prepared source %d",i)
        }
        family,err:=privateP6KindFamily(r.prepared.Record.RecordKind)
        if err!=nil{return err}
        if kind!=c1handoff.Source && kind!=c1handoff.Kind(family+1){
            return fmt.Errorf("C1 remote SoR: signed kind %q crossed incorrect SQL lane",r.prepared.Record.RecordKind)
        }
        frame.Rows=append(frame.Rows,c1handoff.Row{
            SignedBatchIndex:uint32(r.signedBatchIndex),
            SourceBatchID:r.sourceBatchID,Ordinal:r.ordinal,
            RawRecord:r.prepared.RawRecordBytes,Digest:r.prepared.RecordDigest,
        })
    }
    if err:=s.sender.Send(ctx,frame);err!=nil {
        return fmt.Errorf("C1 remote SoR: SQL commit ACK not verified: %w",err)
    }
    s.next++ // Advance only when fi-sor acknowledged durable SQL COMMIT.
    return nil
}
func (s *c1RemoteSoRSink) Source(ctx context.Context,rows []privateP6Record)error{
    return s.submit(ctx,c1handoff.Source,rows)
}
func (s *c1RemoteSoRSink) Family(ctx context.Context,f privateP6Family,rows []privateP6Record)error{
    if f>=privateP6FamilyCount{return errors.New("C1 remote SoR: unknown SQL family")}
    return s.submit(ctx,c1handoff.Kind(f+2),rows)
}
func (s *c1RemoteSoRSink) Drain(ctx context.Context)error{
    if s==nil||s.drained||s.sender==nil||ctx==nil{return errors.New("C1 remote SoR: invalid final drain")}
    frame:=c1handoff.Frame{Kind:c1handoff.Drain,
        SourceID:s.sourceID,GenerationID:s.generationID,
        ReceiptSHA256:s.receiptSHA256,Sequence:s.next}
    if err:=s.sender.Send(ctx,frame);err!=nil{return err}
    s.next++
    s.drained=true
    return nil
}
var _ privateP6SQLHandoff=(*c1RemoteSoRSink)(nil)

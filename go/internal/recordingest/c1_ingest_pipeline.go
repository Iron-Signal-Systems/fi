//go:build fi_c1_sor_dev

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// The C1 fi-ingest phase: original receiver-verified immutable custody,
// one continuous P5 preparation pool, five P6 family buffers and encrypted,
// bounded handoffs. PostgreSQL lives entirely inside fi-sor.
package recordingest

import (
    "context"
    "crypto/tls"
    "errors"
    "fmt"
    "net"
    "time"

    "github.com/Iron-Signal-Systems/fi/go/internal/c1handoff"
)

const c1IngestReportingGroupBytes = int64(4 << 30)

type C1IngestTransport struct {
    SoRAddress string
    TLSIdentity c1handoff.TLSFiles
    ExpectedSoRServerDNS string
    StartBatch int // 0 for clean generation; may follow a separately verified seed
}
type C1IngestStageResult struct {
    SourceID string
    GenerationID string
    ReceiptSHA256 string
    NewRecords int64
    SignedBatches int
    ReportingGroups int
    RelationalCommitted bool
    IndependentlyVerified bool
    Published bool
}

// Successful return proves receiver-bound source read and fi-sor private
// SourceParent/family SQL COMMIT ACKs, NOT final acceptance. B must
// independently validate all committed groups before promotion is allowed.
func RunC1IngestGeneration(ctx context.Context,g *PreparedGeneration,
    cfg C1IngestTransport)(C1IngestStageResult,error){
    var result C1IngestStageResult
    if ctx==nil||g==nil||cfg.StartBatch<0||
        cfg.StartBatch>=len(g.Batches)||cfg.SoRAddress==""{
        return result,errors.New("C1 fi-ingest: original signed generation or network config missing")
    }
    descriptor:=g.Receipt.Descriptor
    if descriptor.SourceID==""||descriptor.GenerationID==""||
        len(g.ReceiptSHA256)!=64{
        return result,errors.New("C1 fi-ingest: original signed custody identity missing")
    }
    result.SourceID=descriptor.SourceID
    result.GenerationID=descriptor.GenerationID
    result.ReceiptSHA256=g.ReceiptSHA256

    names:=make([]string,len(g.Batches))
    var newRows,allRows int64
    for i,b:=range g.Batches{
        if b.BatchID==""||b.Manifest.BatchID!=b.BatchID||
            b.Manifest.RecordCount<=0||b.Manifest.DataBytes<=0{
            return result,fmt.Errorf("C1 fi-ingest: unverified original manifest %d",i)
        }
        names[i]=b.BatchID
        allRows+=int64(b.Manifest.RecordCount)
        if i>=cfg.StartBatch {newRows+=int64(b.Manifest.RecordCount)}
    }
    if allRows!=int64(g.Receipt.RecordCount)||newRows<=0{
        return result,errors.New("C1 fi-ingest: original receipt count and signed batch sums disagree")
    }

    clientTLS,err:=c1handoff.ClientTLSConfig(cfg.TLSIdentity,cfg.ExpectedSoRServerDNS)
    if err!=nil{return result,err}
    clientTLS.MinVersion=tls.VersionTLS13
    dial:=&net.Dialer{Timeout:15*time.Second}
    raw,err:=tls.DialWithDialer(dial,"tcp4",cfg.SoRAddress,clientTLS)
    if err!=nil{return result,fmt.Errorf("C1 fi-ingest: fi-sor mTLS handoff: %w",err)}
    client,err:=c1handoff.NewClient(raw)
    if err!=nil{raw.Close();return result,err}
    defer client.Close()

    start:=c1handoff.Frame{
        Kind:c1handoff.Start,SourceID:descriptor.SourceID,
        GenerationID:descriptor.GenerationID,ReceiptSHA256:g.ReceiptSHA256,
        Sequence:1,BatchIDs:names,StartBatchIndex:uint32(cfg.StartBatch),
        ExpectedRecords:newRows,
    }
    if err:=client.Send(ctx,start);err!=nil{return result,err}
    ids:=client.BatchSQLIDs()
    if len(ids)!=len(g.Batches){
        return result,errors.New("C1 fi-ingest: fi-sor did not provide complete original SQL batch IDs")
    }

    // The real C1 SQL pool has multiple independently committed family
    // handoffs. P5/P6 preparation must not serialize behind each COMMIT.
    pipelined,err:=c1handoff.NewClientPipeline(ctx,client,64)
    if err!=nil{return result,err}
    defer pipelined.Close()
    remote,err:=newC1RemoteSoRSink(pipelined,descriptor.SourceID,
        descriptor.GenerationID,g.ReceiptSHA256)
    if err!=nil{return result,err}
    // The session's first sequence was START. Every subsequent SourceParent
    // and five-family handoff is assigned its own distinct durable ACK ID.
    remote.next=2
    pool,err:=newC1P5RuntimePool(ctx,1)
    if err!=nil{return result,err}
    defer pool.Close()
    buffers,err:=newC1NativeP6Buffers(1,remote)
    if err!=nil{return result,err}

    signed:=make([]privateC1StreamBatch,0,len(g.Batches)-cfg.StartBatch)
    window:=1
    var groupBytes int64
    for i:=cfg.StartBatch;i<len(g.Batches);i++{
        batch:=g.Batches[i]
        if groupBytes>0 && batch.Manifest.DataBytes>c1IngestReportingGroupBytes-groupBytes {
            window++
            groupBytes=0
        }
        signed=append(signed,privateC1StreamBatch{
            Index:i,Window:window,SourceBatchID:ids[i],Batch:batch,
        })
        groupBytes+=batch.Manifest.DataBytes
    }
    result.ReportingGroups=window
    result.SignedBatches=len(signed)
    var totals privateC1PrepTotals
    groups,bytes,err:=privateC1ConsumeContinuousSigned(ctx,pool,signed,
        buffers,&totals,window+1,privateHeaderFirstPrepare,
        func(group int)error {
            // B's independent read-only proof will subscribe to committed
            // group receipts, not this uncommitted reader-seal notification.
            fmt.Printf("FI C1 SIGNED GROUP SEALED group=%d no_flush=true verifier_awaits_commits=true\n",group)
            return remote.Seal(ctx,group)
        })
    if err!=nil{return result,err}
    var processedRows int64
    for i:=1;i<=window;i++{
        if groups[i]<=0||bytes[i]<=0 {
            return result,errors.New("C1 fi-ingest: empty or unaccounted signed group")
        }
        processedRows+=groups[i]
    }
    if processedRows!=newRows||totals.records!=newRows{
        return result,errors.New("C1 fi-ingest: prepared generation does not match signed receipt")
    }
    // True end of signed input: the only unconditional family buffer drain.
    // No window, batch, timer or verification event forces a family flush.
    if err:=buffers.Finish(ctx);err!=nil{return result,err}
    if err:=remote.Drain(ctx);err!=nil{return result,err}
    result.NewRecords=newRows
    result.RelationalCommitted=true
    result.IndependentlyVerified=false
    result.Published=false
    return result,nil
}

// newC1NativeP6Buffers preserves the Security COPY profile proved in
// the frozen full-backlog C1 run. The clone experiment's environment gate
// remains unmodified; no reporting window resets these native buffers.
func newC1NativeP6Buffers(window int,sink privateP6SQLHandoff)(*privateP6Buffers,error){
    buffers,err:=newPrivateP6Buffers(window,sink)
    if err!=nil{return nil,err}
    buffers.lanes[privateP6Security].limit=privateP6Limits{rows:8192,bytes:32<<20}
    return buffers,nil
}

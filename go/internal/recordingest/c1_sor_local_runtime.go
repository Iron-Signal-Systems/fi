//go:build fi_c1_sor_dev

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// One-jail C1: original receiver custody is read-only; the SAME tested
// continuous five-lane P5 preparer and persistent P6 family buffers execute
// directly against the SAME adaptive 32-worker local PostgreSQL SQL pool.
// No fi-ingest jail, network frame serialization, RAM store, or inter-jail
// SQL acknowledgement is in this processing path.
package recordingest

import (
    "context"
    "errors"
    "fmt"
    "math"
    "time"

    "github.com/Iron-Signal-Systems/fi/go/internal/c1handoff"
)

// C1SoRLocalConfig is one explicitly selected source. An operator must
// separately authorize replay after an interrupted Pending generation.
// Original custody paths must be mounted read-only into fi-sor.
type C1SoRLocalConfig struct {
    SourceID string
    Custody C1NativeBCustodyConfig
    WorkerDSN string
    PublisherDSN string
    SQLWorkersMax int
    AllowReplay bool
}

type C1SoRLocalResult struct {
    SourceID string
    GenerationID string
    ReceiptSHA256 string
    Records int64
    Batches int
    Groups int
    IngestElapsed time.Duration
    IngestRecordsPerSecond float64
    IndependentlyVerified bool
    CanonicalAccepted bool
    PreviouslyAccepted bool
}

func validateC1SoRLocalConfig(c C1SoRLocalConfig) error {
    if c.SourceID==""||c.WorkerDSN==""||c.PublisherDSN==""||
       c.Custody.CustodyRoot==""||c.Custody.RecordedRoot==""||
       c.Custody.MaxCanonicalBytes==0||c.Custody.MaxEncodedBytes==0||
       c.Custody.MaxManifestBytes==0||c.SQLWorkersMax<1||c.SQLWorkersMax>32{
        return errors.New("FI C1 local: exact source, original custody, local PostgreSQL roles and 1..32 workers required")
    }
    if _,err:=c1SoRLocalConnectionConfig(c.WorkerDSN);err!=nil{return err}
    return nil
}

func C1SoRLocalGenerationLoad(c C1SoRLocalConfig) GenerationLoadConfig {
    return GenerationLoadConfig{
        SourceID:c.SourceID, CustodyRoot:c.Custody.CustodyRoot,
        RecordedRoot:c.Custody.RecordedRoot,
        SourceNamespaces:c.Custody.SourceNamespaces,
        MaxCanonicalBytes:c.Custody.MaxCanonicalBytes,
        MaxEncodedBytes:c.Custody.MaxEncodedBytes,
        MaxManifestBytes:c.Custody.MaxManifestBytes,
    }
}

// The authenticated signed START plan is exactly the plan that the older
// two-jail protocol transported over TLS. Here it never leaves fi-sor.
func c1SoRLocalPlan(g *PreparedGeneration,source string)(
    c1handoff.Frame,[]privateC1StreamBatch,int,error){
    var empty c1handoff.Frame
    if g==nil||g.Receipt.Descriptor.SourceID!=source||
        g.Receipt.Descriptor.GenerationID==""||
        g.Receipt.BatchCount!=uint64(len(g.Batches))||
        g.Receipt.RecordCount==0||g.Receipt.RecordCount>math.MaxInt64||
        len(g.Batches)==0{
        return empty,nil,0,errors.New("FI C1 local: incomplete original signed receipt")
    }
    names:=make([]string,len(g.Batches))
    signed:=make([]privateC1StreamBatch,0,len(g.Batches))
    group:=1
    var groupBytes,records int64
    for i,b:=range g.Batches {
        if b.BatchID==""||b.BatchID!=b.Manifest.BatchID||
            b.DataPath==""||b.Manifest.RecordCount<=0||b.Manifest.DataBytes<=0||
            b.Manifest.DataBytes>c1IngestReportingGroupBytes ||
            groupBytes>math.MaxInt64-b.Manifest.DataBytes{
            return empty,nil,0,fmt.Errorf("FI C1 local: invalid original signed batch %d",i)
        }
        if groupBytes>0 && b.Manifest.DataBytes>c1IngestReportingGroupBytes-groupBytes {
            group++
            groupBytes=0
        }
        names[i]=b.BatchID
        signed=append(signed,privateC1StreamBatch{Index:i,Window:group,Batch:b})
        groupBytes+=b.Manifest.DataBytes
        records+=int64(b.Manifest.RecordCount)
        if records>math.MaxInt64/2 && uint64(records)>g.Receipt.RecordCount{
            return empty,nil,0,errors.New("FI C1 local: signed record count overflow")
        }
    }
    if uint64(records)!=g.Receipt.RecordCount{
        return empty,nil,0,errors.New("FI C1 local: original signed batch counts disagree with receipt")
    }
    frame:=c1handoff.Frame{
        Kind:c1handoff.Start,Sequence:1,
        SourceID:source,GenerationID:g.Receipt.Descriptor.GenerationID,
        ReceiptSHA256:g.ReceiptSHA256,
        ExpectedRecords:records, BatchIDs:names,
    }
    if err:=frame.Validate();err!=nil{return empty,nil,0,err}
    return frame,signed,group,nil
}

// c1LocalDirectSQLSink is used by the original P6 family buffers in place of
// the remote fi-ingest mTLS/RAM sink. The same PostgreSQL pool and committed
// group/B tracker remain authoritative. Only the signed P5 consumer calls
// Source and Family, so its per-batch admission counters stay ordered.
type c1LocalDirectSQLSink struct {
    service *C1SoRService
    nextSequence uint64
}
func (s *c1LocalDirectSQLSink) valid() bool {
    return s!=nil&&s.service!=nil&&s.service.pool!=nil&&
        s.service.session!=nil&&s.service.commitReady!=nil
}
func (s *c1LocalDirectSQLSink) Source(ctx context.Context,rows []privateP6Record)error{
    return s.admit(ctx,c1handoff.Source,rows)
}
func (s *c1LocalDirectSQLSink) Family(ctx context.Context,f privateP6Family,rows []privateP6Record)error{
    if f>=privateP6FamilyCount{return errors.New("FI C1 local: invalid family")}
    return s.admit(ctx,c1handoff.Kind(f+2),rows)
}
func (s *c1LocalDirectSQLSink) admit(ctx context.Context,kind c1handoff.Kind,
    rows []privateP6Record)error{
    if !s.valid()||ctx==nil||len(rows)==0{
        return errors.New("FI C1 local: invalid SQL admission")
    }
    handler,pool:=s.service.session,s.service.pool
    if s.service.replayMode{
        if s.service.replayRead==nil{return errors.New("FI C1 local: Pending replay read-only audit missing")}
        if s.nextSequence==math.MaxUint64{return errors.New("FI C1 local: handoff sequence exhausted")}
        s.nextSequence++
        frame:=c1handoff.Frame{
            Kind:kind,Sequence:s.nextSequence,
            SourceID:handler.sourceID,GenerationID:handler.generationID,
            ReceiptSHA256:handler.receipt,
            Rows:make([]c1handoff.Row,len(rows)),
        }
        for i,r:=range rows{
            frame.Rows[i]=c1handoff.Row{
                SignedBatchIndex:uint32(r.signedBatchIndex),
                SourceBatchID:r.sourceBatchID,Ordinal:r.ordinal,
                RawRecord:r.prepared.RawRecordBytes,
                Digest:r.prepared.RecordDigest,
            }
        }
        // Replay uses original audited SQL reconciliation, never blind
        // duplicate INSERTs or a fabricated committed receipt.
        _,err:=handler.EnqueueReplay(ctx,frame,s.service.replayRead)
        return err
    }
    if kind==c1handoff.Source{
        if err:=pool.Source(ctx,rows);err!=nil{return err}
        handler.accountSource(rows)
        return nil
    }
    family:=privateP6Family(kind-2)
    if err:=pool.Family(ctx,family,rows);err!=nil{return err}
    handler.accountTyped(rows)
    return nil
}
func(s *c1LocalDirectSQLSink) WaitAll(ctx context.Context)error{
    if !s.valid(){return errors.New("FI C1 local: no SQL session")}
    return s.service.pool.WaitAll(ctx)
}
func(s *c1LocalDirectSQLSink) AsyncUSNDependencies()bool{return s.valid()}

func RunC1SoRLocalGeneration(ctx context.Context,c C1SoRLocalConfig,
    g *PreparedGeneration)(C1SoRLocalResult,error){
    var result C1SoRLocalResult
    if ctx==nil{return result,errors.New("FI C1 local: context required")}
    if err:=validateC1SoRLocalConfig(c);err!=nil{return result,err}
    start,signed,groups,err:=c1SoRLocalPlan(g,c.SourceID)
    if err!=nil{return result,err}
    result=C1SoRLocalResult{
        SourceID:start.SourceID,GenerationID:start.GenerationID,
        ReceiptSHA256:start.ReceiptSHA256,
        Records:start.ExpectedRecords,Batches:len(signed),Groups:groups,
    }
    status,err:=c1ReadCanonicalAcceptanceAfterB(ctx,c.WorkerDSN,
        start.SourceID,start.GenerationID,start.ReceiptSHA256)
    if err!=nil{return result,fmt.Errorf("FI C1 local: read-only canonical status: %w",err)}
    if status==c1handoff.FinalAccepted{
        result.PreviouslyAccepted=true
        result.CanonicalAccepted=true
        result.IndependentlyVerified=true
        return result,nil
    }
    if status!=c1handoff.FinalVerified{
        return result,errors.New("FI C1 local: unrecognized canonical status")
    }
    service,err:=NewC1SoRService(c.WorkerDSN,c.SQLWorkersMax)
    if err!=nil{return result,err}
    defer service.Close()
    service.PublisherDSN=c.PublisherDSN
    service.NativeBCustody=c.Custody
    service.AllowC1Replay=c.AllowReplay
    ids,err:=service.Bootstrap(ctx,start)
    if err!=nil{return result,fmt.Errorf("FI C1 local: signed Pending bootstrap: %w",err)}
    if len(ids)!=len(signed){return result,errors.New("FI C1 local: exact source batch SQL identity count changed")}
    for i:=range signed{
        if ids[i]<=0{return result,fmt.Errorf("FI C1 local: signed batch %d has no SQL identity",i)}
        signed[i].SourceBatchID=ids[i]
    }
    prep,err:=newC1P5RuntimePool(ctx,1)
    if err!=nil{return result,err}
    defer prep.Close()
    sink:=&c1LocalDirectSQLSink{service:service,nextSequence:1}
    buffers,err:=newC1NativeP6Buffers(1,sink)
    if err!=nil{return result,err}
    fmt.Printf("FI C1 SOR LOCAL INGEST CLOCK START utc=%s source=%s generation=%s sql_workers_max=%d direct=true shared_ram=false mtls_handoff=false original_p5=true original_p6=true\n",
        time.Now().UTC().Format(time.RFC3339Nano),
        start.SourceID,start.GenerationID,c.SQLWorkersMax)
    ingestStart:=time.Now()
    var totals privateC1PrepTotals
    groupRows,groupSizes,err:=privateC1ConsumeContinuousSigned(
        ctx,prep,signed,buffers,&totals,groups+1,privateFamilyP3Prepare,
        func(group int)error{
            return service.Commit(ctx,c1handoff.Frame{
                Kind:c1handoff.Seal,Sequence:uint64(group+1),
                SourceID:start.SourceID,GenerationID:start.GenerationID,
                ReceiptSHA256:start.ReceiptSHA256,
                SealedGroup:uint32(group),
            })
        })
    if err!=nil{return result,fmt.Errorf("FI C1 local: original continuous P5/P6 processing: %w",err)}
    var count,bytes int64
    for i:=1;i<=groups;i++{
        if groupRows[i]<=0||groupSizes[i]<=0{
            return result,errors.New("FI C1 local: empty or incomplete signed reporting group")
        }
        count+=groupRows[i]
        bytes+=groupSizes[i]
    }
    if count!=start.ExpectedRecords||totals.records!=count||
       uint64(bytes)!=g.Receipt.DataBytes{
        return result,errors.New("FI C1 local: prepared signed record/byte totals changed")
    }
    if err=buffers.Finish(ctx);err!=nil{
        return result,fmt.Errorf("FI C1 local: original five-family final SQL drain: %w",err)
    }
    elapsed:=time.Since(ingestStart)
    if elapsed<=0{return result,errors.New("FI C1 local: invalid ingest stopwatch")}
    result.IngestElapsed=elapsed
    result.IngestRecordsPerSecond=float64(count)/elapsed.Seconds()
    fmt.Printf("FI C1 SOR LOCAL INGEST THROUGHPUT records=%d source_bytes=%d ingest_seconds=%.3f records_per_second=%.2f verification_excluded=true publication_excluded=true sql_workers_max=%d original_custody_preserved=true\n",
        count,bytes,elapsed.Seconds(),result.IngestRecordsPerSecond,c.SQLWorkersMax)
    drain:=c1handoff.Frame{
        Kind:c1handoff.Drain,Sequence:uint64(groups+2),
        SourceID:start.SourceID,GenerationID:start.GenerationID,
        ReceiptSHA256:start.ReceiptSHA256,
    }
    if err=service.Commit(ctx,drain);err!=nil{
        return result,fmt.Errorf("FI C1 local: independent B verification: %w",err)
    }
    result.IndependentlyVerified=true
    final,err:=service.FinalProof(ctx,drain)
    if err!=nil{return result,fmt.Errorf("FI C1 local: canonical publication/Accepted readback: %w",err)}
    if final!=c1handoff.FinalAccepted{
        return result,errors.New("FI C1 local: independent B passed but canonical Accepted was withheld")
    }
    result.CanonicalAccepted=true
    fmt.Printf("FI C1 SOR LOCAL CANONICAL ACCEPTED source=%s generation=%s records=%d independently_verified=true canonical_accepted=true original_custody_preserved=true\n",
        result.SourceID,result.GenerationID,result.Records)
    return result,nil
}

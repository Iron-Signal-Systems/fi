//go:build fi_c1_sor_dev

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
package recordingest

import (
    "context"
    "errors"
    "os"
    "path/filepath"
    "strings"
    "testing"

    "github.com/Iron-Signal-Systems/fi/go/internal/generationready"
    "github.com/Iron-Signal-Systems/fi/go/internal/generationrecorder"
)

func c1ReadyTest(t *testing.T)(C1ReadyQueueConfig,string,c1ReadyQueueOps,func()bool){
    t.Helper()
    root:=t.TempDir()
    queue:=filepath.Join(root,"ready")
    if err:=os.Mkdir(queue,0700);err!=nil{t.Fatal(err)}
    source:="source.example"
    gen:="generation-01"
    marker:=generationrecorder.RecordedReceiptObjectName(source,gen)
    if _,err:=generationready.PublishForSource(queue,source,marker);err!=nil{t.Fatal(err)}
    cfg:=C1ReadyQueueConfig{
        ReadyRoot:queue,SourceID:source,BatchSize:4,
        GenerationLoad:GenerationLoadConfig{
            SourceID:source,CustodyRoot:"/signed-custody",
            RecordedRoot:"/signed-recorded",
        },
        Transport:C1IngestTransport{SoRAddress:"127.0.0.1:8443",
            SharedRAMDir:"/ram"},
    }
    want:=c1ReadyReceiptIdentity{generationID:gen,receiptSHA:strings.Repeat("a",64)}
    ops:=c1ReadyQueueOpsDefault()
    ops.identity=func(c C1ReadyQueueConfig,name string)(c1ReadyReceiptIdentity,error){
        if name!=marker||c.SourceID!=source{return want,errors.New("wrong READY identity")}
        return want,nil
    }
    ops.load=func(c GenerationLoadConfig,id string)(*PreparedGeneration,error){
        if id!=gen||c.SourceID!=source{return nil,errors.New("wrong signed identity")}
        g:=&PreparedGeneration{ReceiptSHA256:want.receiptSHA}
        g.Receipt.Descriptor.SourceID=source
        g.Receipt.Descriptor.GenerationID=gen
        g.Receipt.RecordCount=1
        g.Receipt.BatchCount=1
        g.Batches=[]PreparedBatch{{BatchID:"signed-batch-1"}}
        return g,nil
    }
    ops.ingest=func(_ context.Context,g *PreparedGeneration,_ C1IngestTransport)(
        C1IngestStageResult,error,
    ){
        return C1IngestStageResult{
            SourceID:source,GenerationID:gen,ReceiptSHA256:want.receiptSHA,
            RelationalCommitted:true,IndependentlyVerified:true,
            Published:true,NewRecords:1,SignedBatches:1,ReportingGroups:1,
        },nil
    }
    present:=func()bool{
        exists,err:=generationready.ReceiptNamePresentForSource(queue,source,marker)
        if err!=nil{t.Fatal(err)}
        return exists
    }
    return cfg,marker,ops,present
}
func TestC1ReadyQueueRetiresOnlyAcceptedGeneration(t *testing.T){
    cfg,_,ops,present:=c1ReadyTest(t)
    count,err:=runC1ReadyQueuePass(context.Background(),cfg,ops)
    if err!=nil||count!=1||present(){
        t.Fatalf("real READY marker was not retired after canonical Accepted: %d %v still_present=%t",
            count,err,present())
    }
    count,err=runC1ReadyQueuePass(context.Background(),cfg,ops)
    if err!=nil||count!=0{t.Fatalf("repeated queue pass rediscovered accepted marker: %d %v",count,err)}
}
func TestC1ReadyQueuePreservesMarkerForUncertainOrBOnlyStage(t *testing.T){
    for _,tc:=range []struct{name string; mutate func(*C1IngestStageResult);runErr error}{
        {"B-only-not-Accepted",func(r *C1IngestStageResult){r.Published=false},nil},
        {"not-B-verified",func(r *C1IngestStageResult){r.IndependentlyVerified=false},nil},
        {"SQL-uncommitted",func(r *C1IngestStageResult){r.RelationalCommitted=false},nil},
        {"wrong-signed-receipt",func(r *C1IngestStageResult){r.ReceiptSHA256=strings.Repeat("f",64)},nil},
        {"wrong-source",func(r *C1IngestStageResult){r.SourceID="attacker"},nil},
        {"wrong-generation",func(r *C1IngestStageResult){r.GenerationID="foreign"},nil},
        {"mismatched-record-total",func(r *C1IngestStageResult){r.NewRecords=2},nil},
        {"mismatched-batch-total",func(r *C1IngestStageResult){r.SignedBatches=2},nil},
        {"uncertain-commit",func(_ *C1IngestStageResult){},errors.New("network ACK unknown")},
    }{
        t.Run(tc.name,func(t *testing.T){
            cfg,_,ops,present:=c1ReadyTest(t)
            previous:=ops.ingest
            ops.ingest=func(ctx context.Context,g *PreparedGeneration,c C1IngestTransport)(
                C1IngestStageResult,error,
            ){
                result,_:=previous(ctx,g,c)
                tc.mutate(&result)
                return result,tc.runErr
            }
            count,err:=runC1ReadyQueuePass(context.Background(),cfg,ops)
            if count!=0||err==nil||!present(){
                t.Fatalf("failure lost original READY marker: retired=%d err=%v still_present=%t",
                    count,err,present())
            }
        })
    }
}
func TestC1ReadyQueueMissingSignedReceiptDoesNotRetireMarker(t *testing.T){
    cfg,_,ops,present:=c1ReadyTest(t)
    ops.identity=c1OriginalReadyReceipt
    count,err:=runC1ReadyQueuePass(context.Background(),cfg,ops)
    if count!=0||err==nil||!present(){
        t.Fatalf("missing original signed receipt incorrectly retired READY: %d %v",count,err)
    }
}
func TestC1ReadyQueueBlocksPartialReplayAndMissingHandlers(t *testing.T){
    cfg,_,ops,present:=c1ReadyTest(t)
    cfg.Transport.StartBatch=1
    if _,err:=runC1ReadyQueuePass(context.Background(),cfg,ops);err==nil{
        t.Fatal("READY queue silently attempted partial private C1 replay")
    }
    cfg.Transport.StartBatch=0
    ops.ingest=nil
    if _,err:=runC1ReadyQueuePass(context.Background(),cfg,ops);err==nil||!present(){
        t.Fatal("READY queue accepted missing authenticated SoR handler")
    }
}

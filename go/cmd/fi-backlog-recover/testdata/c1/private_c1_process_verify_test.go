// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
package recordingest

import (
    "bufio"
    "context"
    "fmt"
    "strings"
    "testing"
)

func privateC1ProcessPlanFixture(t *testing.T)privateC1VerifyProcessPlan{
    t.Helper()
    receipt:=strings.Repeat("a",64)
    transfer:=strings.Repeat("b",64)
    ids:=[]string{"batch-0","batch-1","batch-2"}
    ds:=[]BacklogCheckpointDescriptor{
        {SourceID:"source",GenerationID:"gen",ReceiptSHA256:receipt,TransferSHA256:transfer,
            FirstBatchID:ids[0],LastBatchID:ids[0],StartBatch:0,EndBatch:1,
            StartRecord:0,EndRecord:1,DataBytes:11,DigestSHA256:strings.Repeat("c",64)},
        {SourceID:"source",GenerationID:"gen",ReceiptSHA256:receipt,TransferSHA256:transfer,
            FirstBatchID:ids[1],LastBatchID:ids[1],StartBatch:1,EndBatch:2,
            StartRecord:1,EndRecord:2,DataBytes:12,
            PreviousDigestSHA256:strings.Repeat("c",64),DigestSHA256:strings.Repeat("d",64)},
        {SourceID:"source",GenerationID:"gen",ReceiptSHA256:receipt,TransferSHA256:transfer,
            FirstBatchID:ids[2],LastBatchID:ids[2],StartBatch:2,EndBatch:3,
            StartRecord:2,EndRecord:3,DataBytes:13,
            PreviousDigestSHA256:strings.Repeat("d",64),DigestSHA256:strings.Repeat("e",64)},
    }
    g:=&PreparedGeneration{ReceiptSHA256:receipt,Batches:[]PreparedBatch{
        {BatchID:ids[0]},{BatchID:ids[1]},{BatchID:ids[2]},
    }}
    g.Receipt.TransferSHA256=transfer
    g.Receipt.RecordCount=3
    g.Receipt.DataBytes=36
    g.Batches[0].Manifest.RecordCount=1
    g.Batches[0].Manifest.DataBytes=11
    g.Batches[1].Manifest.RecordCount=1
    g.Batches[1].Manifest.DataBytes=12
    g.Batches[2].Manifest.RecordCount=1
    g.Batches[2].Manifest.DataBytes=13
    p,err:=privateC1BuildVerifyProcessPlan(g,ds,1,3)
    if err!=nil{t.Fatal(err)}
    return p
}

func TestPrivateC1BProcessPlanHasNoSourceBytesOrNewHashes(t *testing.T){
    p:=privateC1ProcessPlanFixture(t)
    if len(p.BatchIDs)!=3||p.Start!=1||p.End!=3||len(p.Descriptors)!=3||p.TotalRecords!=3||p.TotalBytes!=36{
        t.Fatal("C1 B lost exact signed group metadata")
    }
    for _,tc:=range []func(*privateC1VerifyProcessPlan){
        func(p *privateC1VerifyProcessPlan){p.BatchIDs[2]="changed"},
        func(p *privateC1VerifyProcessPlan){p.Descriptors[2].PreviousDigestSHA256="bad"},
        func(p *privateC1VerifyProcessPlan){p.End=4},
        func(p *privateC1VerifyProcessPlan){p.TransferSHA256="bad"},
        func(p *privateC1VerifyProcessPlan){p.BatchBytes[1]=99},
        func(p *privateC1VerifyProcessPlan){p.TotalRecords=4},
    }{
        altered:=privateC1ProcessPlanFixture(t)
        tc(&altered)
        if err:=privateC1ValidateVerifyProcessPlan(&altered);err==nil{
            t.Fatal("C1 B accepted altered custody group plan")
        }
    }
}

func TestPrivateC1BProcessProtocolCommitsAndClosesIndependently(t *testing.T){
    p:=privateC1ProcessPlanFixture(t)
    var verified []int
    var finalCalls int
    scanner:=bufio.NewScanner(strings.NewReader("READY 1\nDRAIN\nREADY 2\nGROUPS\nFINAL\n"))
    if err:=privateC1VerifyProcessCommands(context.Background(),scanner,&p,
        func(_ context.Context,wi int)error{
            verified=append(verified,wi)
            return nil
        },func(context.Context)(BacklogGenerationVerification,error){
            finalCalls++
            return BacklogGenerationVerification{ShadowGenerationID:19},nil
        });err!=nil{t.Fatal(err)}
    if len(verified)!=2||verified[0]!=1||verified[1]!=2||finalCalls!=1{
        t.Fatal("C1 B skipped an original committed group or generation proof")
    }
}

func TestPrivateC1BProcessProtocolFailsClosed(t *testing.T){
    tests:=[]string{
        "READY 2\nGROUPS\nFINAL\n",
        "READY 1\nREADY 1\nREADY 2\nGROUPS\nFINAL\n",
        "READY 1\nGROUPS\nFINAL\n",
        "READY 1\nREADY 2\n",
        "READY 1\nREADY 2\nGROUPS\nFINAL\nREADY 2\n",
        "DRAIN\nDRAIN\nREADY 1\nREADY 2\nGROUPS\nFINAL\n",
        "READY 1\nREADY 2\nFINAL\n",
        "READY 1\nREADY 2\nGROUPS\nGROUPS\nFINAL\n",
        "READY 1\nREADY 2\nGROUPS\nREADY 1\nFINAL\n",
        "UNTRUSTED 1\n",
    }
    for i,commands:=range tests{
        t.Run(fmt.Sprintf("invalid-%d",i),func(t *testing.T){
            p:=privateC1ProcessPlanFixture(t)
            scanner:=bufio.NewScanner(strings.NewReader(commands))
            if err:=privateC1VerifyProcessCommands(context.Background(),scanner,&p,
                func(context.Context,int)error{return nil},
                func(context.Context)(BacklogGenerationVerification,error){
                    return BacklogGenerationVerification{},nil
                });err==nil{
                t.Fatal("C1 B accepted missing, duplicate or out-of-order commit-ready/final proof")
            }
        })
    }
    p:=privateC1ProcessPlanFixture(t)
    ctx:=context.Background()
    err:=privateC1VerifyProcessCommands(ctx,bufio.NewScanner(
        strings.NewReader("READY 1\nREADY 2\nDRAIN\nGROUPS\nFINAL\n")),&p,
        func(_ context.Context,wi int)error{
            if wi==2{return fmt.Errorf("typed relation missing")}
            return nil
        },func(context.Context)(BacklogGenerationVerification,error){
            t.Fatal("B called final generation verifier after group failure")
            return BacklogGenerationVerification{},nil
        })
    if err==nil{t.Fatal("C1 B accepted a failed independent read-only group proof")}
    if ctx.Err()!=nil{t.Fatal("B verification failure cancelled A context")}

    // The committed groups may pass, but final whole-generation evidence can
    // still fail independently; the child must exit nonzero, never PASS.
    p=privateC1ProcessPlanFixture(t)
    called:=0
    err=privateC1VerifyProcessCommands(ctx,bufio.NewScanner(
        strings.NewReader("READY 1\nREADY 2\nDRAIN\nGROUPS\nFINAL\n")),&p,
        func(context.Context,int)error{return nil},
        func(context.Context)(BacklogGenerationVerification,error){
            called++
            return BacklogGenerationVerification{},fmt.Errorf("missing final typed marker")
        })
    if err==nil||called!=1{
        t.Fatal("C1 B accepted a failed final whole-generation proof")
    }
}

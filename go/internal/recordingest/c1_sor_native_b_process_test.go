//go:build fi_c1_sor_dev

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
package recordingest

import (
    "context"
    "io"
    "strings"
    "testing"

    "github.com/Iron-Signal-Systems/fi/go/internal/c1handoff"
    "github.com/Iron-Signal-Systems/fi/go/internal/spool"
)

func c1NativeBTestPlan()c1NativeBPlan{
    receipt:=strings.Repeat("b",64)
    transfer:=strings.Repeat("a",64)
    f:=c1handoff.Frame{
        Kind:c1handoff.Start,SourceID:"source-1",GenerationID:"generation-1",
        ReceiptSHA256:receipt,Sequence:1,StartBatchIndex:1,
        ExpectedRecords:2,BatchIDs:[]string{"batch-0001","batch-0002"},
    }
    batches:=[]PreparedBatch{
        {BatchID:"batch-0001",ManifestSHA256:strings.Repeat("c",64),
            Manifest:spool.Manifest{BatchID:"batch-0001",RecordCount:1,DataBytes:40,
                DataSHA256:strings.Repeat("d",64)}},
        {BatchID:"batch-0002",ManifestSHA256:strings.Repeat("e",64),
            Manifest:spool.Manifest{BatchID:"batch-0002",RecordCount:2,DataBytes:80,
                DataSHA256:strings.Repeat("f",64)}},
    }
    ds:=[]BacklogCheckpointDescriptor{
        {SourceID:f.SourceID,GenerationID:f.GenerationID,
            ReceiptSHA256:receipt,TransferSHA256:transfer},
        {SourceID:f.SourceID,GenerationID:f.GenerationID,
            ReceiptSHA256:receipt,TransferSHA256:transfer,
            StartBatch:1,EndBatch:2,StartRecord:0,EndRecord:2,DataBytes:80},
    }
    return c1NativeBPlan{Start:f,SQLIDs:[]int64{11,12},
        Batches:batches,Descriptors:ds,Transfer:transfer}
}
func TestC1NativeBPlanRejectsChangedSourceAndGroup(t *testing.T){
    p:=c1NativeBTestPlan()
    if err:=c1ValidateNativeBPlan(p);err!=nil{t.Fatalf("valid native B plan rejected: %v",err)}
    for name,change:=range map[string]func(*c1NativeBPlan){
        "wrong SQL identity count":func(p *c1NativeBPlan){p.SQLIDs=p.SQLIDs[:1]},
        "wrong signed manifest records":func(p *c1NativeBPlan){p.Batches[1].Manifest.RecordCount=3},
        "wrong signed source batch":func(p *c1NativeBPlan){p.Batches[1].BatchID="batch-changed"},
        "wrong transfer digest":func(p *c1NativeBPlan){p.Transfer="not-a-digest"},
        "wrong group end":func(p *c1NativeBPlan){p.Descriptors[1].EndBatch=1},
        "wrong group record count":func(p *c1NativeBPlan){p.Descriptors[1].EndRecord=3},
        "wrong group data bytes":func(p *c1NativeBPlan){p.Descriptors[1].DataBytes=81},
        "wrong signed receipt":func(p *c1NativeBPlan){p.Descriptors[1].ReceiptSHA256=strings.Repeat("0",64)},
        "extra batch in Start":func(p *c1NativeBPlan){p.Start.BatchIDs=append(p.Start.BatchIDs,"batch-0003")},
    }{
        t.Run(name,func(t *testing.T){
            p:=c1NativeBTestPlan()
            change(&p)
            if err:=c1ValidateNativeBPlan(p);err==nil{
                t.Fatal("independent B admitted changed original signed metadata")
            }
        })
    }
}
func TestC1NativeBChildRefusesUninvitedExecution(t *testing.T){
    t.Setenv("FI_C1_B_CHILD","0")
    if err:=RunC1SoRNativeBChild(context.Background(),strings.NewReader(""),io.Discard);err==nil{
        t.Fatal("native B child accepted ordinary executable invocation")
    }
}

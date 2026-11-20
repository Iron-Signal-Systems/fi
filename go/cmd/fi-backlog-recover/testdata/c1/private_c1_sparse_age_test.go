// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// C1 regression: low-volume P6 families must commit *before* the final
// 8 GiB drain without flushing at a signed-group boundary.
package recordingest

import (
    "context"
    "testing"
)

func TestPrivateC1AgedSparseHandoffsCommitBeforeEndOfSignedInput(t *testing.T){
    ctx:=context.Background()
    sink:=&privateC1BarrierFake{}
    b,err:=newPrivateP6Buffers(1,sink)
    if err!=nil{t.Fatal(err)}
    for i,k:=range []string{
        "FileObservation","WindowsSecurityCoverage","USNReadBoundary",
        "CollectorIdentity","WindowsSecurityEvent",
    }{
        if err=b.Add(ctx,privateP6Fixture(1,int64(i+1),k));err!=nil{t.Fatal(err)}
    }
    // Simulate continuous signed input beyond a 4GiB reporting boundary.
    // P5/P6 buffers are never Finish()'ed or explicitly flushed there.
    for batch:=2;batch<1+privateC1SparseMaxBatchLag;batch++{
        if err=b.Add(ctx,privateP6Fixture(batch,1,"WindowsSecurityEvent"));err!=nil{t.Fatal(err)}
    }
    for _,f:=range []privateP6Family{
        privateP6Coverage,privateP6USN,privateP6Other,
    }{
        if len(sink.typedRows[f])!=0{
            t.Fatalf("%s flushed before sparse pending was old enough",privateP6FamilyNames[f])
        }
    }
    if b.finished{t.Fatal("unexpected group-boundary Finish")}
    // Advancing by one signed batch makes the sparse data age >=64 batches.
    // This DOES NOT depend on the new family having any rows in this batch.
    if err=b.Add(ctx,privateP6Fixture(1+privateC1SparseMaxBatchLag,1,"WindowsSecurityEvent"));err!=nil{
        t.Fatal(err)
    }
    for _,f:=range []privateP6Family{
        privateP6Coverage,privateP6USN,privateP6Other,
    }{
        if len(sink.typedRows[f])!=1||b.lanes[f].ageHandoffs!=1||
            b.lanes[f].finalHandoffs!=0{
            t.Fatalf("%s did not issue one aged SQL handoff before end of input",
                privateP6FamilyNames[f])
        }
    }
    // USN retains the original File-before-USN dependency and ACK.
    if len(sink.typedRows[privateP6File])!=1||!sink.waited||
        b.lanes[privateP6File].dependencyHandoffs!=1{
        t.Fatal("sparse USN handoff bypassed original File SQL prerequisite")
    }
    // Aged sparse work cannot spuriously flush Security/other SQL families.
    if len(sink.typedRows[privateP6Security])!=0||
        b.lanes[privateP6Security].handoffs!=0||b.finished{
        t.Fatal("sparse age became an all-family or group-end SQL barrier")
    }
    if err=b.Finish(ctx);err!=nil{t.Fatal(err)}
    if got:=len(sink.sourceRows);got!=1+privateC1SparseMaxBatchLag+4{
        t.Fatalf("original source identity rows lost after age + final drain: %d",got)
    }
}

func TestPrivateC1SparseFlushFailureFailsClosed(t *testing.T){
    ctx:=context.Background()
    sink:=&privateP6TestSink{failFamily:privateP6Coverage+1}
    b,err:=newPrivateP6Buffers(1,sink)
    if err!=nil{t.Fatal(err)}
    if err=b.Add(ctx,privateP6Fixture(1,1,"WindowsSecurityCoverage"));err!=nil{t.Fatal(err)}
    for batch:=2;batch<1+privateC1SparseMaxBatchLag;batch++{
        if err=b.Add(ctx,privateP6Fixture(batch,1,"WindowsSecurityEvent"));err!=nil{t.Fatal(err)}
    }
    if err=b.Add(ctx,privateP6Fixture(1+privateC1SparseMaxBatchLag,1,"WindowsSecurityEvent"));err==nil{
        t.Fatal("aged sparse SQL child failure did not reject continued signed input")
    }
    if b.failed==nil||b.finished{
        t.Fatal("P6 sparse failure did not leave dirty private clone fail closed")
    }
    if err=b.Finish(ctx);err==nil{
        t.Fatal("P6 typed marker could advance after aged SQL failure")
    }
}

func TestPrivateC1SparseNoPrematureFlushWithinSignedGroup(t *testing.T){
    sink:=&privateP6TestSink{}
    b,err:=newPrivateP6Buffers(1,sink)
    if err!=nil{t.Fatal(err)}
    ctx:=context.Background()
    if err=b.Add(ctx,privateP6Fixture(200,1,"CollectorIdentity"));err!=nil{t.Fatal(err)}
    if err=b.Add(ctx,privateP6Fixture(200+privateC1SparseMaxBatchLag-1,1,"WindowsSecurityEvent"));err!=nil{
        t.Fatal(err)
    }
    if len(sink.calls)!=0{
        t.Fatalf("aged sparse policy flushed before signed-batch watermark: %v",sink.calls)
    }
    if err=b.Finish(ctx);err!=nil{t.Fatal(err)}
    if len(sink.typedRows[privateP6Other])!=1{
        t.Fatal("unchanged small sparse tail not committed at actual end of input")
    }
}

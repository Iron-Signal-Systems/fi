// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// C1: family flushes on real resource need (capacity, dependency, bounded\n// age); verifier and reporting-group boundaries never request a flush.
package recordingest

import (
    "context"
    "testing"
    "time"
)

func TestPrivateC1SparseFamiliesDoNotFlushForVerifierTiming(t *testing.T){
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
    // Cross many original batches without P6 reacting to an arbitrary
    // 64-batch timer or reporting group boundary to satisfy verifier B.
    for batch:=2;batch<=66;batch++{
        if err=b.Add(ctx,privateP6Fixture(batch,1,"WindowsSecurityEvent"));err!=nil{t.Fatal(err)}
    }
    for _,f:=range []privateP6Family{
        privateP6Coverage,privateP6USN,privateP6Other,
    }{
        if len(sink.typedRows[f])!=0||b.lanes[f].handoffs!=0{
            t.Fatalf("%s flushed because of verification timing",privateP6FamilyNames[f])
        }
    }
    if b.finished{t.Fatal("P6 finished early at an arbitrary batch boundary")}
    if err=b.Finish(ctx);err!=nil{t.Fatal(err)}
    for _,f:=range []privateP6Family{
        privateP6Coverage,privateP6USN,privateP6Other,
    }{
        if len(sink.typedRows[f])!=1||b.lanes[f].finalHandoffs!=1{
            t.Fatalf("%s missing one true end-of-input commit",privateP6FamilyNames[f])
        }
    }
    if !sink.waited||len(sink.typedRows[privateP6File])!=1{
        t.Fatal("File-to-USN prerequisite did not commit")
    }
    if got:=len(sink.sourceRows);got!=70{
        t.Fatalf("signed source ledger count %d, expected 70",got)
    }
}

func TestPrivateC1FinalSparseSQLFailureFailsClosed(t *testing.T){
    ctx:=context.Background()
    sink:=&privateP6TestSink{failFamily:privateP6Coverage+1}
    b,err:=newPrivateP6Buffers(1,sink)
    if err!=nil{t.Fatal(err)}
    if err=b.Add(ctx,privateP6Fixture(1,1,"WindowsSecurityCoverage"));err!=nil{t.Fatal(err)}
    for batch:=2;batch<=66;batch++{
        if err=b.Add(ctx,privateP6Fixture(batch,1,"WindowsSecurityEvent"));err!=nil{t.Fatal(err)}
    }
    if err=b.Finish(ctx);err==nil{
        t.Fatal("SQL child failure permitted final signed completion")
    }
    if b.failed==nil||b.finished{
        t.Fatal("failed P6 SQL handoff did not remain failed")
    }
}

func TestPrivateC1SparseOtherFlushesWhenPendingAgeNeedsIt(t *testing.T){
    ctx:=context.Background()
    sink:=&privateP6TestSink{}
    b,err:=newPrivateP6Buffers(1,sink)
    if err!=nil{t.Fatal(err)}
    if err=b.Add(ctx,privateP6Fixture(1,1,"CollectorIdentity"));err!=nil{t.Fatal(err)}
    // Simulate the Other row having waited beyond the allowed age.
    // Neither a signed batch boundary nor a B callback is involved.
    b.lanes[privateP6Other].firstPendingAt=time.Now().Add(-3*time.Second)
    for i:=int64(2);i<=privateC1FamilyAgePollRecords;i++{
        if err=b.Add(ctx,privateP6Fixture(1,i,"WindowsSecurityEvent"));err!=nil{t.Fatal(err)}
    }
    if got:=len(sink.typedRows[privateP6Other]);got!=1 ||
       b.lanes[privateP6Other].ageHandoffs!=1 {
        t.Fatalf("old Other records stayed buffered: committed=%d age_flushes=%d",
            got,b.lanes[privateP6Other].ageHandoffs)
    }
    if b.lanes[privateP6Security].handoffs!=0 ||
       len(sink.typedRows[privateP6Security])!=0 ||
       b.finished{
        t.Fatal("age flush incorrectly drained or finished another family")
    }
    if got:=len(sink.sourceRows);got!=int(privateC1FamilyAgePollRecords){
        t.Fatalf("age flush failed original source-parent prerequisite: %d",got)
    }
    if err=b.Finish(ctx);err!=nil{t.Fatal(err)}
    if len(sink.typedRows[privateP6Security])!=int(privateC1FamilyAgePollRecords-1) {
        t.Fatal("final Security processing lost a signed row")
    }
}

func TestPrivateC1AgedUSNStillWaitsForFileWithoutGlobalDrain(t *testing.T){
    ctx:=context.Background()
    sink:=&privateC1BarrierFake{}
    b,err:=newPrivateP6Buffers(1,sink)
    if err!=nil{t.Fatal(err)}
    if err=b.Add(ctx,privateP6Fixture(1,1,"FileObservation"));err!=nil{t.Fatal(err)}
    if err=b.Add(ctx,privateP6Fixture(1,2,"USNReadBoundary"));err!=nil{t.Fatal(err)}
    b.lanes[privateP6File].firstPendingAt=time.Now().Add(-13*time.Second)
    b.lanes[privateP6USN].firstPendingAt=time.Now().Add(-3*time.Second)
    for i:=int64(3);i<=2*privateC1FamilyAgePollRecords;i++{
        if err=b.Add(ctx,privateP6Fixture(1,i,"WindowsSecurityEvent"));err!=nil{t.Fatal(err)}
    }
    if b.lanes[privateP6File].ageHandoffs!=1 ||
       b.lanes[privateP6USN].ageHandoffs!=1 ||
       !sink.waited || len(sink.typedRows[privateP6USN])!=1 {
        t.Fatal("aged File->USN dependency did not become durable")
    }
    if b.lanes[privateP6Security].handoffs!=0 || b.finished{
        t.Fatal("aged dependency forced unrelated drain or end-of-input")
    }
    if err=b.Finish(ctx);err!=nil{t.Fatal(err)}
}

func TestPrivateC1AgeTriggeredSQLFailureFailsClosed(t *testing.T){
    ctx:=context.Background()
    sink:=&privateP6TestSink{failFamily:privateP6Other+1}
    b,err:=newPrivateP6Buffers(1,sink)
    if err!=nil{t.Fatal(err)}
    if err=b.Add(ctx,privateP6Fixture(1,1,"CollectorIdentity"));err!=nil{t.Fatal(err)}
    b.lanes[privateP6Other].firstPendingAt=time.Now().Add(-3*time.Second)
    var got error
    for i:=int64(2);i<=privateC1FamilyAgePollRecords;i++{
        got=b.Add(ctx,privateP6Fixture(1,i,"WindowsSecurityEvent"))
        if got!=nil{break}
    }
    if got==nil || b.failed==nil || b.finished {
        t.Fatal("aged Family Processing SQL failure was not fail-closed")
    }
    if err=b.Finish(ctx);err==nil{
        t.Fatal("failed aged handoff allowed final marker")
    }
}

func TestPrivateC1RecordAgeFlushWithoutWallClockExpiration(t *testing.T){
    ctx:=context.Background()
    sink:=&privateP6TestSink{}
    b,err:=newPrivateP6Buffers(1,sink)
    if err!=nil{t.Fatal(err)}
    if err=b.Add(ctx,privateP6Fixture(1,1,"CollectorIdentity"));err!=nil{t.Fatal(err)}
    // Model a very high throughput stream: pending record-age bound must
    // also force a family handoff even if fewer than 2 seconds passed.
    b.lanes[privateP6Other].firstPendingOrdinal=-privateC1FamilyMaxAdmittedAge[privateP6Other]
    for i:=int64(2);i<=privateC1FamilyAgePollRecords;i++{
        if err=b.Add(ctx,privateP6Fixture(1,i,"WindowsSecurityEvent"));err!=nil{t.Fatal(err)}
    }
    if b.lanes[privateP6Other].ageHandoffs!=1 ||
       len(sink.typedRows[privateP6Other])!=1{
        t.Fatal("record-age fallback failed to drain aged sparse family")
    }
}

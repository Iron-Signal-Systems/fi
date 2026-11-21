// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// C1 Family Processing flushes on independent capacity, dependency, or\n// 30-second family inactivity; verifier and group boundaries never flush.
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


func TestPrivateC1ThirtySecondIdleFlushWithoutAnotherRecord(t *testing.T){
    sink:=&privateP6TestSink{}
    b,err:=newPrivateP6Buffers(1,sink)
    if err!=nil{t.Fatal(err)}
    ctx:=context.Background()
    if err=b.Add(ctx,privateP6Fixture(1,1,"CollectorIdentity"));err!=nil{t.Fatal(err)}
    now:=time.Now()
    b.lanes[privateP6Other].lastReceivedAt=now.Add(-31*time.Second)
    // There is deliberately NO call to Add after setting idle time.
    if err=b.flushIdleFamilies(ctx,now);err!=nil{t.Fatal(err)}
    if len(sink.typedRows[privateP6Other])!=1 || len(sink.sourceRows)!=1 ||
       b.lanes[privateP6Other].idleHandoffs!=1 ||
       b.lanes[privateP6Other].finalHandoffs!=0 || b.finished{
        t.Fatal("30-second idle did not commit sparse Other independently")
    }
    if err=b.flushIdleFamilies(ctx,now.Add(time.Second));err!=nil{t.Fatal(err)}
    if b.lanes[privateP6Other].idleHandoffs!=1{
        t.Fatal("empty family flushed twice")
    }
    if err=b.Finish(ctx);err!=nil{t.Fatal(err)}
}
func TestPrivateC1ThirtySecondIdleTimerResetsOnEachFamilyRecord(t *testing.T){
    sink:=&privateP6TestSink{}
    b,err:=newPrivateP6Buffers(1,sink)
    if err!=nil{t.Fatal(err)}
    ctx:=context.Background()
    if err=b.Add(ctx,privateP6Fixture(1,1,"CollectorIdentity"));err!=nil{t.Fatal(err)}
    b.lanes[privateP6Other].lastReceivedAt=time.Now().Add(-40*time.Second)
    if err=b.Add(ctx,privateP6Fixture(1,2,"CollectorIdentity"));err!=nil{t.Fatal(err)}
    if err=b.flushIdleFamilies(ctx,time.Now());err!=nil{t.Fatal(err)}
    if b.lanes[privateP6Other].idleHandoffs!=0 || len(sink.typedRows[privateP6Other])!=0{
        t.Fatal("idle timer did not reset on new record for that family")
    }
    later:=b.lanes[privateP6Other].lastReceivedAt.Add(30*time.Second+time.Millisecond)
    if err=b.flushIdleFamilies(ctx,later);err!=nil{t.Fatal(err)}
    if len(sink.typedRows[privateP6Other])!=2 || b.lanes[privateP6Other].idleHandoffs!=1{
        t.Fatal("30-second inactivity did not commit both records together")
    }
    if err=b.Finish(ctx);err!=nil{t.Fatal(err)}
}
func TestPrivateC1ThirtySecondIdleNeverDrainsActiveOtherFamilies(t *testing.T){
    ctx:=context.Background()
    sink:=&privateP6TestSink{}
    b,err:=newPrivateP6Buffers(1,sink)
    if err!=nil{t.Fatal(err)}
    if err=b.Add(ctx,privateP6Fixture(1,1,"CollectorIdentity"));err!=nil{t.Fatal(err)}
    if err=b.Add(ctx,privateP6Fixture(1,2,"WindowsSecurityEvent"));err!=nil{t.Fatal(err)}
    b.lanes[privateP6Other].lastReceivedAt=time.Now().Add(-31*time.Second)
    if err=b.flushIdleFamilies(ctx,time.Now());err!=nil{t.Fatal(err)}
    if b.lanes[privateP6Other].idleHandoffs!=1||
       b.lanes[privateP6Security].handoffs!=0 ||
       len(sink.typedRows[privateP6Security])!=0{
        t.Fatal("independent sparse Other idle flush drained active Security")
    }
    if err=b.Finish(ctx);err!=nil{t.Fatal(err)}
}
func TestPrivateC1ThirtySecondIdleUSNStillWaitsForFileDependency(t *testing.T){
    ctx:=context.Background()
    sink:=&privateC1BarrierFake{}
    b,err:=newPrivateP6Buffers(1,sink)
    if err!=nil{t.Fatal(err)}
    if err=b.Add(ctx,privateP6Fixture(1,1,"WindowsSecurityEvent"));err!=nil{t.Fatal(err)}
    if err=b.Add(ctx,privateP6Fixture(1,2,"FileObservation"));err!=nil{t.Fatal(err)}
    if err=b.Add(ctx,privateP6Fixture(1,3,"USNReadBoundary"));err!=nil{t.Fatal(err)}
    b.lanes[privateP6USN].lastReceivedAt=time.Now().Add(-31*time.Second)
    if err=b.flushIdleFamilies(ctx,time.Now());err!=nil{t.Fatal(err)}
    if !sink.waited || b.lanes[privateP6File].dependencyHandoffs!=1 ||
       b.lanes[privateP6USN].idleHandoffs!=1 ||
       len(sink.typedRows[privateP6USN])!=1{
        t.Fatal("USN idle flush lost committed File prerequisite")
    }
    if b.lanes[privateP6Security].handoffs!=0{
        t.Fatal("USN idle flush forced unrelated Security work")
    }
    if err=b.Finish(ctx);err!=nil{t.Fatal(err)}
}
func TestPrivateC1ThirtySecondIdleSQLFailureFailsClosed(t *testing.T){
    ctx:=context.Background()
    sink:=&privateP6TestSink{failFamily:privateP6Other+1}
    b,err:=newPrivateP6Buffers(1,sink)
    if err!=nil{t.Fatal(err)}
    if err=b.Add(ctx,privateP6Fixture(1,1,"CollectorIdentity"));err!=nil{t.Fatal(err)}
    b.lanes[privateP6Other].lastReceivedAt=time.Now().Add(-31*time.Second)
    if err=b.flushIdleFamilies(ctx,time.Now());err==nil{
        t.Fatal("idle family SQL failure was lost")
    }
    if b.failed==nil || b.finished {
        t.Fatal("failed Family Processing idle handoff allowed completion")
    }
    if err=b.Finish(ctx);err==nil{t.Fatal("failed idle handoff permitted final marker")}
}
func TestPrivateC1IdlePollDoesNotDependOnRecordOrGroupBoundary(t *testing.T){
    ctx:=context.Background()
    sink:=&privateP6TestSink{}
    b,err:=newPrivateP6Buffers(1,sink)
    if err!=nil{t.Fatal(err)}
    if err=b.Add(ctx,privateP6Fixture(1,1,"CollectorIdentity"));err!=nil{t.Fatal(err)}
    // Model the production independent tick while the input is silent.
    ticker:=time.NewTicker(5*time.Millisecond)
    defer ticker.Stop()
    b.idleTimeout=12*time.Millisecond
    fired:=false
    until:=time.After(250*time.Millisecond)
    for !fired {
        select{
        case now:=<-ticker.C:
            if err=b.flushIdleFamilies(ctx,now);err!=nil{t.Fatal(err)}
            fired=b.lanes[privateP6Other].idleHandoffs==1
        case <-until:
            t.Fatal("independent timer failed to drain idle family without Add")
        }
    }
    if len(sink.typedRows[privateP6Other])!=1 || b.finished{
        t.Fatal("independent idle tick did not commit sparse family")
    }
    if err=b.Finish(ctx);err!=nil{t.Fatal(err)}
}

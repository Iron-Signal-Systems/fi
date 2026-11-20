// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// C1 regression: verifier scheduling does not change P6 family buffering.
package recordingest

import (
    "context"
    "testing"
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

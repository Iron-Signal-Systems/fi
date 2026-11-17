// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
package recordingest

import (
    "context"
    "testing"
)

func TestPrivateP9BuffersSurviveOriginalW512AndBatchBoundaries(t *testing.T){
    ctx:=context.Background()
    ledger:=&privateP6TestSink{}
    buffers,err:=newPrivateP6Buffers(1,ledger)
    if err!=nil{t.Fatal(err)}
    kinds:=[]string{"WindowsSecurityEvent","FileObservation","WindowsSecurityCoverage",
        "USNReadBoundary","CollectorIdentity"}
    // W512 1 uses signed batch 1; W512 2 uses signed batch 2. Neither
    // boundary is a capacity or SQL dependency, so NO family is flushed.
    for batch:=1;batch<=2;batch++{
        for i,kind:=range kinds{
            if err=buffers.Add(ctx,privateP6Fixture(batch,int64(i+1),kind));err!=nil{
                t.Fatalf("original window=%d kind=%s: %v",batch,kind,err)
            }
        }
        if len(ledger.calls)!=0 || buffers.finished {
            t.Fatalf("window %d induced an artificial source/family COPY: %v",batch,ledger.calls)
        }
    }
    if err=buffers.Finish(ctx);err!=nil{t.Fatal(err)}
    if len(ledger.sourceRows)!=10 || buffers.total!=10 {
        t.Fatal("P9 end-of-stream lost signed parent identity across W512")
    }
    for _,f:=range []privateP6Family{privateP6Security,privateP6File,
        privateP6Coverage,privateP6USN,privateP6Other}{
        if len(ledger.typedRows[f])!=2{t.Fatalf("family=%s crossed windows incorrectly",privateP6FamilyNames[f])}
    }
}

func TestPrivateP9CapacityFlushDoesNotDrainOtherFamilyAcrossW512(t *testing.T){
    ctx:=context.Background()
    ledger:=&privateP6TestSink{}
    b,err:=newPrivateP6Buffers(1,ledger)
    if err!=nil{t.Fatal(err)}
    if err=b.Add(ctx,privateP6Fixture(1,1,"CollectorIdentity"));err!=nil{t.Fatal(err)}
    // 2000 Security events in W512 1 followed by 2096 in W512 2.
    // Security flushes precisely at 4096 (capacity), not at a W512
    // boundary or because the earlier Other buffer exists.
    for batch:=1;batch<=2;batch++{
        count:=2000
        if batch==2 {count=2096}
        for i:=0;i<count;i++{
            if err=b.Add(ctx,privateP6Fixture(batch,int64(i+2),"WindowsSecurityEvent"));err!=nil{t.Fatal(err)}
        }
        if batch==1 && len(ledger.calls)!=0 {
            t.Fatal("P9 drained unfilled Security at first window boundary")
        }
    }
    if len(ledger.typedRows[privateP6Security])!=4096 ||
        len(ledger.typedRows[privateP6Other])!=0 ||
        b.lanes[privateP6Security].capacityHandoffs!=1 ||
        b.lanes[privateP6Other].handoffs!=0 {
        t.Fatal("P9 Security capacity incorrectly flushed unrelated family")
    }
    if err=b.Finish(ctx);err!=nil{t.Fatal(err)}
    if len(ledger.typedRows[privateP6Other])!=1{
        t.Fatal("P9 final drain lost previously queued Other record")
    }
}

func TestPrivateP9SelectedOnlyOnExplicitPrivateFiveSQLPath(t *testing.T){
    t.Setenv("FI_W512_P9_DIRECT_STREAM","1")
    t.Setenv("FI_W512_P7_SQL_WRITERS","5")
    t.Setenv("FI_W512_P6_FAMILY_SQL","1")
    t.Setenv("FI_W512_P5_PERSISTENT","1")
    t.Setenv("FI_W512_P8_REUSE","")
    if !privateP9DirectSelected(){t.Fatal("P9 explicit direct five-writer path was not selected")}
    t.Setenv("FI_W512_P8_REUSE","1")
    if privateP9DirectSelected(){t.Fatal("P9 must not mix with P8 materialization path")}
    t.Setenv("FI_W512_P8_REUSE","")
    t.Setenv("FI_W512_P7_SQL_WRITERS","1")
    if privateP9DirectSelected(){t.Fatal("P9 cannot silently fall back to one SQL writer")}
    t.Setenv("FI_W512_P7_SQL_WRITERS","5")
    t.Setenv("FI_W512_P9_DIRECT_STREAM","")
    if privateP9DirectSelected(){t.Fatal("P9 must remain disabled in normal FI")}
}

func TestPrivateP9RunLimitsNoEarlyBoundaryDrain(t *testing.T){
    t.Setenv("FI_W512_P9_STOP_WINDOWS","")
    n,err:=privateP9RunEnd(1,31)
    if err!=nil||n!=31{t.Fatalf("normal complete run %d %v",n,err)}
    t.Setenv("FI_W512_P9_STOP_WINDOWS","2")
    n,err=privateP9RunEnd(1,31)
    if err!=nil||n!=3{t.Fatalf("two-window stream %d %v",n,err)}
    for _,v:=range []string{"0","-1","31","invalid"} {
        t.Setenv("FI_W512_P9_STOP_WINDOWS",v)
        if _,err=privateP9RunEnd(1,31);err==nil{
            t.Fatalf("P9 accepted unsafe run limit %q",v)
        }
    }
}

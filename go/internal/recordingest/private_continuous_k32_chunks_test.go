// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package recordingest

import (
    "context"
    "testing"
)

func TestPrivateContinuousK32DispatchesExactly32768WithoutFamilyBoundaryFlush(t *testing.T) {
    ctx:=context.Background()
    sink:=newPrivateContinuousSinkProbe()
    sink.durable[3]=true
    router,err:=newPrivateContinuousFamilyRouter(ctx,sink,2)
    if err!=nil{t.Fatal(err)}
    if err=router.BeginSourceWindow(ctx,3);err!=nil{t.Fatal(err)}
    chunk,err:=newPrivateContinuousK32Chunk(router,3)
    if err!=nil{t.Fatal(err)}
    // 32768 mixed ORIGINAL signed records form one K32 unit. File, Security,
    // Coverage, and USN buffering rules are NOT reset by that unit.
    for i:=1;i<=privateContinuousK32MaxRecords;i++ {
        kind:="FileObservation"
        if i%2==0 {kind="WindowsSecurityEvent"}
        record:=privateContinuousFixture(3,151,int64(i),kind,128)
        if err=chunk.Add(ctx,record);err!=nil{t.Fatal(err)}
        if i==privateContinuousK32MaxRecords-1 && chunk.dispatched!=0 {
            t.Fatal("incomplete K32 work unit dispatched early")
        }
    }
    if chunk.chunks!=1 || chunk.dispatched!=32768 ||
        chunk.dispatchedBytes!=32768*128 || len(chunk.pending)!=0 {
        t.Fatalf("full K32 dispatch count=%d records=%d bytes=%d pending=%d",
            chunk.chunks,chunk.dispatched,chunk.dispatchedBytes,len(chunk.pending))
    }
    if sink.flushes[privateFamilyFile]!=2 || sink.flushes[privateFamilySecurity]!=4 {
        t.Fatalf("only actual family capacities should flush: %v",sink.flushes)
    }
    if sink.flushes[privateFamilyUSN]!=0 || sink.flushes[privateFamilyCoverage]!=0 {
        t.Fatal("K32 dispatch triggered unrelated family flush")
    }
    if len(sink.projected)!=0 {t.Fatal("K32 dispatch published typed window before W128 closed")}
    if err=chunk.EndSourceWindow(ctx);err!=nil{t.Fatal(err)}
    if err=router.EndSourceWindow(ctx,3);err!=nil{t.Fatal(err)}
    if err=router.EndOfInput(ctx);err!=nil{t.Fatal(err)}
    if router.confirmedThrough!=3 || len(sink.committed)!=32768 {
        t.Fatal("full K32 source did not complete exactly once")
    }
}

func TestPrivateContinuousK32ShortChunksPreserveBuffersAcrossW128(t *testing.T) {
    ctx:=context.Background()
    sink:=newPrivateContinuousSinkProbe()
    sink.durable[3]=true
    sink.durable[4]=true
    router,err:=newPrivateContinuousFamilyRouter(ctx,sink,2)
    if err!=nil{t.Fatal(err)}
    kinds:=[]string{"FileObservation","WindowsSecurityEvent","USNReadBoundary","WindowsSecurityCoverage"}
    for window:=3;window<=4;window++ {
        if err=router.BeginSourceWindow(ctx,window);err!=nil{t.Fatal(err)}
        chunk,e:=newPrivateContinuousK32Chunk(router,window)
        if e!=nil{t.Fatal(e)}
        for i,kind:=range kinds {
            row:=privateContinuousFixture(window,151+window,int64(i+1),kind,512)
            if e=chunk.Add(ctx,row);e!=nil{t.Fatal(e)}
        }
        if chunk.dispatched!=0 || len(sink.committed)!=0 {
            t.Fatal("short K32 work unit routed prematurely")
        }
        if e=chunk.EndSourceWindow(ctx);e!=nil{t.Fatal(e)}
        if chunk.chunks!=1 || chunk.dispatched!=4 {t.Fatal("short K32 records not dispatched")}
        if e=router.EndSourceWindow(ctx,window);e!=nil{t.Fatal(e)}
        if len(sink.committed)!=0 || len(sink.projected)!=0 {
            t.Fatal("K32 or W128 boundary drained independent family buffers")
        }
    }
    if err=router.EndOfInput(ctx);err!=nil{t.Fatal(err)}
    if len(sink.committed)!=8 || len(sink.projected)!=2 ||
        sink.projected[0]!=3 || sink.projected[1]!=4 {
        t.Fatalf("end-of-input did not finish both W128 windows exactly: %v",sink.projected)
    }
    for _,family:=range []privateContinuousFamily{
        privateFamilyFile,privateFamilySecurity,privateFamilyUSN,privateFamilyCoverage,
    } {
        if sink.flushes[family]!=1 {
            t.Fatalf("family %s must commit once only at actual end-of-input, got %d",family,sink.flushes[family])
        }
    }
}

func TestPrivateContinuousK32SQLFailureDoesNotAdvanceChunk(t *testing.T) {
    ctx:=context.Background()
    sink:=newPrivateContinuousSinkProbe()
    sink.durable[3]=true
    sink.failFamily=privateFamilySecurity
    router,err:=newPrivateContinuousFamilyRouter(ctx,sink,2)
    if err!=nil{t.Fatal(err)}
    if err=router.BeginSourceWindow(ctx,3);err!=nil{t.Fatal(err)}
    chunk,err:=newPrivateContinuousK32Chunk(router,3)
    if err!=nil{t.Fatal(err)}
    for i:=1;i<=4096;i++ {
        if err=chunk.Add(ctx,privateContinuousFixture(3,151,int64(i),"WindowsSecurityEvent",128));err!=nil {
            t.Fatal(err)
        }
    }
    if err=chunk.EndSourceWindow(ctx);err==nil {t.Fatal("K32 swallowed family SQL rollback")}
    if chunk.chunks!=0 || chunk.dispatched!=0 || len(chunk.pending)!=4096 ||
        len(sink.projected)!=0 || len(sink.committed)!=0 {
        t.Fatal("failed K32 dispatch released input or marked projected")
    }
}

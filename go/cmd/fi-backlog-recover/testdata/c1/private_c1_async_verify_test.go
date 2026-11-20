// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
package recordingest

import (
    "context"
    "errors"
    "io"
    "os"
    "sync/atomic"
    "testing"
    "time"
)

func TestPrivateC1AsyncVerifierRunsBeforeFinalDrain(t *testing.T){
    ctx,cancel:=context.WithTimeout(context.Background(),5*time.Second)
    defer cancel()
    calls:=make(chan int,4)
    var ready atomic.Bool
    v,err:=newPrivateC1AsyncVerifier(ctx,1,3,func(ctx context.Context,wi int)error{
        select{case calls<-wi:default:}
        if !ready.Load(){return errors.New("FI C1 test: P6 SQL still in flight")}
        return nil
    })
    if err!=nil{t.Fatal(err)}
    defer v.Stop()
    v.retry=10*time.Millisecond
    if err=v.Seal(1);err!=nil{t.Fatal(err)}
    select{
    case wi:=<-calls:
        if wi!=1{t.Fatalf("background verifier started group %d, expected 1",wi)}
    case <-ctx.Done():
        t.Fatal("no background verifier read while ingestion remained active")
    }
    // The first group is not complete yet; sealing next group is nonblocking.
    if err=v.Seal(2);err!=nil{t.Fatal(err)}
    ready.Store(true)
    if err=v.Finish(ctx);err!=nil{t.Fatal(err)}
    if !v.checked[1]||!v.checked[2]{
        t.Fatal("independent verifier failed to deliver complete group proofs")
    }
}

func TestPrivateC1AsyncVerifierFailsClosedAfterFinalSQLDrain(t *testing.T){
    ctx,cancel:=context.WithTimeout(context.Background(),5*time.Second)
    defer cancel()
    v,err:=newPrivateC1AsyncVerifier(ctx,1,2,func(context.Context,int)error{
        return errors.New("FI C1 test: committed family projection missing")
    })
    if err!=nil{t.Fatal(err)}
    defer v.Stop()
    if err=v.Seal(1);err!=nil{t.Fatal(err)}
    if err=v.Finish(ctx);err==nil{
        t.Fatal("C1 accepted a signed group with missing committed relational rows")
    }
    if v.checked[1]{
        t.Fatal("C1 reported successful async verification of missing projection")
    }
}

func TestPrivateC1AsyncVerifierStopWithoutAnySealedGroup(t *testing.T){
    ctx,cancel:=context.WithTimeout(context.Background(),5*time.Second)
    defer cancel()
    v,err:=newPrivateC1AsyncVerifier(ctx,1,3,func(context.Context,int)error{
        t.Fatal("unexpected SQL verification while no group is sealed")
        return nil
    })
    if err!=nil{t.Fatal(err)}
    completed:=make(chan struct{})
    go func(){v.Stop();close(completed)}()
    select{
    case <-completed:
    case <-ctx.Done():t.Fatal("asynchronous verifier cancellation stranded idle worker")
    }
}

func TestPrivateC1AsyncVerifierRejectsMissingAndOutOfOrderGroups(t *testing.T){
    ctx,cancel:=context.WithTimeout(context.Background(),5*time.Second)
    defer cancel()
    v,err:=newPrivateC1AsyncVerifier(ctx,1,3,func(context.Context,int)error{return nil})
    if err!=nil{t.Fatal(err)}
    defer v.Stop()
    if err=v.Seal(2);err==nil{t.Fatal("out of order hash seal accepted")}
    if err=v.Seal(1);err!=nil{t.Fatal(err)}
    if err=v.Finish(ctx);err==nil{t.Fatal("missing sealed group accepted")}
}

func TestPrivateC1SignedBatchSealsOnlyAfterSHAAndNeverOnTamper(t *testing.T){
    b1:=privateC1SignedStreamFixture(t,100,1,1,"WindowsSecurityCoverage")
    b2:=privateC1SignedStreamFixture(t,101,2,1,"CollectorIdentity")
    reader,err:=newPrivateC1SignedContinuousReader([]privateC1StreamBatch{b1,b2})
    if err!=nil{t.Fatal(err)}
    var groups []int
    reader.onSealedGroup=func(wi int)error{groups=append(groups,wi);return nil}
    if _,err=io.Copy(io.Discard,reader);err!=nil{t.Fatal(err)}
    if err=reader.VerifyComplete();err!=nil{t.Fatal(err)}
    if len(groups)!=2||groups[0]!=1||groups[1]!=2{
        t.Fatalf("per-group SHA seals mismatch %v",groups)
    }
    tampered,err:=newPrivateC1SignedContinuousReader([]privateC1StreamBatch{b1,b2})
    if err!=nil{t.Fatal(err)}
    defer tampered.Close()
    var count int
    tampered.onSealedGroup=func(int)error{count++;return nil}
    raw,err:=os.ReadFile(b1.Batch.DataPath)
    if err!=nil{t.Fatal(err)}
    raw[0]^=1
    if err=os.WriteFile(b1.Batch.DataPath,raw,0600);err!=nil{t.Fatal(err)}
    if _,err=io.Copy(io.Discard,tampered);err==nil{
        t.Fatal("corrupt signed group progressed without hash verification")
    }
    if count!=0{t.Fatalf("tampered source emitted %d completion seals",count)}
}

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
package recordingest

import (
    "context"
    "errors"
    "io"
    "os"
    "testing"
    "time"
)

func TestPrivateC1AsyncVerifierCommitsDuringIngestWithoutFinalDrain(t *testing.T){
    ctx,cancel:=context.WithTimeout(context.Background(),5*time.Second)
    defer cancel()
    ready:=make(chan int,2)
    secondMayFinish:=make(chan struct{})
    v,err:=newPrivateC1AsyncVerifier(ctx,1,3,ready,
        func(ctx context.Context,wi int)error{
            if wi==2 {
                select{
                case <-ctx.Done():return ctx.Err()
                case <-secondMayFinish:
                }
            }
            return nil
        },nil,true)
    if err!=nil{t.Fatal(err)}
    defer v.Stop()
    ready<-1
    // Wait for the verified PASS receipt itself before signaling SQL drain:
    // no speculative first-group retry and no post-drain false positive.
    select{
    case wi:=<-v.passed:
        if wi!=1{t.Fatalf("expected first completed group, got %d",wi)}
    case <-ctx.Done():t.Fatal("group 1 did not verify DURING ingestion")
    }
    ready<-2
    v.MarkDrained()
    close(secondMayFinish)
    close(ready)
    if err=v.Finish(ctx);err!=nil{t.Fatal(err)}
    if v.during!=1{
        t.Fatalf("expected one proof before drain and one after, got %d",v.during)
    }
}

func TestPrivateC1AsyncVerifierFailsClosedAndCallsBack(t *testing.T){
    ctx,cancel:=context.WithTimeout(context.Background(),5*time.Second)
    defer cancel()
    ready:=make(chan int,1)
    notified:=make(chan error,1)
    v,err:=newPrivateC1AsyncVerifier(ctx,1,2,ready,
        func(context.Context,int)error{
            return errors.New("FI C1 test: committed typed root missing")
        },
        func(err error){notified<-err},false)
    if err!=nil{t.Fatal(err)}
    defer v.Stop()
    ready<-1
    close(ready)
    select{
    case fail:=<-notified:
        if fail==nil{t.Fatal("missing verifier error callback")}
    case <-ctx.Done():t.Fatal("the verifier did not report failure")
    }
    if err=v.Finish(ctx);err==nil{
        t.Fatal("C1 advanced with a failed independent SQL proof")
    }
}

// B can report a failed committed-data proof without cancelling A's
// ingestion context. Final completion remains fail closed.
func TestPrivateC1VerifierFailureDoesNotCancelIngestionOwner(t *testing.T){
    ctx,cancel:=context.WithTimeout(context.Background(),5*time.Second)
    defer cancel()
    ready:=make(chan int,1)
    notified:=make(chan error,1)
    v,err:=newPrivateC1AsyncVerifier(ctx,1,2,ready,
        func(context.Context,int)error{return errors.New("relational discrepancy")},
        func(err error){notified<-err},false)
    if err!=nil{t.Fatal(err)}
    defer v.Stop()
    ready<-1
    close(ready)
    select{
    case <-notified:
        if ctx.Err()!=nil{t.Fatal("independent verifier failure cancelled A")}
    case <-ctx.Done():t.Fatal("verification callback missing")
    }
    if err=v.Finish(ctx);err==nil{t.Fatal("failed B proof allowed final completion")}
}

func TestPrivateC1AsyncVerifierRejectsNoOverlappingSuccess(t *testing.T){
    ctx,cancel:=context.WithTimeout(context.Background(),5*time.Second)
    defer cancel()
    ready:=make(chan int,2)
    v,err:=newPrivateC1AsyncVerifier(ctx,1,3,ready,
        func(context.Context,int)error{return nil},nil,true)
    if err!=nil{t.Fatal(err)}
    defer v.Stop()
    v.MarkDrained()
    ready<-1
    ready<-2
    close(ready)
    if err=v.Finish(ctx);err==nil{
        t.Fatal("accepted group proofs that completed only after final P6 drain")
    }
}

func TestPrivateC1AsyncVerifierStopWithoutAnyReadyGroup(t *testing.T){
    ctx,cancel:=context.WithTimeout(context.Background(),5*time.Second)
    defer cancel()
    ready:=make(chan int,2)
    v,err:=newPrivateC1AsyncVerifier(ctx,1,3,ready,
        func(context.Context,int)error{
            t.Fatal("unexpected relational query without durable group receipt")
            return nil
        },nil,false)
    if err!=nil{t.Fatal(err)}
    completed:=make(chan struct{})
    go func(){v.Stop();close(completed)}()
    select{
    case <-completed:
    case <-ctx.Done():t.Fatal("committed verifier cancellation stranded idle worker")
    }
}

func TestPrivateC1AsyncVerifierRejectsMissingAndDuplicateReceipts(t *testing.T){
    ctx,cancel:=context.WithTimeout(context.Background(),5*time.Second)
    defer cancel()
    ready:=make(chan int,2)
    v,err:=newPrivateC1AsyncVerifier(ctx,1,3,ready,
        func(context.Context,int)error{return nil},nil,false)
    if err!=nil{t.Fatal(err)}
    defer v.Stop()
    ready<-1
    close(ready)
    if err=v.Finish(ctx);err==nil{t.Fatal("missing second verification accepted")}
    repeated:=make(chan int,3)
    v2,err:=newPrivateC1AsyncVerifier(ctx,1,3,repeated,
        func(context.Context,int)error{return nil},nil,false)
    if err!=nil{t.Fatal(err)}
    defer v2.Stop()
    repeated<-1
    repeated<-1
    repeated<-2
    close(repeated)
    if err=v2.Finish(ctx);err==nil{t.Fatal("duplicate verification receipt accepted")}
}

func TestPrivateC1CustodyBatchSealsOnlyAfterBoundaryValidation(t *testing.T){
    b1:=privateC1SignedStreamFixture(t,100,1,1,"WindowsSecurityCoverage")
    b2:=privateC1SignedStreamFixture(t,101,2,1,"CollectorIdentity")
    reader,err:=newPrivateC1SignedContinuousReader([]privateC1StreamBatch{b1,b2})
    if err!=nil{t.Fatal(err)}
    var groups []int
    reader.onSealedGroup=func(wi int)error{groups=append(groups,wi);return nil}
    if _,err=io.Copy(io.Discard,reader);err!=nil{t.Fatal(err)}
    if err=reader.VerifyComplete();err!=nil{t.Fatal(err)}
    if len(groups)!=2||groups[0]!=1||groups[1]!=2{
        t.Fatalf("per-group custody boundary seals mismatch %v",groups)
    }
    tampered,err:=newPrivateC1SignedContinuousReader([]privateC1StreamBatch{b1,b2})
    if err!=nil{t.Fatal(err)}
    defer tampered.Close()
    var count int
    tampered.onSealedGroup=func(int)error{count++;return nil}
    raw,err:=os.ReadFile(b1.Batch.DataPath)
    if err!=nil{t.Fatal(err)}
    if err=os.WriteFile(b1.Batch.DataPath,raw[:len(raw)-1],0600);err!=nil{t.Fatal(err)}
    if _,err=io.Copy(io.Discard,tampered);err==nil{
        t.Fatal("truncated signed group progressed without boundary validation")
    }
    if count!=0{t.Fatalf("tampered source emitted %d completion seals",count)}
}

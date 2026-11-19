// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// C1: the original P5 preparation and P6 independent family buffers must
// never pause a SQL family until all four outstanding handoffs are drained.
// Retire the oldest ACK only; preserve File/USN and final full-ACK fences.
package recordingest

import (
    "context"
    "errors"
    "strings"
    "testing"
    "time"
)

func privateC1BackpressureFixture()(*privateC1FiveSQL,*privateC1SQLLane,[privateC1MaxFamilyHandoffsInFlight]chan error){
    parent:=&privateC1SourceAck{done:make(chan struct{})}
    close(parent.done) // original ordered source SQL commit is complete
    w:=&privateC1FiveSQL{ctx:context.Background(),sourceLast:parent}
    lane:=&privateC1SQLLane{family:privateP6Security,
        jobs:make(chan privateC1SQLJob,1)}
    w.lanes[privateP6Security]=lane
    var acks [privateC1MaxFamilyHandoffsInFlight]chan error
    for i:=range acks{
        acks[i]=make(chan error,1)
        lane.outstanding=append(lane.outstanding,acks[i])
    }
    return w,lane,acks
}

func TestPrivateC1P5P6OnlyOldestHandoffWaitsAtBound(t *testing.T){
    w,lane,acks:=privateC1BackpressureFixture()
    ctx,cancel:=context.WithTimeout(context.Background(),2*time.Second)
    defer cancel()
    // Only the first SQL handoff completes. The other three stay pending.
    acks[0]<-nil
    row:=privateP6Fixture(1,1,"WindowsSecurityEvent")
    if err:=w.Family(ctx,privateP6Security,[]privateP6Record{row});err!=nil{
        t.Fatalf("C1 unnecessarily waited for all four family SQL jobs: %v",err)
    }
    if len(lane.outstanding)!=privateC1MaxFamilyHandoffsInFlight{
        t.Fatalf("C1 unbounded or underfilled outstanding P6 handoffs=%d",len(lane.outstanding))
    }
    for i:=1;i<len(acks);i++{
        if lane.outstanding[i-1]!=acks[i]{
            t.Fatalf("C1 did not preserve SQL FIFO position %d",i)
        }
    }
    if lane.backpressureWaits!=1 {
        t.Fatalf("C1 did not record exact continuous P6 backpressure: %d",lane.backpressureWaits)
    }
    select{
    case job:=<-lane.jobs:
        if len(job.rows)!=1||job.rows[0].ordinal!=row.ordinal||
           lane.outstanding[len(lane.outstanding)-1]!=job.done{
            t.Fatal("C1 newly admitted SQL handoff changed signed row or ACK")
        }
    default:
        t.Fatal("C1 failed to feed SQL writer immediately after oldest ACK")
    }
}

func TestPrivateC1P5P6OldestHandoffErrorStopsAdmission(t *testing.T){
    w,lane,acks:=privateC1BackpressureFixture()
    acks[0]<-errors.New("injected committed-family error")
    ctx,cancel:=context.WithTimeout(context.Background(),2*time.Second)
    defer cancel()
    err:=w.Family(ctx,privateP6Security,
        []privateP6Record{privateP6Fixture(1,1,"WindowsSecurityEvent")})
    if err==nil||!strings.Contains(err.Error(),"injected committed-family error"){
        t.Fatalf("C1 swallowed failed PostgreSQL family ACK: %v",err)
    }
    if len(lane.jobs)!=0||len(lane.outstanding)!=3||w.failed==nil{
        t.Fatal("C1 admitted another SQL buffer after prior family failure")
    }
}

func TestPrivateC1P6DependencyAndFinalFullFenceStillWaitsAll(t *testing.T){
    w,lane,acks:=privateC1BackpressureFixture()
    for i:=range acks{acks[i]<-nil}
    if err:=w.WaitFamily(context.Background(),privateP6Security);err!=nil{
        t.Fatal(err)
    }
    if len(lane.outstanding)!=0{
        t.Fatalf("C1 dependency fence left %d uncommitted handoffs",len(lane.outstanding))
    }
    // A second fence must not report a phantom SQL completion.
    if err:=w.WaitFamily(context.Background(),privateP6Security);err!=nil{
        t.Fatal(err)
    }
}

func TestPrivateC1P5P6ContextCancellationStopsOldestWait(t *testing.T){
    w,lane,_:=privateC1BackpressureFixture()
    ctx,cancel:=context.WithCancel(context.Background())
    cancel()
    if err:=w.waitNextFamily(ctx,privateP6Security);!errors.Is(err,context.Canceled){
        t.Fatalf("C1 failed to cancel bounded SQL admission: %v",err)
    }
    if len(lane.outstanding)!=privateC1MaxFamilyHandoffsInFlight{
        t.Fatal("C1 cancellation discarded unacknowledged SQL handoffs")
    }
}

// Parent commits must be a broadcast fence: both the Security and File
// workers can depend on one source ACK without stealing its result.
func TestPrivateC1OrderedSourceBroadcastAndFailure(t *testing.T){
    ctx,cancel:=context.WithTimeout(context.Background(),2*time.Second)
    defer cancel()
    ack:=&privateC1SourceAck{done:make(chan struct{})}
    started:=make(chan struct{},2)
    results:=make(chan error,2)
    for i:=0;i<2;i++{
        go func(){started<-struct{}{};results<-privateC1AwaitSource(ctx,ack)}()
    }
    <-started
    <-started
    fail:=errors.New("injected parent commit failure")
    ack.err=fail
    close(ack.done)
    for i:=0;i<2;i++{
        if err:=<-results;!errors.Is(err,fail) {
            t.Fatalf("FI C1 parent SQL failure lost across dependent lanes: %v",err)
        }
    }
}
func TestPrivateC1OrderedSourceOldestOnlyAdmission(t *testing.T){
    w:=&privateC1FiveSQL{ctx:context.Background(),
        sourceJobs:make(chan privateC1SourceJob,2)}
    for i:=0;i<privateC1MaxFamilyHandoffsInFlight;i++{
        ack:=&privateC1SourceAck{done:make(chan struct{})}
        w.sourceOutstanding=append(w.sourceOutstanding,ack)
        w.sourceLast=ack
    }
    oldest:=w.sourceOutstanding[0]
    close(oldest.done)
    ctx,cancel:=context.WithTimeout(context.Background(),2*time.Second)
    defer cancel()
    if err:=w.Source(ctx,[]privateP6Record{privateP6Fixture(1,1,"FileObservation")});err!=nil{
        t.Fatal(err)
    }
    if len(w.sourceOutstanding)!=privateC1MaxFamilyHandoffsInFlight ||
        w.sourceBackpressureWaits!=1 ||
        w.sourceOutstanding[0]==oldest ||
        w.sourceLast!=w.sourceOutstanding[len(w.sourceOutstanding)-1]{
        t.Fatal("FI C1 ordered source waited for all instead of one oldest ACK")
    }
    select{
    case job:=<-w.sourceJobs:
        if job.ack!=w.sourceLast || len(job.rows)!=1 {
            t.Fatal("FI C1 ordered source handoff detached from signed identity")
        }
    default:
        t.Fatal("FI C1 ordered source was not enqueued")
    }
}
func TestPrivateC1KnownSecurityIDsOnlyWhenEnabled(t *testing.T){
    ctx:=context.WithValue(context.Background(),privateC1KnownSourceIDsKey{},
        []int64{11,22})
    if len(privateC1KnownSourceIDs(ctx))!=0{
        t.Fatal("FI C1 Security source IDs leaked into the regular projector")
    }
    t.Setenv("FI_W512_C1_P6_DIRECT","1")
    t.Setenv("FI_W512_P6_FAMILY_SQL","1")
    t.Setenv("FI_W512_P7_SQL_WRITERS","")
    t.Setenv("FI_W512_P8_REUSE","")
    t.Setenv("FI_W512_P9_DIRECT_STREAM","")
    if ids:=privateC1KnownSourceIDs(ctx);len(ids)!=2||ids[0]!=11||ids[1]!=22{
        t.Fatal("FI C1 exact signed Security IDs not forwarded")
    }
    if len(privateC1KnownSourceIDs(context.Background()))!=0 {
        t.Fatal("FI C1 used source IDs without a signed SQL lookup")
    }
}

func TestPrivateC1OrderedSourceCancelDoesNotDiscardACK(t *testing.T){
    ack:=&privateC1SourceAck{done:make(chan struct{})}
    ctx,cancel:=context.WithCancel(context.Background())
    cancel()
    if err:=privateC1AwaitSource(ctx,ack);!errors.Is(err,context.Canceled){
        t.Fatalf("FI C1 source waiting ignored cancellation: %v",err)
    }
    w:=&privateC1FiveSQL{ctx:context.Background(),
        sourceOutstanding:[]*privateC1SourceAck{ack}}
    if err:=w.waitNextSource(ctx);!errors.Is(err,context.Canceled){
        t.Fatalf("FI C1 ordered parent wait did not fail closed: %v",err)
    }
    if len(w.sourceOutstanding)!=1 || w.sourceOutstanding[0]!=ack {
        t.Fatal("FI C1 lost unacknowledged parent SQL handoff on cancel")
    }
}

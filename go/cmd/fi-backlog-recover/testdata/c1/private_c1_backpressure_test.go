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
    "fmt"
    "strings"
    "testing"
    "time"
)

func privateC1BackpressureFixture()(*privateC1FiveSQL,*privateC1SQLLane,[privateC1MaxFamilyHandoffsInFlight]chan error){
    parent:=&privateC1SourceAck{done:make(chan struct{})}
    close(parent.done) // original ordered source SQL commit is complete
    w:=&privateC1FiveSQL{ctx:context.Background(),sourceLast:parent,
        maxWorkers:1,workerCount:1,jobs:make(chan privateC1SQLJob,1)}
    lane:=&privateC1SQLLane{family:privateP6Security}
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
    case job:=<-w.jobs:
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
    if len(w.jobs)!=0||len(lane.outstanding)!=3||w.failed==nil{
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

func TestPrivateC1AdaptiveSQLWorkersMaxValidation(t *testing.T){
    t.Setenv("FI_W512_C1_SQL_WORKERS_MAX","")
    if n,e:=privateC1SQLWorkersMax();e!=nil||n!=5{
        t.Fatalf("expected default 5, got %d %v",n,e)
    }
    for _,n:=range []int{1,2,5,8,12,16,24,31,32}{
        t.Setenv("FI_W512_C1_SQL_WORKERS_MAX",fmt.Sprint(n))
        if got,e:=privateC1SQLWorkersMax();e!=nil||got!=n{
            t.Fatalf("requested %d shared workers, got %d %v",n,got,e)
        }
    }
    for _,s:=range []string{"0","33","64","-1","bogus","1.5"," 5","0000"}{
        t.Setenv("FI_W512_C1_SQL_WORKERS_MAX",s)
        if _,e:=privateC1SQLWorkersMax();e==nil{
            t.Fatalf("accepted invalid shared SQL worker maximum %q",s)
        }
    }
}
func TestPrivateC1SharedSQLQueueAcceptsAnyFamily(t *testing.T){
    parent:=&privateC1SourceAck{done:make(chan struct{})}
    close(parent.done)
    w:=&privateC1FiveSQL{ctx:context.Background(),sourceLast:parent,
        maxWorkers:5,workerCount:5,jobs:make(chan privateC1SQLJob,5)}
    for f:=privateP6Family(0);f<privateP6FamilyCount;f++{
        w.lanes[f]=&privateC1SQLLane{family:f}
        if e:=w.Family(context.Background(),f,
            []privateP6Record{privateP6Fixture(int(f)+1,1,privateC1TestKind(f))});e!=nil{
            t.Fatal(e)
        }
    }
    if len(w.jobs)!=5{t.Fatal("one shared SQL queue did not receive all five families")}
    seen:=make(map[privateP6Family]bool)
    for i:=0;i<5;i++{
        job:=<-w.jobs
        if job.source!=parent||seen[job.family]||job.done!=w.lanes[job.family].outstanding[0]{
            t.Fatal("shared SQL worker job lost family/identity or duplicate ACK")
        }
        seen[job.family]=true
    }
    if len(seen)!=5{t.Fatal("a family was pinned to its own SQL queue")}
}
func privateC1TestKind(f privateP6Family)string{
    switch f{
    case privateP6Security:return "WindowsSecurityEvent"
    case privateP6File:return "FileObservation"
    case privateP6Coverage:return "WindowsSecurityCoverage"
    case privateP6USN:return "USNReadBoundary"
    default:return "CollectorIdentity"
    }
}
func TestPrivateC1SharedSQLFamilyBoundFollowsMax(t *testing.T){
    for _,n:=range []int{1,4,5,8,12,16,24,32}{
        w:=&privateC1FiveSQL{maxWorkers:n}
        want:=n
        if want<4{want=4}
        if w.familyLimit()!=want{t.Fatalf("max %d family capacity=%d, want %d",n,w.familyLimit(),want)}
    }
}

 
// The original P6 projector guarantees ordered USN source-bound captures.
// C1 must not let a later USN SQL transaction race a still-uncommitted
// preceding capture transaction on a different shared SQL worker.
func TestPrivateC1USNRequiresPreviousCommittedSQLACK(t *testing.T){
    parent:=&privateC1SourceAck{done:make(chan struct{})}
    close(parent.done)
    w:=&privateC1FiveSQL{ctx:context.Background(),sourceLast:parent,
        maxWorkers:32,workerCount:32,jobs:make(chan privateC1SQLJob,8)}
    w.lanes[privateP6USN]=&privateC1SQLLane{family:privateP6USN}
    w.lanes[privateP6Security]=&privateC1SQLLane{family:privateP6Security}
    if got:=w.familyHandoffLimit(privateP6USN);got!=1 {
        t.Fatalf("C1 USN SQL limit=%d, must be one committed handoff",got)
    }
    if got:=w.familyHandoffLimit(privateP6Security);got!=32 {
        t.Fatalf("C1 must not throttle unrelated Security SQL: %d",got)
    }
    first:=privateP6Fixture(1,1,"USNReadBoundary")
    next:=privateP6Fixture(2,1,"USNObjectObservation")
    if err:=w.Family(context.Background(),privateP6USN,[]privateP6Record{first});err!=nil{
        t.Fatal(err)
    }
    firstJob:=<-w.jobs
    if firstJob.family!=privateP6USN||firstJob.rows[0].signedBatchIndex!=1 {
        t.Fatal("C1 lost signed USN boundary handoff")
    }
    ctx,cancel:=context.WithTimeout(context.Background(),2*time.Second)
    defer cancel()
    result:=make(chan error,1)
    go func(){result<-w.Family(ctx,privateP6USN,[]privateP6Record{next})}()
    select{
    case err:=<-result:
        t.Fatalf("C1 admitted later USN before boundary commit: %v",err)
    case <-time.After(30*time.Millisecond):
        // The second signed USN handoff must wait for first SQL commit.
    }
    if len(w.jobs)!=0{
        t.Fatal("C1 queued out-of-order USN transaction")
    }
    // Other families still use the full shared queue and do not require
    // the USN transaction's ACK.
    if err:=w.Family(ctx,privateP6Security,[]privateP6Record{
        privateP6Fixture(2,2,"WindowsSecurityEvent"),
    });err!=nil{
        t.Fatalf("C1 USN dependency stalled unrelated SQL family: %v",err)
    }
    if job:=<-w.jobs;job.family!=privateP6Security{
        t.Fatal("C1 blocked unrelated Security SQL by USN dependency")
    }
    firstJob.done<-nil // the first USN transaction has committed
    select{
    case err:=<-result:
        if err!=nil{t.Fatalf("C1 failed to admit next USN after ACK: %v",err)}
    case <-ctx.Done():
        t.Fatal("C1 deadlocked after USN SQL commit")
    }
    select{
    case secondJob:=<-w.jobs:
        if secondJob.family!=privateP6USN||
            secondJob.rows[0].signedBatchIndex!=2||
            w.lanes[privateP6USN].backpressureWaits!=1 {
            t.Fatal("C1 second USN handoff lost signed order or ACK barrier")
        }
    default:
        t.Fatal("C1 never dispatched second USN after first commit")
    }
}

func TestPrivateC1USNPrecedingSQLFailureStopsLaterHandoff(t *testing.T){
    parent:=&privateC1SourceAck{done:make(chan struct{})}
    close(parent.done)
    w:=&privateC1FiveSQL{ctx:context.Background(),sourceLast:parent,
        maxWorkers:16,workerCount:16,jobs:make(chan privateC1SQLJob,8)}
    w.lanes[privateP6USN]=&privateC1SQLLane{family:privateP6USN}
    if e:=w.Family(context.Background(),privateP6USN,[]privateP6Record{
        privateP6Fixture(1,1,"USNReadBoundary"),
    });e!=nil{t.Fatal(e)}
    original:=<-w.jobs
    original.done<-errors.New("injected USN capture transaction rolled back")
    e:=w.Family(context.Background(),privateP6USN,[]privateP6Record{
        privateP6Fixture(2,1,"USNObjectObservation"),
    })
    if e==nil||!strings.Contains(e.Error(),"rolled back"){
        t.Fatalf("C1 allowed object after failed capture: %v",e)
    }
    if len(w.jobs)!=0||len(w.lanes[privateP6USN].outstanding)!=0{
        t.Fatal("C1 leaked subsequent USN SQL after capture failure")
    }
}

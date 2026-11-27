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

func TestPrivateC1SecurityCOPYCallLatencyAggregatesAcrossConcurrentWorkers(t *testing.T){
    var first,second,combined copyCallLatency
    first.observe(250*time.Millisecond)
    first.observe(1500*time.Millisecond)
    second.observe(125*time.Millisecond)
    second.observe(6*time.Second)
    privateC1MergeCopyCallLatency(&combined,first)
    privateC1MergeCopyCallLatency(&combined,copyCallLatency{})
    privateC1MergeCopyCallLatency(&combined,second)
    if combined.Calls!=4 ||
       combined.Min!=125*time.Millisecond ||
       combined.Max!=6*time.Second ||
       combined.Total!=7875*time.Millisecond ||
       combined.AtLeastOneSecond!=2 ||
       combined.AtLeastFiveSeconds!=1 {
        t.Fatalf("Security field COPY call distribution lost worker measurements: %+v",combined)
    }
    // No calls must retain the empty baseline without fabricated min/max.
    var empty copyCallLatency
    privateC1MergeCopyCallLatency(&empty,copyCallLatency{})
    if empty.Calls!=0||empty.Min!=0||empty.Max!=0{
        t.Fatalf("Security COPY empty latency was mutated: %+v",empty)
    }
}

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
        maxWorkers:5,workerCount:5,jobs:make(chan privateC1SQLJob,5),
        usnPending:make(chan privateC1SQLJob,privateC1MaxPendingUSNHandoffs)}
    for f:=privateP6Family(0);f<privateP6FamilyCount;f++{
        w.lanes[f]=&privateC1SQLLane{family:f}
    }
    for f:=privateP6Family(0);f<privateP6FamilyCount;f++{
        if e:=w.Family(context.Background(),f,
            []privateP6Record{privateP6Fixture(int(f)+1,1,privateC1TestKind(f))});e!=nil{
            t.Fatal(e)
        }
    }
    // USN is the only family with an intermediate ORDERED admission queue.
    // Its eventual SQL executor is still one of the 1..32 shared workers.
    if len(w.jobs)!=4||len(w.usnPending)!=1{
        t.Fatalf("shared queue=%d, async USN queue=%d; expected 4 and 1",
            len(w.jobs),len(w.usnPending))
    }
    seen:=make(map[privateP6Family]bool)
    for i:=0;i<4;i++{
        job:=<-w.jobs
        if job.source!=parent||seen[job.family]||job.done!=w.lanes[job.family].outstanding[0]{
            t.Fatal("shared SQL worker job lost family/identity or duplicate ACK")
        }
        seen[job.family]=true
    }
    job:=<-w.usnPending
    if job.family!=privateP6USN||job.source!=parent||
       job.done!=w.lanes[privateP6USN].outstanding[0]||job.committed==nil{
        t.Fatal("USN was not admitted through the bounded ordered queue")
    }
    seen[job.family]=true
    if len(seen)!=5{t.Fatal("not all five families were admitted")}
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

 
// The original USN relational projector requires a preceding committed
// capture boundary and the associated NTFS/File identities. These tests
// exercise the asynchronous scheduler, not synthetic unordered USN SQL.
func privateC1AsyncUSNFixture(t *testing.T)(*privateC1FiveSQL,context.Context,func()){
    t.Helper()
    ctx,cancel:=context.WithCancel(context.Background())
    parent:=&privateC1SourceAck{done:make(chan struct{})}
    close(parent.done)
    w:=&privateC1FiveSQL{ctx:ctx,sourceLast:parent,
        maxWorkers:32,workerCount:32,jobs:make(chan privateC1SQLJob,16),
        usnPending:make(chan privateC1SQLJob,privateC1MaxPendingUSNHandoffs)}
    for f:=privateP6Family(0);f<privateP6FamilyCount;f++{
        w.lanes[f]=&privateC1SQLLane{family:f}
    }
    w.usnWG.Add(1)
    go w.runUSNDispatcher()
    cleanup:=func(){cancel();close(w.usnPending);w.usnWG.Wait()}
    return w,ctx,cleanup
}
func privateC1FinishMockSQLJob(j privateC1SQLJob,err error){
    j.committed.err=err
    close(j.committed.done)
    j.done<-err
    close(j.done)
}
func TestPrivateC1AsyncUSNDoesNotBlockOtherFamiliesAndPreservesSQLOrder(t *testing.T){
    w,ctx,cleanup:=privateC1AsyncUSNFixture(t)
    defer cleanup()
    if w.familyHandoffLimit(privateP6USN)!=privateC1MaxPendingUSNHandoffs{
        t.Fatal("USN still has its previous single-handoff admission limit")
    }
    // The preceding File job has been enqueued but has NOT committed.
    fileAck:=&privateC1SourceAck{done:make(chan struct{})}
    w.lanes[privateP6File].fileReceipts=[]*privateC1SourceAck{fileAck}
    for i:=1;i<=2;i++{
        if err:=w.Family(ctx,privateP6USN,[]privateP6Record{
            privateP6Fixture(i,1,"USNReadBoundary"),
        });err!=nil{t.Fatalf("USN admission %d blocked: %v",i,err)}
    }
    // Unrelated Security SQL must reach the worker queue now.
    if err:=w.Family(ctx,privateP6Security,[]privateP6Record{
        privateP6Fixture(3,1,"WindowsSecurityEvent"),
    });err!=nil{t.Fatal(err)}
    job:=<-w.jobs
    if job.family!=privateP6Security{
        t.Fatal("USN File dependency blocked independent Security family")
    }
    select{
    case job:=<-w.jobs:
        t.Fatalf("USN SQL began before File prerequisite committed: %v",job.family)
    case <-time.After(20*time.Millisecond):
    }
    close(fileAck.done)
    var first privateC1SQLJob
    select{
    case first=<-w.jobs:
        if first.family!=privateP6USN||first.rows[0].signedBatchIndex!=1 {
            t.Fatal("first USN job did not preserve source order")
        }
    case <-time.After(time.Second):
        t.Fatal("File ACK failed to release first USN job")
    }
    select{
    case j:=<-w.jobs:
        t.Fatalf("next USN SQL started before earlier COMMIT: %v",j.family)
    case <-time.After(20*time.Millisecond):
    }
    privateC1FinishMockSQLJob(first,nil)
    var second privateC1SQLJob
    select{
    case second=<-w.jobs:
        if second.family!=privateP6USN||second.rows[0].signedBatchIndex!=2{
            t.Fatal("USN SQL execution reordered after first commit")
        }
    case <-time.After(time.Second):
        t.Fatal("USN dispatcher failed to release following committed job")
    }
    privateC1FinishMockSQLJob(second,nil)
    if err:=w.WaitFamily(ctx,privateP6USN);err!=nil{t.Fatal(err)}
    if w.lanes[privateP6USN].backpressureWaits!=0{
        t.Fatal("asynchronous USN admission incorrectly waited on each SQL ACK")
    }
}
func TestPrivateC1AsyncUSNWaitsEveryPriorFileCommit(t *testing.T){
    w,ctx,cleanup:=privateC1AsyncUSNFixture(t)
    defer cleanup()
    firstFile:=&privateC1SourceAck{done:make(chan struct{})}
    secondFile:=&privateC1SourceAck{done:make(chan struct{})}
    w.lanes[privateP6File].fileReceipts=[]*privateC1SourceAck{
        firstFile,secondFile,
    }
    if err:=w.Family(ctx,privateP6USN,[]privateP6Record{
        privateP6Fixture(1,1,"USNReadBoundary"),
    });err!=nil{t.Fatal(err)}
    close(firstFile.done)
    select{
    case j:=<-w.jobs:
        t.Fatalf("USN started before the second earlier File commit: %v",j.family)
    case <-time.After(20*time.Millisecond):
    }
    close(secondFile.done)
    select{
    case j:=<-w.jobs:
        if j.family!=privateP6USN{t.Fatal("USN dispatcher lost family")}
        privateC1FinishMockSQLJob(j,nil)
    case <-time.After(time.Second):
        t.Fatal("USN remained blocked after all File commits completed")
    }
    if err:=w.WaitFamily(ctx,privateP6USN);err!=nil{t.Fatal(err)}
}
func TestPrivateC1AsyncUSNQueueIsBounded(t *testing.T){
    w,ctx,cleanup:=privateC1AsyncUSNFixture(t)
    defer cleanup()
    for i:=0;i<privateC1MaxPendingUSNHandoffs;i++{
        if err:=w.Family(ctx,privateP6USN,[]privateP6Record{
            privateP6Fixture(i+1,1,"USNReadBoundary"),
        });err!=nil{t.Fatal(err)}
    }
    first:=<-w.jobs
    if first.family!=privateP6USN{t.Fatal("USN queue lost first signed job")}
    result:=make(chan error,1)
    go func(){
        result<-w.Family(ctx,privateP6USN,[]privateP6Record{
            privateP6Fixture(999,1,"USNObjectObservation"),
        })
    }()
    select{
    case e:=<-result:
        t.Fatalf("USN admitted beyond bounded queue without ACK: %v",e)
    case <-time.After(25*time.Millisecond):
    }
    privateC1FinishMockSQLJob(first,nil)
    select{
    case err:=<-result:
        if err!=nil{t.Fatal(err)}
    case <-time.After(time.Second):
        t.Fatal("USN failed to resume bounded admission after first SQL ACK")
    }
    if w.usnPeakOutstanding>privateC1MaxPendingUSNHandoffs{
        t.Fatal("USN exceeded bounded backlog")
    }
    // The fixture's cancellation prevents stranded mock worker jobs in cleanup.
}
func TestPrivateC1AsyncUSNFileFailureFailsClosed(t *testing.T){
    w,ctx,cleanup:=privateC1AsyncUSNFixture(t)
    defer cleanup()
    fileAck:=&privateC1SourceAck{done:make(chan struct{})}
    w.lanes[privateP6File].fileReceipts=[]*privateC1SourceAck{fileAck}
    if err:=w.Family(ctx,privateP6USN,[]privateP6Record{
        privateP6Fixture(1,1,"USNReadBoundary"),
    });err!=nil{t.Fatal(err)}
    fileAck.err=errors.New("injected File transaction failed")
    close(fileAck.done)
    if err:=w.WaitFamily(ctx,privateP6USN);err==nil||
       !strings.Contains(err.Error(),"injected File transaction failed"){
        t.Fatalf("C1 allowed USN without its committed File prerequisites: %v",err)
    }
    if len(w.jobs)!=0||w.failed==nil{
        t.Fatal("failed File commit allowed USN SQL or successful generation")
    }
}
func TestPrivateC1AsyncUSNPreviousSQLFailureFailsClosed(t *testing.T){
    w,ctx,cleanup:=privateC1AsyncUSNFixture(t)
    defer cleanup()
    for i:=1;i<=2;i++{
        if err:=w.Family(ctx,privateP6USN,[]privateP6Record{
            privateP6Fixture(i,1,"USNReadBoundary"),
        });err!=nil{t.Fatal(err)}
    }
    first:=<-w.jobs
    failure:=errors.New("injected USN capture transaction rolled back")
    privateC1FinishMockSQLJob(first,failure)
    if err:=w.WaitFamily(ctx,privateP6USN);err==nil||
       !strings.Contains(err.Error(),"rolled back"){
        t.Fatalf("C1 failed to stop on USN SQL commit error: %v",err)
    }
    // After cancellation/dispatcher failure, no later USN SQL is submitted.
    if len(w.jobs)!=0{t.Fatal("later USN escaped after failed SQL commit")}
}

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
package recordingest

import (
    "bufio"
    "bytes"
    "context"
    "crypto/sha256"
    "errors"
    "fmt"
    "testing"
    "time"
)

func privateP5TestMode(t *testing.T){
    t.Helper()
    t.Setenv("FI_W512_P5_PERSISTENT","1")
    t.Setenv("FI_W512_P3_DYNAMIC_MIN","2")
    t.Setenv("FI_W512_P3_DYNAMIC_MAX","32")
    t.Setenv("FI_W512_P3_SECURITY_WORKERS","")
    t.Setenv("FI_W512_P3_GENERAL_WORKERS","")
}

func privateP5TestPrepare(raw []byte,kind string,f spoolDispatchFamily)(
    SourceRecord,securityBulkRecord,bool,error,
){
    k,observed,err:=classifyCanonicalSpoolRecord(raw)
    if err!=nil||k!=kind||f!=observed{
        return SourceRecord{},securityBulkRecord{},false,
            errors.New("FI P5 test: source identity or dispatch family changed")
    }
    return SourceRecord{RecordDigest:sha256.Sum256(raw)},securityBulkRecord{},false,nil
}

func TestPrivateP5RequiresWindowPool(t *testing.T){
    privateP5TestMode(t)
    s,err:=newPrivateFamilyP3PreparedStream(context.Background(),
        bufio.NewReader(bytes.NewReader(canonicalDispatchFixture("WindowsSecurityEvent","{}"))),
        privateP5TestPrepare)
    if err==nil {s.Close();t.Fatal("P5 without explicit typed-window pool was accepted")}
}

func TestPrivateP5ReuseAllFiveLanesAcrossSignedBatches(t *testing.T){
    privateP5TestMode(t)
    pool,err:=newPrivateP5Pool(context.Background(),1)
    if err!=nil{t.Fatal(err)}
    defer pool.Close()
    ctx:=context.WithValue(context.Background(),privateP5PoolContextKey{},pool)
    kinds:=[]string{"WindowsSecurityEvent","FileObservation",
        "WindowsSecurityCoverage","USNReadBoundary","CollectorIdentity"}
    var batches int
    var all int
    for batch:=0;batch<8;batch++{
        var data []byte
        var expect [][]byte
        for i:=0;i<110;i++{
            kind:=kinds[i%len(kinds)]
            raw:=canonicalDispatchFixture(kind,fmt.Sprintf("{\"batch\":%d,\"i\":%d}",batch,i))
            data=append(data,raw...)
            expect=append(expect,raw)
        }
        s,err:=newPrivateFamilyP3PreparedStream(ctx,bufio.NewReader(bytes.NewReader(data)),
            privateP5TestPrepare)
        if err!=nil{t.Fatal(err)}
        for i:=0;i<len(expect);i++{
            line,ok:=s.Next()
            if !ok||line.readErr!=nil||line.prepareErr!=nil||
                line.ordinal!=int64(i+1)||!bytes.Equal(line.raw,expect[i])||
                line.source.RecordDigest!=sha256.Sum256(expect[i]){
                t.Fatalf("batch=%d ordinal=%d: signed identity mismatch",batch,i)
            }
        }
        if _,ok:=s.Next();ok{t.Fatalf("batch=%d: extra source row",batch)}
        s.Close()
        if !s.privateSweepComplete||s.privateFamilyP3Telemetry.InputRecords!=110{
            t.Fatalf("batch=%d incomplete session",batch)
        }
        var prepared uint64
        for _,lane:=range s.privateFamilyP3Telemetry.Lanes {
            for _,worker:=range lane.WorkersStats {prepared+=worker.Records}
        }
        if prepared!=110{t.Fatalf("batch=%d prepared=%d",batch,prepared)}
        used,peak:=s.privateFamilyBudget.stats()
        if used!=0||peak>privateFamilyP3Bytes{t.Fatalf("batch=%d admitted bytes used=%d peak=%d",batch,used,peak)}
        batches++
        all+=int(prepared)
    }
    if batches!=8||all!=880{t.Fatalf("batch count=%d rows=%d",batches,all)}
    for i:=range pool.lanes {
        if n:=pool.lanes[i].spawned();n<2||n>32 {
            t.Fatalf("family %d spawned workers=%d",i,n)
        }
    }
}

// The five P5 lanes remain independently adaptive. A blocked Security
// preparation burst must be able to occupy all 32 configured slots while
// idle families remain at their two-worker floor.
func TestPrivateP5AdaptiveSecurityScalesToThirtyTwo(t *testing.T){
    privateP5TestMode(t)
    pool,err:=newPrivateP5Pool(context.Background(),1)
    if err!=nil{t.Fatal(err)}
    defer pool.Close()
    for i,lane:=range pool.lanes{
        if len(lane.jobs)!=32||len(lane.busy)!=32||cap(lane.done)!=32{
            t.Fatalf("family %d was not allocated 32 independent adaptive slots",i)
        }
        if got:=lane.spawned();got!=2{
            t.Fatalf("family %d floor workers=%d, expected 2",i,got)
        }
    }
    gate:=make(chan struct{})
    released:=false
    defer func(){if !released{close(gate)}}()
    ctx:=context.WithValue(context.Background(),privateP5PoolContextKey{},pool)
    data:=bytes.Repeat(canonicalDispatchFixture("WindowsSecurityEvent","{}"),48)
    prep:=func(raw []byte,kind string,f spoolDispatchFamily)(
        SourceRecord,securityBulkRecord,bool,error,
    ){
        <-gate
        return privateP5TestPrepare(raw,kind,f)
    }
    stream,err:=newPrivateFamilyP3PreparedStream(ctx,
        bufio.NewReader(bytes.NewReader(data)),prep)
    if err!=nil{t.Fatal(err)}
    deadline:=time.After(10*time.Second)
    for pool.lanes[spoolDispatchSecurity].spawned()<32{
        select{
        case <-deadline:
            t.Fatal("P5 Security failed to scale adaptively to 32 busy preparation workers")
        case <-time.After(5*time.Millisecond):
        }
    }
    close(gate)
    released=true
    for i:=0;i<48;i++{
        row,ok:=stream.Next()
        if !ok||row.readErr!=nil||row.prepareErr!=nil||row.ordinal!=int64(i+1){
            t.Fatalf("P5 source order lost at record %d",i+1)
        }
    }
    if _,ok:=stream.Next();ok{t.Fatal("extra prepared Security record")}
    stream.Close()
    for i,lane:=range pool.lanes{
        want:=2
        if i==int(spoolDispatchSecurity){want=32}
        if got:=lane.spawned();got!=want{
            t.Fatalf("P5 family %d spawned=%d expected=%d",i,got,want)
        }
    }
}

func TestPrivateP5PoolPersistsWorkersWithoutRecreatingMinimum(t *testing.T){
    privateP5TestMode(t)
    pool,err:=newPrivateP5Pool(context.Background(),2)
    if err!=nil{t.Fatal(err)}
    defer pool.Close()
    ctx:=context.WithValue(context.Background(),privateP5PoolContextKey{},pool)
    for batch:=0;batch<3;batch++{
        s,err:=newPrivateFamilyP3PreparedStream(ctx,
            bufio.NewReader(bytes.NewReader(canonicalDispatchFixture(
                "WindowsSecurityEvent",fmt.Sprintf("{\"batch\":%d}",batch)))),
            privateP5TestPrepare)
        if err!=nil{t.Fatal(err)}
        row,ok:=s.Next()
        if !ok||row.prepareErr!=nil||row.ordinal!=1{t.Fatalf("batch %d: no record",batch)}
        if _,ok:=s.Next();ok{t.Fatal("unexpected extra record")}
        s.Close()
    }
    // A batch reset would create at least 3x2 minimum workers per family;
    // P5 keeps its pool and its five original lane coordinators alive.
    for i:=range pool.lanes {
        if n:=pool.lanes[i].spawned();n!=2 {
            t.Fatalf("family %d unnecessarily recreated minimum workers: %d",i,n)
        }
    }
}

func TestPrivateP5CanceledSessionDoesNotPoisonNextBatch(t *testing.T){
    privateP5TestMode(t)
    pool,err:=newPrivateP5Pool(context.Background(),3)
    if err!=nil{t.Fatal(err)}
    defer pool.Close()
    ctx:=context.WithValue(context.Background(),privateP5PoolContextKey{},pool)
    first:=bytes.Repeat(canonicalDispatchFixture("WindowsSecurityEvent","{}"),40)
    s,err:=newPrivateFamilyP3PreparedStream(ctx,bufio.NewReader(bytes.NewReader(first)),
        privateP5TestPrepare)
    if err!=nil{t.Fatal(err)}
    _,_=s.Next()
    closed:=make(chan struct{})
    go func(){s.Close();close(closed)}()
    select{
    case <-closed:
    case <-time.After(5*time.Second):t.Fatal("canceled session stranded shared worker tasks")
    }
    second:=canonicalDispatchFixture("FileObservation","{}")
    next,err:=newPrivateFamilyP3PreparedStream(ctx,bufio.NewReader(bytes.NewReader(second)),
        privateP5TestPrepare)
    if err!=nil{t.Fatal(err)}
    defer next.Close()
    row,ok:=next.Next()
    if !ok||row.ordinal!=1||row.prepareErr!=nil||!bytes.Equal(row.raw,second){
        t.Fatal("second signed batch corrupted after first session cancellation")
    }
    if _,ok:=next.Next();ok{t.Fatal("extra second batch row")}
}

func TestPrivateP5RejectsInvalidWindowConfig(t *testing.T){
    t.Setenv("FI_W512_P5_PERSISTENT","1")
    t.Setenv("FI_W512_P3_DYNAMIC_MIN","2")
    t.Setenv("FI_W512_P3_DYNAMIC_MAX","32")
    t.Setenv("FI_W512_P3_SECURITY_WORKERS","8")
    t.Setenv("FI_W512_P3_GENERAL_WORKERS","")
    if _,err:=newPrivateP5Pool(context.Background(),1);err==nil {
        t.Fatal("mixed fixed/dynamic configuration accepted")
    }
}

func TestPrivateP5CanceledWindowContextDrainsWithoutStranding(t *testing.T){
    privateP5TestMode(t)
    windowCtx,cancel:=context.WithCancel(context.Background())
    pool,err:=newPrivateP5Pool(windowCtx,4)
    if err!=nil{t.Fatal(err)}
    defer pool.Close()
    ctx:=context.WithValue(windowCtx,privateP5PoolContextKey{},pool)
    input:=bytes.Repeat(canonicalDispatchFixture("WindowsSecurityEvent","{}"),100)
    stream,err:=newPrivateFamilyP3PreparedStream(ctx,
        bufio.NewReader(bytes.NewReader(input)),privateP5TestPrepare)
    if err!=nil{t.Fatal(err)}
    // Failure occurs before all 100 source records can pass the 32-credit
    // admission controller. The pool must still drain accepted tasks.
    cancel()
    closed:=make(chan struct{})
    go func(){stream.Close();close(closed)}()
    select{
    case <-closed:
    case <-time.After(5*time.Second):
        t.Fatal("canceled W512 context left signed batch tasks in persistent pool")
    }
}

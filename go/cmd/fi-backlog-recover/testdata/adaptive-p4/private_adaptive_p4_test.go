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
    "sync"
    "testing"
    "time"
)

func privateAdaptiveP4TestPrepare(raw []byte,kind string,f spoolDispatchFamily)(
    SourceRecord,securityBulkRecord,bool,error,
) {
    actual,kindFamily,err:=classifyCanonicalSpoolRecord(raw)
    if err!=nil||actual!=kind||kindFamily!=f{
        return SourceRecord{},securityBulkRecord{},false,errors.New("FI P4: signed family identity changed")
    }
    return SourceRecord{RecordDigest:sha256.Sum256(raw)},securityBulkRecord{},false,nil
}

func TestPrivateAdaptiveP4PrioritySelection(t *testing.T){
    idle:=[]bool{true,true,true,true}
    if x:=privateAdaptiveP4LowestIdle(idle,4);x!=0{t.Fatalf("first idle=%d",x)}
    idle[0]=false
    if x:=privateAdaptiveP4LowestIdle(idle,4);x!=1{t.Fatalf("second idle=%d",x)}
    idle[1]=false
    if x:=privateAdaptiveP4LowestIdle(idle,4);x!=2{t.Fatalf("third idle=%d",x)}
    for i:=range idle {idle[i]=false}
    if x:=privateAdaptiveP4LowestIdle(idle,4);x!=-1{t.Fatalf("none idle=%d",x)}
}

func TestPrivateAdaptiveP4NoBatchFillDelayAndAllFamilies(t *testing.T){
    kinds:=[]string{"WindowsSecurityEvent","FileObservation",
        "WindowsSecurityCoverage","USNReadBoundary","CollectorIdentity"}
    var raw []byte
    originals:=make([][]byte,len(kinds))
    for i,kind:=range kinds{
        originals[i]=canonicalDispatchFixture(kind,fmt.Sprintf("{\"seq\":%d}",i))
        raw=append(raw,originals[i]...)
    }
    ctx,cancel:=context.WithCancel(context.Background())
    defer cancel()
    stream,err:=newPrivateAdaptiveP4PreparedStream(ctx,bufio.NewReader(
        bytes.NewReader(raw)),privateAdaptiveP4TestPrepare)
    if err!=nil{t.Fatal(err)}
    defer stream.Close()
    received:=make(chan []privateParallelLine,1)
    go func(){
        out:=make([]privateParallelLine,0,len(kinds))
        for range kinds {
            line,ok:=stream.Next()
            if !ok {break}
            out=append(out,line)
        }
        received<-out
    }()
    var out []privateParallelLine
    select{
    case out=<-received:
    case <-time.After(3*time.Second):
        t.Fatal("FI P4 withheld ready records waiting for an elevator/batch to fill")
    }
    if len(out)!=len(kinds){t.Fatalf("received=%d want=%d",len(out),len(kinds))}
    for i,line:=range out{
        if line.ordinal!=int64(i+1)||line.readErr!=nil||line.prepareErr!=nil||
            !bytes.Equal(line.raw,originals[i])||
            line.source.RecordDigest!=sha256.Sum256(originals[i]){
            t.Fatalf("record %d signed bytes/digest/order mismatch %+v",i,line)
        }
    }
    if _,ok:=stream.Next();ok{t.Fatal("received extra signed record")}
    stream.Close()
    if !stream.privateSweepComplete {t.Fatal("complete finite signed source was not marked")}
    if cap(stream.credits)!=32 {t.Fatalf("inflight credits=%d",cap(stream.credits))}
    if stream.privateFamilyP3Telemetry.InputRecords!=5 {t.Fatal("wrong signed input count")}
    for f:=range stream.privateAdaptiveP4Telemetry.Lanes{
        lane:=stream.privateAdaptiveP4Telemetry.Lanes[f]
        if lane.PeakActive!=2 || lane.Activations!=2 {
            t.Fatalf("family %d idle floor %+v",f,lane)
        }
        if stream.privateFamilyP3Telemetry.Lanes[f].DispatchCount!=1 {
            t.Fatalf("family %d missing prepared signed record",f)
        }
    }
    used,peak:=stream.privateFamilyBudget.stats()
    if used!=0||peak>privateFamilyP3Bytes{t.Fatalf("raw admission used=%d peak=%d",used,peak)}
}

func TestPrivateAdaptiveP4SecurityBurstScalesToSixteen(t *testing.T){
    const n=96
    release:=make(chan struct{})
    starts:=make(chan struct{},32)
    var once sync.Once
    unblock:=func(){once.Do(func(){close(release)})}
    defer unblock()
    var input []byte
    originals:=make([][]byte,n)
    for i:=0;i<n;i++{
        originals[i]=canonicalDispatchFixture("WindowsSecurityEvent",fmt.Sprintf("{\"seq\":%d}",i))
        input=append(input,originals[i]...)
    }
    prepare:=func(raw []byte,kind string,f spoolDispatchFamily)(
        SourceRecord,securityBulkRecord,bool,error,
    ){
        starts<-struct{}{}
        <-release
        return privateAdaptiveP4TestPrepare(raw,kind,f)
    }
    stream,err:=newPrivateAdaptiveP4PreparedStream(context.Background(),
        bufio.NewReader(bytes.NewReader(input)),prepare)
    if err!=nil{t.Fatal(err)}
    defer stream.Close()
    for i:=0;i<16;i++{
        select{
        case <-starts:
        case <-time.After(3*time.Second):
            unblock()
            t.Fatalf("only %d of 16 Security workers activated under backlog",i)
        }
    }
    unblock()
    for i:=0;i<n;i++{
        line,ok:=stream.Next()
        if !ok||line.readErr!=nil||line.prepareErr!=nil||
            line.ordinal!=int64(i+1)||!bytes.Equal(line.raw,originals[i]){
            t.Fatalf("Security row %d reordering or corruption %+v",i,line)
        }
    }
    if _,ok:=stream.Next();ok{t.Fatal("extra Security result")}
    stream.Close()
    family:=&stream.privateAdaptiveP4Telemetry.Lanes[spoolDispatchSecurity]
    if family.PeakActive!=16 || family.Activations<16{
        t.Fatalf("Security backlog did not activate max worker count %+v",family)
    }
    var nPrepared uint64
    for _,stat:=range stream.privateFamilyP3Telemetry.Lanes[spoolDispatchSecurity].WorkersStats{
        nPrepared+=stat.Records
    }
    if nPrepared!=n {t.Fatalf("Security prepared=%d want %d",nPrepared,n)}
    used,_:=stream.privateFamilyBudget.stats()
    if used!=0{t.Fatalf("signed record admission not released: %d",used)}
}

func TestPrivateAdaptiveP4IdleRetiresOverflowButKeepsTwo(t *testing.T){
    ctx,cancel:=context.WithCancel(context.Background())
    defer cancel()
    input:=make(chan privateParallelLine,32)
    output:=make(chan privateParallelLine,32)
    entered:=make(chan struct{},16)
    release:=make(chan struct{})
    var once sync.Once
    unblock:=func(){once.Do(func(){close(release)})}
    defer unblock()
    prep:=func(raw []byte,kind string,f spoolDispatchFamily)(
        SourceRecord,securityBulkRecord,bool,error,
    ){
        entered<-struct{}{}
        <-release
        return SourceRecord{},securityBulkRecord{},false,nil
    }
    fixed:=&privateFamilyP3Telemetry{}
    family:=spoolDispatchSecurity
    fixed.Lanes[family].WorkersStats=make([]privateFamilyP3WorkerStat,16)
    adaptive:=&privateAdaptiveP4Telemetry{}
    var wg sync.WaitGroup
    wg.Add(1)
    go func(){
        defer wg.Done()
        privateAdaptiveP4RunLane(ctx,family,input,output,prep,&wg,fixed,adaptive)
    }()
    for i:=0;i<8;i++{input<-privateParallelLine{ordinal:int64(i+1),raw:[]byte("a")}}
    for i:=0;i<8;i++{
        select{
        case <-entered:
        case <-time.After(3*time.Second):unblock();t.Fatalf("only %d/8 workers activated",i)
        }
    }
    unblock()
    for i:=0;i<8;i++{
        select{
        case <-output:
        case <-time.After(3*time.Second):t.Fatal("pending source row not released")
        }
    }
    time.Sleep(350*time.Millisecond)
    input<-privateParallelLine{ordinal:9,raw:[]byte("a")}
    close(input)
    select{
    case <-output:
    case <-time.After(3*time.Second):t.Fatal("post-retirement row not processed")
    }
    done:=make(chan struct{})
    go func(){wg.Wait();close(done)}()
    select{
    case <-done:
    case <-time.After(3*time.Second):t.Fatal("worker shutdown stranded")
    }
    metrics:=adaptive.Lanes[family]
    if metrics.PeakActive<8||metrics.Retirements<6{
        t.Fatalf("workers did not scale back to floor of two %+v",metrics)
    }
    var prepared uint64
    for _,stat:=range fixed.Lanes[family].WorkersStats {prepared+=stat.Records}
    if prepared!=9 {t.Fatalf("worker accounting rows=%d",prepared)}
}

func TestPrivateAdaptiveP4CancelJoinsWithoutPublishingCompletion(t *testing.T){
    rows:=bytes.Repeat(canonicalDispatchFixture("WindowsSecurityEvent","{}"),5000)
    ctx,cancel:=context.WithCancel(context.Background())
    stream,err:=newPrivateAdaptiveP4PreparedStream(ctx,
        bufio.NewReader(bytes.NewReader(rows)),privateAdaptiveP4TestPrepare)
    if err!=nil{t.Fatal(err)}
    if _,ok:=stream.Next();!ok{t.Fatal("first record missing")}
    cancel()
    done:=make(chan struct{})
    go func(){stream.Close();close(done)}()
    select{
    case <-done:
    case <-time.After(3*time.Second):t.Fatal("cancelled worker pool did not join")
    }
    if stream.privateSweepComplete{
        t.Fatal("cancelled signed replay published false completion")
    }
}

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

func privateDynamicTestMode(t *testing.T) {
    t.Helper()
    t.Setenv("FI_W512_P3_DYNAMIC_MIN","2")
    t.Setenv("FI_W512_P3_DYNAMIC_MAX","16")
    t.Setenv("FI_W512_P3_SECURITY_WORKERS","")
    t.Setenv("FI_W512_P3_GENERAL_WORKERS","")
}

func privateDynamicTestPreparer(raw []byte,kind string,f spoolDispatchFamily)(
    SourceRecord,securityBulkRecord,bool,error,
){
    k,got,err:=classifyCanonicalSpoolRecord(raw)
    if err!=nil || k!=kind || got!=f {
        return SourceRecord{},securityBulkRecord{},false,errors.New("FI dynamic test: signed kind/family mismatch")
    }
    return SourceRecord{RecordDigest:sha256.Sum256(raw)},securityBulkRecord{},false,nil
}

func TestPrivateDynamicP4RejectsPartialOrFixedTopology(t *testing.T){
    configs:=[]struct{ min,max,security,general string }{
        {"","16","",""},{"2","","",""},{"1","16","",""},
        {"3","16","",""},{"2","17","",""},{"2","8","",""},
        {"2","16","8",""},{"2","16","","8"},{"2","16","8","16"},
    }
    for i,c:=range configs{
        t.Run(fmt.Sprintf("invalid_%d",i),func(t *testing.T){
            t.Setenv("FI_W512_P3_DYNAMIC_MIN",c.min)
            t.Setenv("FI_W512_P3_DYNAMIC_MAX",c.max)
            t.Setenv("FI_W512_P3_SECURITY_WORKERS",c.security)
            t.Setenv("FI_W512_P3_GENERAL_WORKERS",c.general)
            stream,err:=newPrivateFamilyP3PreparedStream(context.Background(),
                bufio.NewReader(bytes.NewReader(canonicalDispatchFixture("WindowsSecurityEvent","{}"))),
                privateDynamicTestPreparer)
            if err==nil{stream.Close();t.Fatal("invalid dynamic topology accepted")}
        })
    }
}

func TestPrivateDynamicP4NoFullBufferWaitAndSignedOrdering(t *testing.T){
    privateDynamicTestMode(t)
    kinds:=[]string{"WindowsSecurityEvent","FileObservation",
        "WindowsSecurityCoverage","USNReadBoundary","CollectorIdentity"}
    const n=1250
    var input []byte
    expected:=make([][]byte,n)
    for i:=0;i<n;i++{
        expected[i]=canonicalDispatchFixture(kinds[i%len(kinds)],
            fmt.Sprintf("{\"seq\":%d}",i))
        input=append(input,expected[i]...)
    }
    s,err:=newPrivateFamilyP3PreparedStream(context.Background(),
        bufio.NewReader(bytes.NewReader(input)),privateDynamicTestPreparer)
    if err!=nil{t.Fatal(err)}
    defer s.Close()
    if cap(s.credits)!=32 || s.privateFamilyP3Telemetry==nil ||
        !s.privateFamilyP3Telemetry.Topology.Dynamic {
        t.Fatal("dynamic scheduler or global 32-credit limit not activated")
    }
    seenHash:=sha256.New()
    for i:=0;i<n;i++{
        item,ok:=s.Next()
        if !ok || item.prepareErr!=nil || item.readErr!=nil ||
            item.ordinal!=int64(i+1) || !bytes.Equal(item.raw,expected[i]) ||
            item.source.RecordDigest!=sha256.Sum256(expected[i]){
            t.Fatalf("signed source/order mismatch record=%d ok=%t error=%v",i,ok,item.prepareErr)
        }
        _,_=seenHash.Write(item.raw)
    }
    if _,ok:=s.Next();ok{t.Fatal("extra record")}
    s.Close()
    digest:=sha256.Sum256(input)
    if !bytes.Equal(digest[:],seenHash.Sum(nil)){t.Fatal("signed hash changed")}
    m:=s.privateFamilyP3Telemetry
    var prepared uint64
    for i:=range m.Lanes{
        lane:=m.Lanes[i]
        var lanePrepared uint64
        for _,worker:=range lane.WorkersStats{lanePrepared+=worker.Records}
        prepared+=lanePrepared
        if lanePrepared!=lane.DispatchCount || lane.DynamicAssigned!=int64(lane.DispatchCount) ||
            lane.DynamicSpawned<2 || lane.DynamicSpawned>16 ||
            lane.DynamicPeakBusy>lane.DynamicSpawned {
            t.Fatalf("family=%d lane statistics invalid: %+v",i,lane)
        }
    }
    if prepared!=n{t.Fatalf("prepared=%d want=%d",prepared,n)}
    used,peak:=s.privateFamilyBudget.stats()
    if used!=0 || peak>privateFamilyP3Bytes{t.Fatalf("budget used=%d peak=%d",used,peak)}
}

func TestPrivateDynamicP4SecurityOverflowAndIndependentFile(t *testing.T){
    privateDynamicTestMode(t)
    const secRecords=20
    var input []byte
    for i:=0;i<secRecords;i++{
        input=append(input,canonicalDispatchFixture("WindowsSecurityEvent",
            fmt.Sprintf("{\"i\":%d}",i))...)
    }
    input=append(input,canonicalDispatchFixture("FileObservation","{}")...)
    var once sync.Once
    unblock:=make(chan struct{})
    started:=make(chan struct{},secRecords)
    filePrepared:=make(chan struct{},1)
    prepare:=func(raw []byte,kind string,f spoolDispatchFamily)(
        SourceRecord,securityBulkRecord,bool,error,
    ){
        if f==spoolDispatchSecurity{
            started<-struct{}{}
            <-unblock
        }
        if f==spoolDispatchFile{
            filePrepared<-struct{}{}
        }
        return privateDynamicTestPreparer(raw,kind,f)
    }
    s,err:=newPrivateFamilyP3PreparedStream(context.Background(),
        bufio.NewReader(bytes.NewReader(input)),prepare)
    if err!=nil{t.Fatal(err)}
    defer func(){once.Do(func(){close(unblock)});s.Close()}()
    // The signed reader can admit 21 records (within 32 credits) while
    // output ordinals remain blocked. Security must activate >2 workers.
    for i:=0;i<8;i++{
        select{
        case <-started:
        case <-time.After(3*time.Second):
            once.Do(func(){close(unblock)})
            t.Fatalf("priority-fill failed to activate overflow worker %d",i+1)
        }
    }
    select{
    case <-filePrepared:
    case <-time.After(3*time.Second):
        once.Do(func(){close(unblock)})
        t.Fatal("File was blocked behind Security; family scheduling not independent")
    }
    once.Do(func(){close(unblock)})
    for i:=1;i<=secRecords+1;i++{
        row,ok:=s.Next()
        if !ok || row.ordinal!=int64(i) || row.prepareErr!=nil || row.readErr!=nil {
            t.Fatalf("wrong ordered row %d: %+v",i,row)
        }
    }
    if _,ok:=s.Next();ok {t.Fatal("extra source")}
    s.Close()
    m:=s.privateFamilyP3Telemetry
    if m.Lanes[spoolDispatchSecurity].DynamicSpawned<=2 ||
        m.Lanes[spoolDispatchSecurity].DynamicSpawned>16 ||
        m.Lanes[spoolDispatchFile].DispatchCount!=1 {
        t.Fatalf("scale out not observed, Security=%+v File=%+v",
            m.Lanes[spoolDispatchSecurity],m.Lanes[spoolDispatchFile])
    }
}

func TestPrivateDynamicP4CancellationJoinsAllWorkers(t *testing.T){
    privateDynamicTestMode(t)
    ctx,cancel:=context.WithCancel(context.Background())
    raw:=canonicalDispatchFixture("WindowsSecurityEvent","{}")
    s,err:=newPrivateFamilyP3PreparedStream(ctx,
        bufio.NewReader(bytes.NewReader(bytes.Repeat(raw,100))),
        privateDynamicTestPreparer)
    if err!=nil{t.Fatal(err)}
    _,_=s.Next()
    cancel()
    finished:=make(chan struct{})
    go func(){s.Close();close(finished)}()
    select{
    case <-finished:
    case <-time.After(3*time.Second):
        t.Fatal("dynamic priority-fill coordinator/worker stranded on cancellation")
    }
}

func TestPrivateDynamicP4SingleRecordDoesNotWaitToFill(t *testing.T){
    privateDynamicTestMode(t)
    one:=canonicalDispatchFixture("FileObservation","{}")
    s,err:=newPrivateFamilyP3PreparedStream(context.Background(),
        bufio.NewReader(bytes.NewReader(one)),privateDynamicTestPreparer)
    if err!=nil{t.Fatal(err)}
    defer s.Close()
    finished:=make(chan struct{})
    go func(){
        defer close(finished)
        row,ok:=s.Next()
        if !ok || row.ordinal!=1 {return}
        _,_=s.Next()
    }()
    select{
    case <-finished:
    case <-time.After(3*time.Second):
        t.Fatal("single ready record waited for family batch to fill")
    }
}

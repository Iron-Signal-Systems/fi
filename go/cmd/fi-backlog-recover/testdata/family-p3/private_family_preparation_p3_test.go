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

func TestPrivateFamilyP3ExactSignedBytesAndOrder(t *testing.T) {
    kinds:=[]string{"WindowsSecurityEvent","FileObservation","WindowsSecurityCoverage",
        "USNReadBoundary","USNObjectObservation","CollectorIdentity",
        "WindowsSecurityContinuityGap","USNContinuityGap"}
    const n=1600
    var input []byte
    originals:=make([][]byte,n)
    for i:=0;i<n;i++{
        originals[i]=canonicalDispatchFixture(kinds[i%len(kinds)],fmt.Sprintf("{\"i\":%d}",i))
        input=append(input,originals[i]...)
    }
    prepare:=func(raw []byte,kind string,f spoolDispatchFamily)(SourceRecord,securityBulkRecord,bool,error){
        actual,af,err:=classifyCanonicalSpoolRecord(raw)
        if err!=nil || actual!=kind || af!=f {return SourceRecord{},securityBulkRecord{},false,errors.New("family identity mismatch")}
        return SourceRecord{RecordDigest:sha256.Sum256(raw)},securityBulkRecord{},false,nil
    }
    stream,err:=newPrivateFamilyP3PreparedStream(context.Background(),
        bufio.NewReader(bytes.NewReader(input)),prepare)
    if err!=nil{t.Fatal(err)}
    defer stream.Close()
    h:=sha256.New()
    for i:=0;i<n;i++{
        line,ok:=stream.Next()
        if !ok || line.readErr!=nil || line.prepareErr!=nil {t.Fatalf("record %d: %+v ok=%t",i,line,ok)}
        if line.ordinal!=int64(i+1) || !bytes.Equal(line.raw,originals[i]) ||
            line.source.RecordDigest!=sha256.Sum256(originals[i]){
            t.Fatalf("signed ordinal/bytes/digest mismatch at %d",i)
        }
        _,_=h.Write(line.raw)
    }
    if _,ok:=stream.Next();ok{t.Fatal("extra record")}
    digest:=sha256.Sum256(input)
    if !bytes.Equal(h.Sum(nil),digest[:]) {t.Fatal("complete signed stream differs")}
    used,peak:=stream.privateFamilyBudget.stats()
    if used!=0 || peak<=0 || peak>privateFamilyP3Bytes {
        t.Fatalf("admission budget used=%d peak=%d",used,peak)
    }
    if stream.rows!=n {t.Fatalf("processed %d want %d",stream.rows,n)}
}

func TestPrivateFamilyP3DifferentFamiliesCanPrepareWhileSecurityBlocked(t *testing.T) {
    securityStarted:=make(chan struct{},2)
    unblock:=make(chan struct{})
    filePrepared:=make(chan struct{},1)
    var input []byte
    for _,kind:=range []string{"WindowsSecurityEvent","WindowsSecurityEvent",
        "FileObservation","WindowsSecurityCoverage"}{
        input=append(input,canonicalDispatchFixture(kind,"{}")...)
    }
    prepare:=func(raw []byte,kind string,_ spoolDispatchFamily)(SourceRecord,securityBulkRecord,bool,error){
        if kind=="WindowsSecurityEvent" {
            securityStarted<-struct{}{}
            <-unblock
        }
        if kind=="FileObservation" {filePrepared<-struct{}{}}
        return SourceRecord{},securityBulkRecord{},false,nil
    }
    stream,err:=newPrivateFamilyP3PreparedStream(context.Background(),
        bufio.NewReader(bytes.NewReader(input)),prepare)
    if err!=nil{t.Fatal(err)}
    defer stream.Close()
    for i:=0;i<2;i++{
        select{
        case <-securityStarted:
        case <-time.After(2*time.Second):close(unblock);t.Fatal("Security workers failed to start")
        }
    }
    select{
    case <-filePrepared:
    case <-time.After(2*time.Second):
        close(unblock);t.Fatal("File lane blocked behind Security workers")
    }
    close(unblock)
    for i:=1;i<=4;i++{
        line,ok:=stream.Next()
        if !ok || line.ordinal!=int64(i) || line.readErr!=nil || line.prepareErr!=nil {
            t.Fatalf("wrong ordered row %d %+v",i,line)
        }
    }
}

func TestPrivateFamilyP3RejectsUnknownKindAndMissingLF(t *testing.T){
    for _,bad:=range [][]byte{
        canonicalDispatchFixture("UnsupportedKind","{}"),
        bytes.TrimSuffix(canonicalDispatchFixture("WindowsSecurityEvent","{}"),[]byte("\n")),
    } {
        input:=append(canonicalDispatchFixture("FileObservation","{}"),bad...)
        stream,err:=newPrivateFamilyP3PreparedStream(context.Background(),
            bufio.NewReader(bytes.NewReader(input)),
            func([]byte,string,spoolDispatchFamily)(SourceRecord,securityBulkRecord,bool,error){
                return SourceRecord{},securityBulkRecord{},false,nil
            })
        if err!=nil{t.Fatal(err)}
        first,ok:=stream.Next()
        if !ok || first.readErr!=nil{t.Fatalf("first record rejected %+v",first)}
        last,ok:=stream.Next()
        if !ok || last.readErr==nil || last.ordinal!=2 {t.Fatalf("invalid source accepted %+v",last)}
        stream.Close()
    }
}

func TestPrivateFamilyP3BudgetBoundsAndCancel(t *testing.T){
    b:=newPrivateFamilyP3Budget(16)
    ctx,cancel:=context.WithCancel(context.Background())
    if err:=b.reserve(ctx,15);err!=nil{t.Fatal(err)}
    var wg sync.WaitGroup
    wg.Add(1)
    result:=make(chan error,1)
    go func(){defer wg.Done();result<-b.reserve(ctx,2)}()
    cancel()
    select {
    case err:=<-result: if !errors.Is(err,context.Canceled){t.Fatalf("cancel returned %v",err)}
    case <-time.After(2*time.Second):t.Fatal("budget reservation did not wake on cancel")
    }
    wg.Wait()
    b.release(15)
    used,peak:=b.stats()
    if used!=0 || peak!=15 {t.Fatalf("used=%d peak=%d",used,peak)}
    if err:=b.reserve(context.Background(),17);err==nil{t.Fatal("oversize accepted")}
}

func TestPrivateFamilyP3CancelJoinsWorkers(t *testing.T){
    ctx,cancel:=context.WithCancel(context.Background())
    line:=canonicalDispatchFixture("WindowsSecurityEvent","{}")
    stream,err:=newPrivateFamilyP3PreparedStream(ctx,
        bufio.NewReader(bytes.NewReader(bytes.Repeat(line,1000))),
        func([]byte,string,spoolDispatchFamily)(SourceRecord,securityBulkRecord,bool,error){
            return SourceRecord{},securityBulkRecord{},false,nil
        })
    if err!=nil{t.Fatal(err)}
    _,_=stream.Next()
    cancel()
    done:=make(chan struct{})
    go func(){stream.Close();close(done)}()
    select{
    case <-done:
    case <-time.After(2*time.Second):t.Fatal("cancel stranded family workers")
    }
}

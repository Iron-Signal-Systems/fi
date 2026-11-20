// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
package recordingest

import (
    "bytes"
    "context"
    "crypto/sha256"
    "errors"
    "fmt"
    "io"
    "os"
    "path/filepath"
    "strings"
    "testing"

    "github.com/Iron-Signal-Systems/fi/go/internal/spool"
)

func privateC1SignedStreamFixture(t *testing.T,index,window,rows int,kind string) privateC1StreamBatch{
    t.Helper()
    var raw []byte
    for i:=0;i<rows;i++{
        raw=append(raw,canonicalDispatchFixture(kind,fmt.Sprintf("{\"batch\":%d,\"ordinal\":%d}",index,i+1))...)
    }
    path:=filepath.Join(t.TempDir(),fmt.Sprintf("batch-%d.data",index))
    if err:=os.WriteFile(path,raw,0600);err!=nil{t.Fatal(err)}
    var b PreparedBatch
    b.DataPath=path
    b.Manifest.RecordCount=rows
    b.Manifest.DataBytes=int64(len(raw))
    sum:=sha256.Sum256(raw)
    b.Manifest.DataSHA256=fmt.Sprintf("%x",sum)
    return privateC1StreamBatch{Index:index,Window:window,SourceBatchID:int64(index+1000),Batch:b}
}

func TestPrivateC1ContinuousSignedReaderValidatesEveryBatch(t *testing.T){
    batches:=[]privateC1StreamBatch{
        privateC1SignedStreamFixture(t,10,1,6,"WindowsSecurityEvent"),
        privateC1SignedStreamFixture(t,11,1,1,"WindowsSecurityCoverage"),
        privateC1SignedStreamFixture(t,12,2,3,"CollectorIdentity"),
    }
    var expected []byte
    for _,b:=range batches{
        chunk,err:=os.ReadFile(b.Batch.DataPath)
        if err!=nil{t.Fatal(err)}
        expected=append(expected,chunk...)
    }
    src,err:=newPrivateC1SignedContinuousReader(batches)
    if err!=nil{t.Fatal(err)}
    defer src.Close()
    got,err:=io.ReadAll(src)
    if err!=nil{t.Fatal(err)}
    if !bytes.Equal(got,expected){t.Fatal("C1 continuous reader changed canonical record bytes")}
    if err=src.VerifyComplete();err!=nil{t.Fatal(err)}
    if src.verified!=3 {t.Fatalf("verified %d signed batches, expected 3",src.verified)}
}

func TestPrivateC1ContinuousSignedReaderFailsBeforeNextBatchOnTamper(t *testing.T){
    cases:=[]struct{
        name string
        tamper func(*privateC1StreamBatch)
    }{
        {"digest",func(b *privateC1StreamBatch){
            raw,e:=os.ReadFile(b.Batch.DataPath);if e!=nil{t.Fatal(e)}
            raw[1]^=1
            if e=os.WriteFile(b.Batch.DataPath,raw,0600);e!=nil{t.Fatal(e)}
        }},
        {"record-count",func(b *privateC1StreamBatch){b.Batch.Manifest.RecordCount++}},
        {"trailing-LF",func(b *privateC1StreamBatch){
            raw,e:=os.ReadFile(b.Batch.DataPath);if e!=nil{t.Fatal(e)}
            raw[len(raw)-1]=' '
            if e=os.WriteFile(b.Batch.DataPath,raw,0600);e!=nil{t.Fatal(e)}
            b.Batch.Manifest.DataSHA256=fmt.Sprintf("%x",sha256.Sum256(raw))
        }},
    }
    for _,tc:=range cases{
        t.Run(tc.name,func(t *testing.T){
            first:=privateC1SignedStreamFixture(t,1,1,2,"WindowsSecurityCoverage")
            tc.tamper(&first)
            next:=privateC1SignedStreamFixture(t,2,1,1,"CollectorIdentity")
            // The next file must not even be opened if the first batch fails.
            next.Batch.DataPath=filepath.Join(t.TempDir(),"should-not-be-opened.data")
            src,e:=newPrivateC1SignedContinuousReader([]privateC1StreamBatch{first,next})
            if e!=nil{t.Fatal(e)}
            defer src.Close()
            _,e=io.ReadAll(src)
            if e==nil||!strings.Contains(e.Error(),"signed batch 1"){
                t.Fatalf("expected original signed batch rejection, got %v",e)
            }
            if src.verified!=0{t.Fatal("tampered batch was marked verified")}
            if e=src.VerifyComplete();e==nil{t.Fatal("tampered signed source completed")}
        })
    }
}

func TestPrivateC1ContinuousP5FeedsP6InOriginalBatchOrdinalOrder(t *testing.T){
    t.Setenv("FI_W512_P5_PERSISTENT","1")
    t.Setenv("FI_W512_P3_DYNAMIC_MIN","2")
    t.Setenv("FI_W512_P3_DYNAMIC_MAX","16")
    t.Setenv("FI_W512_P3_SECURITY_WORKERS","")
    t.Setenv("FI_W512_P3_GENERAL_WORKERS","")
    ctx:=context.Background()
    pool,err:=newPrivateP5Pool(ctx,1)
    if err!=nil{t.Fatal(err)}
    defer pool.Close()
    sink:=&privateP6TestSink{}
    buffer,err:=newPrivateP6Buffers(1,sink)
    if err!=nil{t.Fatal(err)}
    batches:=[]privateC1StreamBatch{
        privateC1SignedStreamFixture(t,200,1,24,"WindowsSecurityCoverage"),
        privateC1SignedStreamFixture(t,201,1,1,"CollectorIdentity"),
        privateC1SignedStreamFixture(t,202,2,17,"WindowsSecurityCoverage"),
    }
    prepare:=func(raw []byte,kind string,f spoolDispatchFamily)(
        SourceRecord,securityBulkRecord,bool,error){
        got,family,e:=classifyCanonicalSpoolRecord(raw)
        if e!=nil||got!=kind||family!=f{
            return SourceRecord{},securityBulkRecord{},false,errors.New("C1 continuous test: changed original record kind")
        }
        return SourceRecord{
            Record:spool.Record{Version:SpoolRecordVersion,RecordKind:kind,ScopeID:"root"},
            RawRecordBytes:raw,RecordBytes:len(raw),RecordDigest:sha256.Sum256(raw),
        },securityBulkRecord{},false,nil
    }
    var totals privateC1PrepTotals
    groupRows,groupBytes,err:=privateC1ConsumeContinuousSigned(
        ctx,pool,batches,buffer,&totals,3,prepare)
    if err!=nil{t.Fatal(err)}
    if totals.batches!=3||totals.records!=42||groupRows[1]!=25||groupRows[2]!=17{
        t.Fatalf("C1 continuous batch tally mismatch totals=%+v windows=%v",totals,groupRows)
    }
    if groupBytes[1]<=0||groupBytes[2]<=0{t.Fatal("C1 continuous byte tally missing")}
    if len(sink.calls)!=0{t.Fatal("C1 continuous signed batch boundary flushed a P6 family")}
    if err=buffer.Finish(ctx);err!=nil{t.Fatal(err)}
    if len(sink.sourceRows)!=42{t.Fatalf("C1 source rows %d, expected 42",len(sink.sourceRows))}
    if len(sink.typedRows[privateP6Coverage])!=41 ||
        len(sink.typedRows[privateP6Other])!=1{
        t.Fatal("C1 continuous family dispatch changed original types")
    }
    for _,row:=range sink.sourceRows{
        if row.signedBatchIndex==201&&row.ordinal!=1{
            t.Fatal("C1 failed to restart signed record ordinal at next batch")
        }
    }
}

func TestPrivateC1ContinuousRejectsOutOfOrderBatchIndex(t *testing.T){
    a:=privateC1SignedStreamFixture(t,1,1,1,"WindowsSecurityCoverage")
    b:=privateC1SignedStreamFixture(t,3,1,1,"WindowsSecurityCoverage")
    if _,err:=newPrivateC1SignedContinuousReader([]privateC1StreamBatch{a,b});err==nil{
        t.Fatal("C1 accepted skipped signed batch index")
    }
}

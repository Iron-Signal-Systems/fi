// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
package recordingest

import ("bufio";"bytes";"context";"crypto/sha256";"errors";"fmt";"io";"testing";"github.com/Iron-Signal-Systems/fi/go/internal/spool")

func TestPrivateP11P6OriginalBuffersContinueAcrossW512(t *testing.T){
    ctx:=context.Background()
    mock:=&privateP6TestSink{}
    b,err:=newPrivateP6Buffers(1,mock)
    if err!=nil{t.Fatal(err)}
    kinds:=[]string{"WindowsSecurityEvent","FileObservation",
        "WindowsSecurityCoverage","USNReadBoundary","CollectorIdentity"}
    for batch:=1;batch<=2;batch++{
        for i,kind:=range kinds{
            if err=b.Add(ctx,privateP6Fixture(batch,int64(i+1),kind));err!=nil{t.Fatal(err)}
        }
        if len(mock.calls)!=0{
            t.Fatalf("W512 boundary %d incorrectly drained P6 family: %v",batch,mock.calls)
        }
    }
    if err=b.Finish(ctx);err!=nil{t.Fatal(err)}
    if b.total!=10||len(mock.sourceRows)!=10{
        t.Fatal("P11 lost one or more signed parents across W512")
    }
    for i:=range b.lanes{
        if len(mock.typedRows[i])!=2{t.Fatalf("P11 family %s missing original rows",privateP6FamilyNames[i])}
    }
}

type privateP11BarrierFake struct{
    privateP6TestSink
    fileDone bool
    waited bool
}
func(s *privateP11BarrierFake) WaitFamily(ctx context.Context,f privateP6Family)error{
    if err:=ctx.Err();err!=nil{return err}
    if f!=privateP6File{return errors.New("FI P11: unexpected unrelated dependency flush")}
    s.waited=true
    s.fileDone=true
    return nil
}
func(s *privateP11BarrierFake) WaitAll(ctx context.Context)error{
    return ctx.Err()
}
func(s *privateP11BarrierFake) Family(ctx context.Context,f privateP6Family,rows []privateP6Record)error{
    if f==privateP6USN&&!s.fileDone{return errors.New("FI P11: USN before SQL File commit")}
    return s.privateP6TestSink.Family(ctx,f,rows)
}
func TestPrivateP11FileDependencyWaitsWithoutFlushingOtherFamilies(t *testing.T){
    ctx:=context.Background()
    mock:=&privateP11BarrierFake{}
    b,err:=newPrivateP6Buffers(1,mock)
    if err!=nil{t.Fatal(err)}
    kinds:=[]string{"WindowsSecurityEvent","FileObservation",
        "WindowsSecurityCoverage","USNReadBoundary","USNObjectObservation"}
    b.lanes[privateP6USN].limit.rows=2
    for i,kind:=range kinds{
        if err=b.Add(ctx,privateP6Fixture(1,int64(i+1),kind));err!=nil{t.Fatal(err)}
    }
    if !mock.waited||len(mock.typedRows[privateP6USN])!=2{
        t.Fatal("P11 File SQL completion wasn't awaited before USN")
    }
    if len(mock.typedRows[privateP6Security])!=0||
       len(mock.typedRows[privateP6Coverage])!=0{
        t.Fatal("P11 dependency incorrectly flushed independent family")
    }
    if err=b.Finish(ctx);err!=nil{t.Fatal(err)}
}
func TestPrivateP11NeverSelectsWithoutP6AndPrivateClone(t *testing.T){
    t.Setenv("FI_W512_P6_FAMILY_SQL","1")
    t.Setenv("FI_W512_P11_P6_DIRECT","1")
    t.Setenv("FI_W512_P7_SQL_WRITERS","")
    t.Setenv("FI_W512_P8_REUSE","")
    t.Setenv("FI_W512_P9_DIRECT_STREAM","")
    if !privateP11Enabled(){t.Fatal("P11 private P6 path not selected")}
    t.Setenv("FI_W512_P7_SQL_WRITERS","5")
    if privateP11Enabled(){t.Fatal("P11 incorrectly selected P7 infrastructure")}
    t.Setenv("FI_W512_P7_SQL_WRITERS","")
    t.Setenv("FI_W512_P6_FAMILY_SQL","")
    if privateP11Enabled(){t.Fatal("P11 incorrectly selected without original P6")}
}
func TestPrivateP11ExactBenchmarkStop(t *testing.T){
    t.Setenv("FI_W512_P11_STOP_WINDOWS","2")
    end,err:=privateP11StopIndex(1,20)
    if err!=nil||end!=3{t.Fatalf("P11 prefix end=%d err=%v",end,err)}
    for _,s:=range []string{"0","-1","20","NaN"}{
        t.Setenv("FI_W512_P11_STOP_WINDOWS",s)
        if _,err:=privateP11StopIndex(1,20);err==nil{
            t.Fatalf("P11 accepted invalid window limit %s",s)
        }
    }
}


func TestPrivateP11FiveNativeProjectorsReuseP6CopyContexts(t *testing.T){
    // A File DACL with no ACE state would call privateProjectionTx.SendBatch,
    // which MUST remain forbidden. Each worker needs P6's bounded ACE COPY
    // state, and also the hash/USN states that P6 used to inherit from the
    // typed-window transaction. The contexts must not share mutable buffers.
    left,hashA,aceA,usnA:=privateP11BoundedProjectorContext(context.Background())
    right,hashB,aceB,usnB:=privateP11BoundedProjectorContext(context.Background())
    for i,c:=range []context.Context{left,right}{
        if c.Value(aceCopyContextKey{})==nil||
           c.Value(contentHashCopyContextKey{})==nil||
           c.Value(usnChangeCopyContextKey{})==nil||
           c.Value(ntfsObjectCacheContextKey{})==nil||
           c.Value(ntfsScopeIdentityCacheContextKey{})==nil||
           c.Value(ntfsStageTimingContextKey{})==nil{
            t.Fatalf("P11 SQL worker %d omitted accepted P6 bounded child projector state",i)
        }
    }
    if hashA==hashB||aceA==aceB||usnA==usnB{
        t.Fatal("P11 concurrent PostgreSQL workers share mutable bounded buffers")
    }
    // Confirm this regression fix did not weaken FI's original private
    // projector security boundary.
    var failClosed privateProjectionTx
    if err:=failClosed.SendBatch(context.Background(),nil).Close();err==nil{
        t.Fatal("P11 weakened the original private SendBatch prohibition")
    }
}

func TestPrivateP11FiveDirectModulesMatchOriginalP6Kinds(t *testing.T){
    for i,module:=range privateP11SQLModules{
        if int(module.family)!=i||module.project==nil{
            t.Fatalf("P11 SQL family module %d not independently bound",i)
        }
    }
}

func TestPrivateP11OriginalP5WorkersFeedPersistentP6Buffers(t *testing.T){
    // The original P5 dynamic worker pool MUST be invoked, remain alive
    // across signed batches, and dispatch prepared rows to P6 buffers once
    // in signed order, without an artificial W512 flush or a second SHA.
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
    kinds:=[]string{"WindowsSecurityEvent","FileObservation",
        "WindowsSecurityCoverage","USNReadBoundary","CollectorIdentity"}
    var totals privateP11PrepTotals
    prepare:=func(raw []byte,kind string,f spoolDispatchFamily)(
        SourceRecord,securityBulkRecord,bool,error){
        got,gotFamily,e:=classifyCanonicalSpoolRecord(raw)
        if e!=nil||kind!=got||gotFamily!=f{
            return SourceRecord{},securityBulkRecord{},false,
                errors.New("FI P11 test: signed header and family changed")
        }
        return SourceRecord{
            Record:spool.Record{Version:SpoolRecordVersion,RecordKind:kind,ScopeID:"root"},
            RawRecordBytes:raw,RecordBytes:len(raw),
            RecordDigest:sha256.Sum256(raw),
        },securityBulkRecord{},false,nil
    }
    for batch:=1;batch<=2;batch++ {
        var input []byte
        for i:=0;i<60;i++{
            raw:=canonicalDispatchFixture(kinds[i%len(kinds)],
                fmt.Sprintf("{\"batch\":%d,\"ordinal\":%d}",batch,i+1))
            input=append(input,raw...)
        }
        sha:=sha256.New()
        r:=bufio.NewReader(io.TeeReader(bytes.NewReader(input),sha))
        n,nbytes,e:=privateP11ConsumePrepared(ctx,pool,r,prepare,
            func(line privateParallelLine)error{
                return buffer.Add(ctx,privateP6Record{
                    signedBatchIndex:batch,sourceBatchID:int64(100+batch),
                    ordinal:line.ordinal,prepared:line.source,
                })
            },&totals)
        if e!=nil||n!=60||nbytes!=int64(len(input)){
            t.Fatalf("P11 P5 pool signed batch %d rows=%d bytes=%d err=%v",
                batch,n,nbytes,e)
        }
        expected:=sha256.Sum256(input)
        if !bytes.Equal(sha.Sum(nil),expected[:]){
            t.Fatal("P11 tee reader changed original signed bytes")
        }
        if len(sink.calls)!=0{
            t.Fatalf("P11 signed batch/W512 boundary drained a P6 family: %v",sink.calls)
        }
    }
    if totals.batches!=2||totals.records!=120{
        t.Fatalf("P11 pool preparation incomplete %+v",totals)
    }
    for f,lane:=range pool.lanes{
        if n:=lane.spawned();n<2||n>16{
            t.Fatalf("P11 family %d has %d P5 workers",f,n)
        }
    }
    if err=buffer.Finish(ctx);err!=nil{t.Fatal(err)}
    if len(sink.sourceRows)!=120{
        t.Fatalf("P11 original source ledger lost records: %d",len(sink.sourceRows))
    }
    for f:=range sink.typedRows{
        if len(sink.typedRows[f])!=24{
            t.Fatalf("P11 family %d received %d instead of 24",f,len(sink.typedRows[f]))
        }
    }
}

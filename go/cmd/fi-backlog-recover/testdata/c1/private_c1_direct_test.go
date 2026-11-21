// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
package recordingest

import ("bufio";"bytes";"context";"crypto/sha256";"errors";"fmt";"io";"testing";"github.com/Iron-Signal-Systems/fi/go/internal/spool")

func TestPrivateC1Security8GiBBufferProfileFailClosedAndBounded(t *testing.T){
    t.Setenv("FI_C1_SECURITY_8G_EXPERIMENT","0")
    t.Setenv("FI_C1_DEV_PREFIX8","1")
    t.Setenv("FI_W512_C1_P6_DIRECT","1")
    t.Setenv("FI_W512_C1_FULL_BACKLOG","0")
    control,err:=newPrivateP6Buffers(1,&privateP6TestSink{})
    if err!=nil{t.Fatal(err)}
    if control.lanes[privateP6Security].limit!=(privateP6Limits{rows:4096,bytes:16<<20}){
        t.Fatal("established C1 Security buffer was modified without candidate opt-in")
    }
    t.Setenv("FI_C1_SECURITY_8G_EXPERIMENT","1")
    candidate,err:=newPrivateP6Buffers(1,&privateP6TestSink{})
    if err!=nil{t.Fatal(err)}
    if candidate.lanes[privateP6Security].limit!=(privateP6Limits{rows:8192,bytes:32<<20}){
        t.Fatal("C1 8GiB Security candidate did not select exact 8192/32MiB limits")
    }
    for f:=privateP6Family(0);f<privateP6FamilyCount;f++{
        if f!=privateP6Security&&candidate.lanes[f].limit!=control.lanes[f].limit{
            t.Fatalf("C1 Security candidate changed unrelated family %s capacity",privateP6FamilyNames[f])
        }
    }
    rowBound:=candidate.lanes[privateP6Security]
    rowBound.pending=make([]privateP6Record,8191)
    if privateP6ShouldFlush(&rowBound,1){t.Fatal("Security candidate flushed before 8192-row bound")}
    rowBound.pending=append(rowBound.pending,privateP6Record{})
    if !privateP6ShouldFlush(&rowBound,1){t.Fatal("Security candidate exceeded 8192-row bound")}
    bytesBound:=candidate.lanes[privateP6Security]
    bytesBound.pending=make([]privateP6Record,1)
    bytesBound.bytes=32<<20-1
    if privateP6ShouldFlush(&bytesBound,1){t.Fatal("Security candidate flushed at exact byte bound")}
    if !privateP6ShouldFlush(&bytesBound,2){t.Fatal("Security candidate exceeded 32MiB bound")}
    t.Setenv("FI_W512_C1_FULL_BACKLOG","1")
    if _,err:=newPrivateP6Buffers(1,&privateP6TestSink{});err==nil{
        t.Fatal("C1 experimental Security profile selected in full 8399-batch run")
    }
    t.Setenv("FI_W512_C1_FULL_BACKLOG","0")
    t.Setenv("FI_C1_DEV_PREFIX8","0")
    if _,err:=newPrivateP6Buffers(1,&privateP6TestSink{});err==nil{
        t.Fatal("C1 experimental Security profile selected without two-group 8GiB mode")
    }
    t.Setenv("FI_C1_DEV_PREFIX8","1")
    t.Setenv("FI_C1_SECURITY_8G_EXPERIMENT","unexpected")
    if _,err:=newPrivateP6Buffers(1,&privateP6TestSink{});err==nil{
        t.Fatal("C1 experimental Security profile accepted invalid flag")
    }
}

func TestPrivateC1P6OriginalBuffersContinueAcrossW512(t *testing.T){
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
        t.Fatal("C1 lost one or more signed parents across W512")
    }
    for i:=range b.lanes{
        if len(mock.typedRows[i])!=2{t.Fatalf("C1 family %s missing original rows",privateP6FamilyNames[i])}
    }
}

type privateC1BarrierFake struct{
    privateP6TestSink
    fileDone bool
    waited bool
}
func(s *privateC1BarrierFake) WaitFamily(ctx context.Context,f privateP6Family)error{
    if err:=ctx.Err();err!=nil{return err}
    if f!=privateP6File{return errors.New("FI C1: unexpected unrelated dependency flush")}
    s.waited=true
    s.fileDone=true
    return nil
}
func(s *privateC1BarrierFake) WaitAll(ctx context.Context)error{
    return ctx.Err()
}
func(s *privateC1BarrierFake) Family(ctx context.Context,f privateP6Family,rows []privateP6Record)error{
    if f==privateP6USN&&!s.fileDone{return errors.New("FI C1: USN before SQL File commit")}
    return s.privateP6TestSink.Family(ctx,f,rows)
}
func TestPrivateC1FileDependencyWaitsWithoutFlushingOtherFamilies(t *testing.T){
    ctx:=context.Background()
    mock:=&privateC1BarrierFake{}
    b,err:=newPrivateP6Buffers(1,mock)
    if err!=nil{t.Fatal(err)}
    kinds:=[]string{"WindowsSecurityEvent","FileObservation",
        "WindowsSecurityCoverage","USNReadBoundary","USNObjectObservation"}
    b.lanes[privateP6USN].limit.rows=2
    for i,kind:=range kinds{
        if err=b.Add(ctx,privateP6Fixture(1,int64(i+1),kind));err!=nil{t.Fatal(err)}
    }
    if !mock.waited||len(mock.typedRows[privateP6USN])!=2{
        t.Fatal("C1 File SQL completion wasn't awaited before USN")
    }
    if len(mock.typedRows[privateP6Security])!=0||
       len(mock.typedRows[privateP6Coverage])!=0{
        t.Fatal("C1 dependency incorrectly flushed independent family")
    }
    if err=b.Finish(ctx);err!=nil{t.Fatal(err)}
}
type privateC1DeferredUSNBufferSink struct{
    privateP6TestSink
    synchronousFileWaits int
}
func (s *privateC1DeferredUSNBufferSink) AsyncUSNDependencies() bool{return true}
func (s *privateC1DeferredUSNBufferSink) WaitFamily(ctx context.Context,f privateP6Family)error{
    s.synchronousFileWaits++
    return errors.New("C1 async USN must not synchronously wait on File")
}
func TestPrivateC1USNFilePrerequisitesDeferredOffPreparation(t *testing.T){
    sink:=&privateC1DeferredUSNBufferSink{}
    buf,err:=newPrivateP6Buffers(1,sink)
    if err!=nil{t.Fatal(err)}
    buf.lanes[privateP6USN].limit.rows=1
    ctx:=context.Background()
    if err:=buf.Add(ctx,privateP6Fixture(1,1,"FileObservation"));err!=nil{t.Fatal(err)}
    if err:=buf.Add(ctx,privateP6Fixture(1,2,"USNReadBoundary"));err!=nil{t.Fatal(err)}
    if sink.synchronousFileWaits!=0 {
        t.Fatal("C1 Preparation still blocked on File/NTFS commit")
    }
    if len(sink.typedRows[privateP6File])!=1||len(sink.typedRows[privateP6USN])!=1{
        t.Fatal("File and USN handoffs were not submitted together")
    }
    if err:=buf.Finish(ctx);err!=nil{t.Fatal(err)}
}
func TestPrivateC1NeverSelectsWithoutP6AndPrivateClone(t *testing.T){
    t.Setenv("FI_W512_P6_FAMILY_SQL","1")
    t.Setenv("FI_W512_C1_P6_DIRECT","1")
    t.Setenv("FI_W512_P7_SQL_WRITERS","")
    t.Setenv("FI_W512_P8_REUSE","")
    t.Setenv("FI_W512_P9_DIRECT_STREAM","")
    if !privateC1Enabled(){t.Fatal("C1 private P6 path not selected")}
    t.Setenv("FI_W512_P7_SQL_WRITERS","5")
    if privateC1Enabled(){t.Fatal("C1 incorrectly selected P7 infrastructure")}
    t.Setenv("FI_W512_P7_SQL_WRITERS","")
    t.Setenv("FI_W512_P6_FAMILY_SQL","")
    if privateC1Enabled(){t.Fatal("C1 incorrectly selected without original P6")}
}
func TestPrivateC1ExactBenchmarkStop(t *testing.T){
    t.Setenv("FI_W512_C1_STOP_WINDOWS","2")
    end,err:=privateC1StopIndex(1,20)
    if err!=nil||end!=3{t.Fatalf("C1 prefix end=%d err=%v",end,err)}
    for _,s:=range []string{"0","-1","20","NaN"}{
        t.Setenv("FI_W512_C1_STOP_WINDOWS",s)
        if _,err:=privateC1StopIndex(1,20);err==nil{
            t.Fatalf("C1 accepted invalid window limit %s",s)
        }
    }
}


func TestPrivateC1FiveNativeProjectorsReuseP6CopyContexts(t *testing.T){
    // A File DACL with no ACE state would call privateProjectionTx.SendBatch,
    // which MUST remain forbidden. Each worker needs P6's bounded ACE COPY
    // state, and also the hash/USN states that P6 used to inherit from the
    // typed-window transaction. The contexts must not share mutable buffers.
    left,hashA,aceA,usnA:=privateC1BoundedProjectorContext(context.Background())
    right,hashB,aceB,usnB:=privateC1BoundedProjectorContext(context.Background())
    for i,c:=range []context.Context{left,right}{
        if c.Value(aceCopyContextKey{})==nil||
           c.Value(contentHashCopyContextKey{})==nil||
           c.Value(usnChangeCopyContextKey{})==nil||
           c.Value(ntfsObjectCacheContextKey{})==nil||
           c.Value(ntfsScopeIdentityCacheContextKey{})==nil||
           c.Value(ntfsStageTimingContextKey{})==nil{
            t.Fatalf("C1 SQL worker %d omitted accepted P6 bounded child projector state",i)
        }
    }
    if hashA==hashB||aceA==aceB||usnA==usnB{
        t.Fatal("C1 concurrent PostgreSQL workers share mutable bounded buffers")
    }
    // Confirm this regression fix did not weaken FI's original private
    // projector security boundary.
    var failClosed privateProjectionTx
    if err:=failClosed.SendBatch(context.Background(),nil).Close();err==nil{
        t.Fatal("C1 weakened the original private SendBatch prohibition")
    }
}

func TestPrivateC1FiveDirectModulesMatchOriginalP6Kinds(t *testing.T){
    for i,module:=range privateC1SQLModules{
        if int(module.family)!=i||module.project==nil{
            t.Fatalf("C1 SQL family module %d not independently bound",i)
        }
    }
}

func TestPrivateC1OriginalP5WorkersFeedPersistentP6Buffers(t *testing.T){
    // The original P5 dynamic worker pool MUST be invoked, remain alive
    // across signed batches, and dispatch prepared rows to P6 buffers once
    // in signed order, without an artificial W512 flush or a second SHA.
    t.Setenv("FI_W512_P5_PERSISTENT","1")
    t.Setenv("FI_W512_P3_DYNAMIC_MIN","2")
    t.Setenv("FI_W512_P3_DYNAMIC_MAX","32")
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
    var totals privateC1PrepTotals
    prepare:=func(raw []byte,kind string,f spoolDispatchFamily)(
        SourceRecord,securityBulkRecord,bool,error){
        got,gotFamily,e:=classifyCanonicalSpoolRecord(raw)
        if e!=nil||kind!=got||gotFamily!=f{
            return SourceRecord{},securityBulkRecord{},false,
                errors.New("FI C1 test: signed header and family changed")
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
        n,nbytes,e:=privateC1ConsumePrepared(ctx,pool,r,prepare,
            func(line privateParallelLine)error{
                return buffer.Add(ctx,privateP6Record{
                    signedBatchIndex:batch,sourceBatchID:int64(100+batch),
                    ordinal:line.ordinal,prepared:line.source,
                })
            },&totals)
        if e!=nil||n!=60||nbytes!=int64(len(input)){
            t.Fatalf("C1 P5 pool signed batch %d rows=%d bytes=%d err=%v",
                batch,n,nbytes,e)
        }
        expected:=sha256.Sum256(input)
        if !bytes.Equal(sha.Sum(nil),expected[:]){
            t.Fatal("C1 tee reader changed original signed bytes")
        }
        if len(sink.calls)!=0{
            t.Fatalf("C1 signed batch/W512 boundary drained a P6 family: %v",sink.calls)
        }
    }
    if totals.batches!=2||totals.records!=120{
        t.Fatalf("C1 pool preparation incomplete %+v",totals)
    }
    for f,lane:=range pool.lanes{
        if n:=lane.spawned();n<2||n>32{
            t.Fatalf("C1 family %d has %d P5 workers",f,n)
        }
    }
    if err=buffer.Finish(ctx);err!=nil{t.Fatal(err)}
    if len(sink.sourceRows)!=120{
        t.Fatalf("C1 original source ledger lost records: %d",len(sink.sourceRows))
    }
    for f:=range sink.typedRows{
        if len(sink.typedRows[f])!=24{
            t.Fatalf("C1 family %d received %d instead of 24",f,len(sink.typedRows[f]))
        }
    }
}

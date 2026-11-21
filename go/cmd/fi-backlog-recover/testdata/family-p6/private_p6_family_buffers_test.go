// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
package recordingest

import (
    "context"
    "errors"
    "fmt"
    "strings"
    "testing"
    "reflect"
    "time"

    "github.com/jackc/pgx/v5"

    "github.com/Iron-Signal-Systems/fi/go/internal/spool"
)

type privateP6TestSink struct{
    sourceRows []privateP6Record
    typedRows [privateP6FamilyCount][]privateP6Record
    calls []string
    failSource bool
    failFamily privateP6Family
}
func(s *privateP6TestSink) Source(_ context.Context,rows []privateP6Record)error{
    if s.failSource{return errors.New("injected original source COPY failure")}
    for _,r:=range rows{
        if len(s.sourceRows)>0{
            prev:=s.sourceRows[len(s.sourceRows)-1]
            if r.signedBatchIndex<prev.signedBatchIndex ||
                (r.signedBatchIndex==prev.signedBatchIndex && r.ordinal<=prev.ordinal){
                return errors.New("FI P6 TEST: SQL source order reversed")
            }
        }
        s.sourceRows=append(s.sourceRows,r)
    }
    s.calls=append(s.calls,fmt.Sprintf("source:%d",len(rows)))
    return nil
}
func(s *privateP6TestSink) Family(_ context.Context,f privateP6Family,rows []privateP6Record)error{
    if s.failFamily==f+1{return errors.New("injected relational child/FK failure")}
    // Parent source identities MUST be present before any relational child.
    for _,r:=range rows{
        found:=false
        for _,src:=range s.sourceRows{
            if r.signedBatchIndex==src.signedBatchIndex&&r.ordinal==src.ordinal&&
                r.prepared.RecordDigest==src.prepared.RecordDigest{
                found=true;break
            }
        }
        if !found{return errors.New("FI P6 TEST: child before exact source FK")}
        s.typedRows[f]=append(s.typedRows[f],r)
    }
    s.calls=append(s.calls,privateP6FamilyNames[f])
    return nil
}
func privateP6Fixture(batch int,ordinal int64,kind string)privateP6Record{
    raw:=[]byte("{\"signed\":\"fixture\"}\n")
    return privateP6Record{
        signedBatchIndex:batch,sourceBatchID:int64(batch+101),
        ordinal:ordinal,
        prepared:SourceRecord{
            Record:spool.Record{Version:SpoolRecordVersion,RecordKind:kind,ScopeID:"root"},
            RawRecordBytes:raw,RecordBytes:len(raw),
        },
    }
}

func TestPrivateP6OrderedSourceCOPYCursorExactNineColumns(t *testing.T){
    rows:=[]privateP6Record{
        privateP6Fixture(205,1,"WindowsSecurityEvent"),
        privateP6Fixture(205,2,"FileObservation"),
        privateP6Fixture(206,1,"USNReadBoundary"),
    }
    for i:=range rows{
        rows[i].prepared.WrittenAtUTC=time.Date(2026,11,21,10,i,0,0,time.UTC)
        rows[i].prepared.RecordDigest[0]=byte(i+10)
        rows[i].prepared.RecordDigest[31]=byte(i+100)
    }
    reference:=pgx.CopyFromSlice(len(rows),func(i int)([]any,error){
        r:=rows[i]
        p:=r.prepared
        return []any{r.sourceBatchID,r.ordinal,p.Record.Version,p.Record.RecordKind,
            p.Record.ScopeID,p.WrittenAtUTC,p.RecordBytes,p.RecordDigest[:],IngestVersion},nil
    })
    cur:=&privateP6SourceCopyCursor{rows:rows}
    if _,err:=cur.Values();err==nil{t.Fatal("SourceParent cursor permitted Values before Next")}
    if !cur.Next(){t.Fatal("SourceParent cursor dropped the first signed record")}
    for i:=range rows{
        if i>0&&!cur.Next(){t.Fatalf("SourceParent cursor dropped signed record %d",i)}
        if !reference.Next(){t.Fatal("old SourceParent reference cursor was shorter")}
        got,err:=cur.Values()
        if err!=nil{t.Fatal(err)}
        want,err:=reference.Values()
        if err!=nil{t.Fatal(err)}
        if !reflect.DeepEqual(got,want){
            t.Fatalf("SourceParent row %d changed source batch/ordinal/digest or one of 9 SQL values: got=%v want=%v",i,got,want)
        }
        if len(got)!=9{t.Fatalf("SourceParent row has %d columns instead of 9",len(got))}
    }
    if cur.Next()||reference.Next()||cur.Err()!=nil{
        t.Fatal("SourceParent cursor added/omitted a signed row")
    }
    var nilCursor *privateP6SourceCopyCursor
    if nilCursor.Next(){t.Fatal("nil SourceParent cursor advanced")}
    if _,err:=nilCursor.Values();err==nil{t.Fatal("nil SourceParent cursor returned values")}
}

func TestPrivateP6RoutesEverySignedKindExactlyOnce(t *testing.T){
    kinds:=SupportedRecordKinds()
    if len(kinds)!=13{t.Fatalf("supported kinds=%d want=13",len(kinds))}
    sink:=&privateP6TestSink{}
    b,err:=newPrivateP6Buffers(1,sink);if err!=nil{t.Fatal(err)}
    ctx:=context.Background()
    counts:=[privateP6FamilyCount]int{}
    for i,kind:=range kinds{
        f,e:=privateP6KindFamily(kind);if e!=nil{t.Fatal(e)}
        counts[f]++
        if err=b.Add(ctx,privateP6Fixture(1,int64(i+1),kind));err!=nil{t.Fatal(err)}
    }
    if err=b.Finish(ctx);err!=nil{t.Fatal(err)}
    if !b.finished||len(sink.sourceRows)!=13||b.source.records!=13{
        t.Fatalf("source/finish mismatch source=%d total=%d",len(sink.sourceRows),b.total)
    }
    for f,n:=range counts{
        if len(sink.typedRows[f])!=n{
            t.Fatalf("family=%s received=%d expected=%d",privateP6FamilyNames[f],len(sink.typedRows[f]),n)
        }
    }
    if err=b.Add(ctx,privateP6Fixture(1,14,"WindowsSecurityEvent"));err==nil{
        t.Fatal("committed typed window accepted another source row")
    }
}

func TestPrivateP6SecurityCapacityDoesNotFlushUnrelatedFamilies(t *testing.T){
    ctx:=context.Background()
    sink:=&privateP6TestSink{}
    b,err:=newPrivateP6Buffers(1,sink);if err!=nil{t.Fatal(err)}
    for i,kind:=range []string{"FileObservation","WindowsSecurityCoverage",
        "USNContinuityGap","CollectorIdentity"}{
        if err=b.Add(ctx,privateP6Fixture(1,int64(i+1),kind));err!=nil{t.Fatal(err)}
    }
    for i:=0;i<4096;i++{
        if err=b.Add(ctx,privateP6Fixture(1,int64(i+5),"WindowsSecurityEvent"));err!=nil{t.Fatal(err)}
    }
    if len(sink.typedRows[privateP6Security])!=4096||
        len(sink.typedRows[privateP6File])!=0||
        len(sink.typedRows[privateP6Coverage])!=0||
        len(sink.typedRows[privateP6USN])!=0||
        len(sink.typedRows[privateP6Other])!=0{
        t.Fatal("Security capacity drained unrelated family")
    }
    if b.lanes[privateP6Security].capacityHandoffs!=1||
        b.lanes[privateP6File].handoffs!=0{
        t.Fatal("Security capacity not recorded as the sole family handoff")
    }
    if err=b.Finish(ctx);err!=nil{t.Fatal(err)}
    if len(sink.sourceRows)!=4100 {t.Fatal("source ledger lost interleaved original rows")}
}

func TestPrivateP6USNDependencyFlushesOnlyRelatedFile(t *testing.T){
    ctx:=context.Background()
    sink:=&privateP6TestSink{}
    b,err:=newPrivateP6Buffers(1,sink);if err!=nil{t.Fatal(err)}
    for i,kind:=range []string{"WindowsSecurityEvent","FileObservation",
        "WindowsSecurityCoverage","USNReadBoundary"}{
        if err=b.Add(ctx,privateP6Fixture(1,int64(i+1),kind));err!=nil{t.Fatal(err)}
    }
    b.lanes[privateP6USN].limit.rows=2
    if err=b.Add(ctx,privateP6Fixture(1,5,"USNObjectObservation"));err!=nil{t.Fatal(err)}
    joined:=strings.Join(sink.calls,",")
    if strings.Index(joined,"NTFSFile")<0||strings.Index(joined,"USNDependency")<0||
        strings.Index(joined,"NTFSFile")>strings.Index(joined,"USNDependency"){
        t.Fatalf("NTFS prerequisite wasn't written before dependent USN: %v",sink.calls)
    }
    if len(sink.typedRows[privateP6Security])!=0||
        len(sink.typedRows[privateP6Coverage])!=0{
        t.Fatal("USN dependency unnecessarily flushed Security/Coverage")
    }
    if b.lanes[privateP6File].dependencyHandoffs!=1{
        t.Fatal("File dependency handoff not accounted")
    }
    if err=b.Finish(ctx);err!=nil{t.Fatal(err)}
}

func TestPrivateP6SignedBatchBoundaryDoesNotFlush(t *testing.T){
    ctx:=context.Background()
    sink:=&privateP6TestSink{}
    b,err:=newPrivateP6Buffers(1,sink);if err!=nil{t.Fatal(err)}
    for batch:=1;batch<=3;batch++{
        for ordinal:=int64(1);ordinal<=3;ordinal++{
            if err=b.Add(ctx,privateP6Fixture(batch,ordinal,"WindowsSecurityEvent"));err!=nil{t.Fatal(err)}
        }
    }
    if len(sink.calls)!=0{
        t.Fatalf("ordinary signed batch boundary caused premature SQL flush: %v",sink.calls)
    }
    if err=b.Finish(ctx);err!=nil{t.Fatal(err)}
    if len(sink.typedRows[privateP6Security])!=9 || len(sink.sourceRows)!=9{
        t.Fatal("signed records across three batches not drained atomically")
    }
}

func TestPrivateP6FailsClosedOnBadOrderAndSQLFailures(t *testing.T){
    ctx:=context.Background()
    t.Run("bad-ordinal",func(t *testing.T){
        b,_:=newPrivateP6Buffers(1,&privateP6TestSink{})
        a:=privateP6Fixture(1,1,"WindowsSecurityEvent")
        if err:=b.Add(ctx,a);err!=nil{t.Fatal(err)}
        if err:=b.Add(ctx,a);err==nil{t.Fatal("duplicate signed row accepted")}
        if err:=b.Finish(ctx);err==nil{t.Fatal("invalid source allowed typed commit")}
    })
    t.Run("missing-kind",func(t *testing.T){
        b,_:=newPrivateP6Buffers(1,&privateP6TestSink{})
        if err:=b.Add(ctx,privateP6Fixture(1,1,"Unsupported"));err==nil{
            t.Fatal("unreviewed projector kind accepted")
        }
    })
    t.Run("source-sql-failure",func(t *testing.T){
        sink:=&privateP6TestSink{failSource:true}
        b,_:=newPrivateP6Buffers(1,sink)
        b.source.limit.rows=1
        if err:=b.Add(ctx,privateP6Fixture(1,1,"WindowsSecurityEvent"));err==nil{
            t.Fatal("source SQL failure ignored")
        }
        if b.finished||len(b.source.pending)!=1||len(sink.typedRows[privateP6Security])!=0{
            t.Fatal("SQL failure discarded original rows or allowed typed commit")
        }
    })
    t.Run("typed-fk-failure",func(t *testing.T){
        sink:=&privateP6TestSink{failFamily:privateP6Security+1}
        b,_:=newPrivateP6Buffers(1,sink)
        b.lanes[privateP6Security].limit.rows=1
        if err:=b.Add(ctx,privateP6Fixture(1,1,"WindowsSecurityEvent"));err==nil{
            t.Fatal("typed child SQL failure ignored")
        }
        if b.finished||len(b.lanes[privateP6Security].pending)!=1{
            t.Fatal("failed SQL child changed queue or completed typed window")
        }
    })
}

func TestPrivateP6BatchedSourceParentAlwaysPrecedesChild(t *testing.T){
    ctx:=context.Background()
    sink:=&privateP6TestSink{}
    b,_:=newPrivateP6Buffers(1,sink)
    b.lanes[privateP6Coverage].limit.rows=3
    for i:=0;i<20;i++{
        kind:="WindowsSecurityCoverage"
        if i%2==0{kind="FileObservation"}
        if err:=b.Add(ctx,privateP6Fixture(i/7+1,int64(i%7+1),kind));err!=nil{t.Fatal(err)}
    }
    if err:=b.Finish(ctx);err!=nil{t.Fatal(err)}
    if len(sink.sourceRows)!=20 || b.total!=20{
        t.Fatalf("source records=%d total=%d",len(sink.sourceRows),b.total)
    }
}

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
package recordingest

import ("context";"errors";"testing")

func TestPrivateP10P6OriginalBuffersContinueAcrossW512(t *testing.T){
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
        t.Fatal("P10 lost one or more signed parents across W512")
    }
    for i:=range b.lanes{
        if len(mock.typedRows[i])!=2{t.Fatalf("P10 family %s missing original rows",privateP6FamilyNames[i])}
    }
}

type privateP10BarrierFake struct{
    privateP6TestSink
    fileDone bool
    waited bool
}
func(s *privateP10BarrierFake) WaitFamily(ctx context.Context,f privateP6Family)error{
    if err:=ctx.Err();err!=nil{return err}
    if f!=privateP6File{return errors.New("FI P10: unexpected unrelated dependency flush")}
    s.waited=true
    s.fileDone=true
    return nil
}
func(s *privateP10BarrierFake) WaitAll(ctx context.Context)error{
    return ctx.Err()
}
func(s *privateP10BarrierFake) Family(ctx context.Context,f privateP6Family,rows []privateP6Record)error{
    if f==privateP6USN&&!s.fileDone{return errors.New("FI P10: USN before SQL File commit")}
    return s.privateP6TestSink.Family(ctx,f,rows)
}
func TestPrivateP10FileDependencyWaitsWithoutFlushingOtherFamilies(t *testing.T){
    ctx:=context.Background()
    mock:=&privateP10BarrierFake{}
    b,err:=newPrivateP6Buffers(1,mock)
    if err!=nil{t.Fatal(err)}
    kinds:=[]string{"WindowsSecurityEvent","FileObservation",
        "WindowsSecurityCoverage","USNReadBoundary","USNObjectObservation"}
    b.lanes[privateP6USN].limit.rows=2
    for i,kind:=range kinds{
        if err=b.Add(ctx,privateP6Fixture(1,int64(i+1),kind));err!=nil{t.Fatal(err)}
    }
    if !mock.waited||len(mock.typedRows[privateP6USN])!=2{
        t.Fatal("P10 File SQL completion wasn't awaited before USN")
    }
    if len(mock.typedRows[privateP6Security])!=0||
       len(mock.typedRows[privateP6Coverage])!=0{
        t.Fatal("P10 dependency incorrectly flushed independent family")
    }
    if err=b.Finish(ctx);err!=nil{t.Fatal(err)}
}
func TestPrivateP10NeverSelectsWithoutP6AndPrivateClone(t *testing.T){
    t.Setenv("FI_W512_P6_FAMILY_SQL","1")
    t.Setenv("FI_W512_P10_P6_DIRECT","1")
    t.Setenv("FI_W512_P7_SQL_WRITERS","")
    t.Setenv("FI_W512_P8_REUSE","")
    t.Setenv("FI_W512_P9_DIRECT_STREAM","")
    if !privateP10Enabled(){t.Fatal("P10 private P6 path not selected")}
    t.Setenv("FI_W512_P7_SQL_WRITERS","5")
    if privateP10Enabled(){t.Fatal("P10 incorrectly selected P7 infrastructure")}
    t.Setenv("FI_W512_P7_SQL_WRITERS","")
    t.Setenv("FI_W512_P6_FAMILY_SQL","")
    if privateP10Enabled(){t.Fatal("P10 incorrectly selected without original P6")}
}
func TestPrivateP10ExactBenchmarkStop(t *testing.T){
    t.Setenv("FI_W512_P10_STOP_WINDOWS","2")
    end,err:=privateP10StopIndex(1,20)
    if err!=nil||end!=3{t.Fatalf("P10 prefix end=%d err=%v",end,err)}
    for _,s:=range []string{"0","-1","20","NaN"}{
        t.Setenv("FI_W512_P10_STOP_WINDOWS",s)
        if _,err:=privateP10StopIndex(1,20);err==nil{
            t.Fatalf("P10 accepted invalid window limit %s",s)
        }
    }
}

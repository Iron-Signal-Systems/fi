// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// C1 development correctness gates; no release claims or fake SQL receipts.
package recordingest

import (
    "context"
    "strings"
    "testing"
)

func TestPrivateC1RefusesDirtyPartialOrAlreadyCompletedDestination(t *testing.T){
    cases:=[]struct{
        name string
        markers int64
        sourceRows bool
        pass bool
    }{
        {"new-clean-clone",0,false,true},
        {"partially-committed-source",0,true,false},
        {"completed-marker",1,false,false},
        {"marker-and-partial-source",1,true,false},
        {"invalid-count",-1,false,false},
    }
    for _,tc:=range cases{
        t.Run(tc.name,func(t *testing.T){
            err:=privateC1CleanDestinationStatus(tc.markers,tc.sourceRows)
            if (err==nil)!=tc.pass {
                t.Fatalf("C1 clean-start gate markers=%d source=%v pass=%t err=%v",
                    tc.markers,tc.sourceRows,tc.pass,err)
            }
            if tc.sourceRows && err!=nil && !strings.Contains(err.Error(),"new verified private clone"){
                t.Fatalf("C1 tried to recover a dirty clone: %v",err)
            }
        })
    }
}

func TestPrivateC1PostCommitInjectionNeverSelectableOutsideDevelopment(t *testing.T){
    t.Setenv("FI_C1_DEV_FAIL_AFTER_FILE_SQL_COMMIT","1")
    t.Setenv("FI_W512_C1_P6_DIRECT","")
    t.Setenv("FI_W512_P6_FAMILY_SQL","1")
    if privateC1PostCommitFailpoint(privateP6File){
        t.Fatal("C1 post-commit injection selectable outside C1 private clone")
    }
    t.Setenv("FI_W512_C1_P6_DIRECT","1")
    t.Setenv("FI_W512_P7_SQL_WRITERS","")
    t.Setenv("FI_W512_P8_REUSE","")
    t.Setenv("FI_W512_P9_DIRECT_STREAM","")
    if !privateC1PostCommitFailpoint(privateP6File){
        t.Fatal("C1 post-commit injection unavailable on requested private File lane")
    }
    for f:=privateP6Family(0);f<privateP6FamilyCount;f++{
        if f!=privateP6File && privateC1PostCommitFailpoint(f){
            t.Fatalf("C1 injected into unrelated family %s",privateP6FamilyNames[f])
        }
    }
    t.Setenv("FI_C1_DEV_FAIL_AFTER_FILE_SQL_COMMIT","")
    if privateC1PostCommitFailpoint(privateP6File){
        t.Fatal("C1 failure injection remained selected after being disabled")
    }
}

func TestPrivateC1SourceFlushAndFinalOnlyDoNotDrainAtWindow(t *testing.T){
    ctx:=context.Background()
    sink:=&privateP6TestSink{}
    buffers,err:=newPrivateP6Buffers(1,sink)
    if err!=nil{t.Fatal(err)}
    kinds:=[]string{"WindowsSecurityEvent","FileObservation","WindowsSecurityCoverage",
        "USNReadBoundary","CollectorIdentity"}
    for batch:=1;batch<=4;batch++{
        for i,kind:=range kinds{
            if err=buffers.Add(ctx,privateP6Fixture(batch,int64(i+1),kind));err!=nil{
                t.Fatal(err)
            }
        }
        if len(sink.calls)!=0{
            t.Fatalf("C1 signed batch or artificial window drained unrelated family: %v",sink.calls)
        }
    }
    if err=buffers.Finish(ctx);err!=nil{t.Fatal(err)}
    for i,lane:=range buffers.lanes{
        if lane.records!=4 || len(sink.typedRows[i])!=4{
            t.Fatalf("C1 end-of-input lost %s family records",privateP6FamilyNames[i])
        }
    }
    if buffers.source.records!=20||buffers.total!=20{
        t.Fatalf("C1 signed source/typed mismatch source=%d typed=%d",buffers.source.records,buffers.total)
    }
}

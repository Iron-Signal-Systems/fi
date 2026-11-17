// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
package recordingest

import (
    "context"
    "os"
    "path/filepath"
    "testing"
)

func privateP8Fixture(t *testing.T)(*PreparedGeneration,BacklogWindowLimits,
    BacklogCheckpointDescriptor,string){
    t.Helper()
    t.Setenv("FI_W512_P7_SQL_WRITERS","5")
    t.Setenv("FI_W512_P6_FAMILY_SQL","1")
    t.Setenv("FI_W512_P5_PERSISTENT","1")
    t.Setenv("FI_W512_P8_REUSE","1")
    g:=privateBacklogStageFixture(t)
    root:=privateBacklogTestRoot(t)
    limits:=BacklogWindowLimits{MaxRecords:6,MaxDataBytes:32}
    ds,err:=DescribeBacklogWindows(g,limits)
    if err!=nil || len(ds)!=2 {t.Fatalf("P8 fixture: %v windows=%d",err,len(ds))}
    return g,limits,ds[1],root
}

func TestPrivateP8ExistingSignedArtifactRequiresExactFilesAndManifests(t *testing.T){
    g,limits,d,root:=privateP8Fixture(t)
    if _,err:=privateP8ReusableStage(context.Background(),g,limits,1,root,d);err==nil{
        t.Fatal("P8 accepted nonexistent signed window")
    }
    original,err:=privateP7MaterializeSignedWindow(context.Background(),g,limits,1,root,d)
    if err!=nil{t.Fatal(err)}
    got,err:=privateP8ReusableStage(context.Background(),g,limits,1,root,d)
    if err!=nil || got!=original {
        t.Fatalf("P8 exact signed artifact reuse rejected: %q %v",got,err)
    }
    for _,tc:=range []struct{name,root string;d BacklogCheckpointDescriptor;index int}{
        {name:"foreign-private-root",root:root+"-foreign",d:d,index:1},
        {name:"wrong-window-index",root:root,d:d,index:2},
        {name:"changed-signed-descriptor",root:root,d:func()BacklogCheckpointDescriptor{x:=d;x.DigestSHA256="tampered";return x}(),index:1},
    }{
        t.Run(tc.name,func(t *testing.T){
            if _,err:=privateP8ReusableStage(context.Background(),g,limits,tc.index,tc.root,tc.d);err==nil{
                t.Fatal("P8 accepted mismatched signed stage identity")
            }
        })
    }
    manifest:=filepath.Join(original,"batch-00000002.manifest")
    if err:=os.WriteFile(manifest,[]byte("tampered-manifest"),0600);err!=nil {t.Fatal(err)}
    if _,err:=privateP8ReusableStage(context.Background(),g,limits,1,root,d);err==nil {
        t.Fatal("P8 accepted mutated signed manifest")
    }
}


func TestPrivateP8DeferredCacheWithoutCheckpointMaterializesSignedBytes(t *testing.T){
    g,limits,d,root:=privateP8Fixture(t)
    // Fresh C220 clones have a seed checkpoint at W512=0, but no durable
    // artifact row or physical signed directory yet at W512=1. The
    // branch must NOT require an outer checkpoint to copy signed bytes.
    dir:=filepath.Join(root,"receipt-"+d.ReceiptSHA256,"window-00000001")
    if _,err:=os.Lstat(dir);!os.IsNotExist(err){
        t.Fatalf("P8 fixture unexpectedly materialized W512=1 before retry: %v",err)
    }
    staged,err:=privateP8FreshSignedWindow(context.Background(),g,limits,1,root,d)
    if err!=nil||staged!=dir{
        t.Fatalf("P8 cannot stage missing checkpoint signed bytes: got %q want %q error=%v",staged,dir,err)
    }
    if err:=VerifyMaterializedBacklogWindow(context.Background(),g,limits,1,root);err!=nil{
        t.Fatalf("P8 private materialization did not verify original signed SHA: %v",err)
    }
    if _,err:=privateP8FreshSignedWindow(context.Background(),g,limits,1,root,d);err!=nil{
        t.Fatalf("P8 fresh stage retry cannot verify existing exact file: %v",err)
    }
    bad:=filepath.Join(dir,"batch-00000002.data")
    if err:=os.WriteFile(bad,[]byte("deadbeef"),0600);err!=nil{t.Fatal(err)}
    if _,err:=privateP8FreshSignedWindow(context.Background(),g,limits,1,root,d);err==nil{
        t.Fatal("P8 accepted tampered signed batch on retry without fresh SHA")
    }
}

func TestPrivateP8FreshStageRejectsIncorrectDescriptorAndUnsafeRoot(t *testing.T){
    g,limits,d,root:=privateP8Fixture(t)
    changed:=d
    changed.DigestSHA256="wrong"
    if _,err:=privateP8FreshSignedWindow(context.Background(),g,limits,1,root,changed);err==nil{
        t.Fatal("P8 materialized mismatched signed descriptor")
    }
    if _,err:=privateP8FreshSignedWindow(context.Background(),g,limits,0,root,d);err==nil{
        t.Fatal("P8 materialized seed window through non-seed fast path")
    }
    t.Setenv("FI_W512_P8_REUSE","0")
    if _,err:=privateP8FreshSignedWindow(context.Background(),g,limits,1,root,d);err==nil{
        t.Fatal("P8 materialized signed files without private P8 explicit gate")
    }
}

func TestPrivateP8RequiresPrivateFiveWriterSelection(t *testing.T){
    g,limits,d,root:=privateP8Fixture(t)
    if err:=privateP8CommittedArtifact(context.Background(),nil,d,1);err==nil{
        t.Fatal("P8 accepted absent clone SQL checkpoint connection")
    }
    t.Setenv("FI_W512_P8_REUSE","0")
    if privateP8Selected() {t.Fatal("P8 selected without explicit flag")}
    if _,err:=privateP8ReusableStage(context.Background(),g,limits,1,root,d);err==nil{
        t.Fatal("P8 reused private stage without explicit feature gate")
    }
    t.Setenv("FI_W512_P8_REUSE","1")
    t.Setenv("FI_W512_P7_SQL_WRITERS","0")
    if privateP8Selected(){t.Fatal("P8 selected without five PostgreSQL writers")}
    if err:=privateP8CommittedArtifact(context.Background(),nil,d,1);err==nil{
        t.Fatal("P8 accepted non-five-writer verification path")
    }
}

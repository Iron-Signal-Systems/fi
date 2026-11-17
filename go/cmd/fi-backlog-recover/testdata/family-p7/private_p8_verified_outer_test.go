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

func TestPrivateP8VerifiedOuterArtifactRequiresExactSameProcessEvidence(t *testing.T){
    t.Setenv("FI_W512_P7_SQL_WRITERS","5")
    t.Setenv("FI_W512_P6_FAMILY_SQL","1")
    t.Setenv("FI_W512_P5_PERSISTENT","1")
    g:=privateBacklogStageFixture(t)
    root:=privateBacklogTestRoot(t)
    limits:=BacklogWindowLimits{MaxRecords:6,MaxDataBytes:32}
    ds,err:=DescribeBacklogWindows(g,limits)
    if err!=nil || len(ds)!=2 {t.Fatalf("P8 fixture: %v windows=%d",err,len(ds))}
    d:=ds[1]
    if _,ok,err:=privateP8ReusableStage(context.Background(),g,limits,1,root,d);
       err!=nil || ok {
        t.Fatalf("P8 accepted source without current-process proof: %t %v",ok,err)
    }
    original,err:=privateP7MaterializeSignedWindow(context.Background(),g,limits,1,root,d)
    if err!=nil {t.Fatal(err)}
    ctx,err:=privateP8WithVerifiedOuterArtifact(context.Background(),root,d,1)
    if err!=nil {t.Fatal(err)}
    got,reused,err:=privateP8ReusableStage(ctx,g,limits,1,root,d)
    if err!=nil || !reused || got!=original {
        t.Fatalf("P8 verified artifact reuse rejected: %q %t %v",got,reused,err)
    }
    for _,tc:=range []struct{
        name,root string;d BacklogCheckpointDescriptor;index int
    }{
        {name:"foreign-private-root",root:root+"-foreign",d:d,index:1},
        {name:"wrong-window-index",root:root,d:d,index:2},
        {name:"changed-signed-descriptor",root:root,d:func()BacklogCheckpointDescriptor{x:=d;x.DigestSHA256="tampered";return x}(),index:1},
    }{
        t.Run(tc.name,func(t *testing.T){
            if _,ok,err:=privateP8ReusableStage(ctx,g,limits,tc.index,tc.root,tc.d);
               err==nil || ok {
                t.Fatalf("P8 admitted mismatched same-process proof %t %v",ok,err)
            }
        })
    }
    manifest:=filepath.Join(original,"batch-00000002.manifest")
    if err:=os.WriteFile(manifest,[]byte("tampered-manifest"),0600);err!=nil {t.Fatal(err)}
    if _,ok,err:=privateP8ReusableStage(ctx,g,limits,1,root,d);
       err==nil || ok {
        t.Fatalf("P8 accepted mutated signed manifest: %t %v",ok,err)
    }
}

func TestPrivateP8EvidenceDoesNotChangeOrdinaryP7OrProduction(t *testing.T){
    g:=privateBacklogStageFixture(t)
    root:=privateBacklogTestRoot(t)
    limits:=BacklogWindowLimits{MaxRecords:6,MaxDataBytes:32}
    ds,err:=DescribeBacklogWindows(g,limits)
    if err!=nil || len(ds)!=2 {t.Fatal(err)}
    if _,err:=privateP8WithVerifiedOuterArtifact(context.Background(),root,ds[1],1);err==nil {
        t.Fatal("P8 unsigned/outside-P7 caller minted trusted artifact evidence")
    }
    if privateP8OuterEvidenceMatches(context.Background(),root,ds[1],1) {
        t.Fatal("ordinary source path unexpectedly reused P8 proof")
    }
}

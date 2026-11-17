// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
package main

import ("strings";"testing")

func TestPrivateP8OuterStageOnlyAfterArtifactCheckpoint(t *testing.T){
    src:=`tick=time.Now()
   if err=RecordVerifiedBacklogArtifactWindow(ctx,writer,g,limits,window,privateRoot);err!=nil{return empty,err}
   ledgerDuration:=time.Since(tick)
   tick=time.Now()
   `+edits[0].old+`
   typedDuration:=time.Since(tick)`
    got,err:=rewrite([]byte(src),edits[0])
    if err!=nil {t.Fatal(err)}
    s:=string(got)
    if strings.Count(s,"privateP8WithVerifiedOuterArtifact(")!=1 ||
       strings.Index(s,"privateP8WithVerifiedOuterArtifact(") <
       strings.Index(s,"RecordVerifiedBacklogArtifactWindow(") {
        t.Fatal("P8 evidence minted before or without exact verified artifact handoff")
    }
    if _,err:=rewrite(got,edits[0]);err==nil {
        t.Fatal("P8 duplicate outer source patch accepted")
    }
    if _,err:=rewrite([]byte(strings.Replace(src,"StageBacklogSourceAndTypedWindow","NonexistentStage",1)),edits[0]);err==nil {
        t.Fatal("P8 incompatible private loader accepted")
    }
}
func TestPrivateP8SourceScanCannotBeBypassed(t *testing.T){
    original:=`if err := VerifyMaterializedBacklogWindow(ctx, g, limits, index, privateRoot); err != nil {
        return fmt.Errorf("FI backlog source stage: source copy verification failed: %w", err)
    }
   // unchanged source scanner:
   sourceHash,records,bytes,err:=scanBacklogWindowRecords(ctx,g,d,index,privateRoot,nil)`
    got,err:=rewrite([]byte(original),edits[1])
    if err!=nil{t.Fatal(err)}
    s:=string(got)
    if !strings.Contains(s,"if !privateP8OuterEvidenceMatches(") ||
        strings.Count(s,"VerifyMaterializedBacklogWindow(")!=1 ||
        strings.Count(s,"scanBacklogWindowRecords(")!=1{
        t.Fatal("P8 source scan weakened instead of removing only redundant prehash")
    }
    if _,err:=rewrite(got,edits[1]);err==nil{
        t.Fatal("duplicate artifact scan source patch accepted")
    }
    if _,err:=rewrite([]byte(strings.Replace(original,"source copy verification failed","different error",1)),edits[1]);err==nil{
        t.Fatal("P8 altered source verifier unexpectedly accepted")
    }
}

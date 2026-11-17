// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
package main

import ("strings";"testing")

const p8OuterSourceFixture = `package recordingest
func recoverBacklogVerifiedCachedWindows(
 ctx context.Context,reader,writer *pgx.Conn,g *PreparedGeneration,
 limits BacklogWindowLimits,privateRoot string,startWindow int,
 cacheRoot string,descriptors []BacklogCheckpointDescriptor,
 report func(BacklogContinuousProgress),
)(BacklogGenerationVerification,error){
 var empty BacklogGenerationVerification
 var err error
 for window:=startWindow;window<len(descriptors);window++{
  d:=descriptors[window]
  if _,err=MaterializeBacklogWindow(ctx,g,limits,window,privateRoot);err!=nil{
   return empty,err
  }
  if err=RecordVerifiedBacklogArtifactWindow(ctx,writer,g,limits,window,privateRoot);err!=nil{
   return empty,err
  }
  if err=StageBacklogSourceAndTypedWindow(ctx,reader,writer,g,limits,window,privateRoot);err!=nil{
   return empty,err
  }
  _=d
 }
 verified,err:=VerifyCompleteBacklogTypedGeneration(ctx,reader,g,limits)
 return verified,err
}
`

func TestPrivateP8OuterStageOnlyAfterArtifactCheckpoint(t *testing.T){
    for _,src:=range []string{
        p8OuterSourceFixture,
        strings.ReplaceAll(p8OuterSourceFixture,"  ","\t"),
        strings.Replace(p8OuterSourceFixture,
            "if err=StageBacklogSourceAndTypedWindow(",
            "if err:=StageBacklogSourceAndTypedWindow(",1),
    }{
        got,err:=rewrite([]byte(src),edits[0])
        if err!=nil {t.Fatalf("valid real-source stage formatting rejected: %v",err)}
        s:=string(got)
        if strings.Count(s,"privateP8WithVerifiedOuterArtifact(")!=1 ||
           strings.Count(s,"StageBacklogSourceAndTypedWindow(stageCtx,")!=1 ||
           strings.Index(s,"privateP8WithVerifiedOuterArtifact(") <
           strings.Index(s,"RecordVerifiedBacklogArtifactWindow(") ||
           strings.Count(s,"VerifyCompleteBacklogTypedGeneration(")!=1{
            t.Fatal("P8 proof missing, duplicate, premature or final verified stage removed")
        }
        if _,err:=rewrite(got,edits[0]);err==nil{
            t.Fatal("P8 accepted duplicate source patch")
        }
    }
    for _,invalid:=range []string{
        strings.Replace(p8OuterSourceFixture,"StageBacklogSourceAndTypedWindow(","WrongStage(",1),
        strings.Replace(p8OuterSourceFixture,"MaterializeBacklogWindow(","NotMaterialized(",1),
        strings.Replace(p8OuterSourceFixture,"RecordVerifiedBacklogArtifactWindow(","NoArtifactCheckpoint(",1),
        strings.Replace(p8OuterSourceFixture,"d:=descriptors[window]","_ = descriptors[window]",1),
        strings.Replace(p8OuterSourceFixture,"VerifyCompleteBacklogTypedGeneration(","NoFinalProof(",1),
    }{
        if _,err:=rewrite([]byte(invalid),edits[0]);err==nil{
            t.Fatal("P8 accepted changed original source trust boundary")
        }
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

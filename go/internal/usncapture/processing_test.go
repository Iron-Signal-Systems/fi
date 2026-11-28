// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package usncapture

import (
    "errors"
    "testing"

    "github.com/Iron-Signal-Systems/fi/go/internal/records"
)

func TestOneRawSegmentFansOutToSeveralGovernedRootsWithoutReread(t *testing.T){
    seg:=exampleScopedSegment(t)
    rootA:=scopeTestIdentity("101")
    rootB:=scopeTestIdentity("201")
    a:=GovernedProcessingPlan{ScopeID:"root-a",RootIdentity:rootA,Resolve:func(change records.USNChangeObservation)(ScopeEvidence,error){
        return ScopeEvidence{
            ScopeID:"root-a",JournalID:seg.Batch.JournalID,RootIdentity:rootA,
            FileIdentity:change.FileIdentity,ParentIdentity:change.ParentIdentity,
            EventUSN:change.USN,Class:ScopeGoverned,HistoricalAncestry:true,
            Reason:"RecordedRootAncestry",
        },nil
    }}
    b:=GovernedProcessingPlan{ScopeID:"root-b",RootIdentity:rootB,Resolve:func(records.USNChangeObservation)(ScopeEvidence,error){return ScopeEvidence{},nil}}
    result,err:=BuildVolumeProjections(seg,[]GovernedProcessingPlan{a,b})
    if err!=nil||len(result)!=2{t.Fatalf("multi-root source projection: %+v %v",result,err)}
    if result[0].GovernedRecordCount!=2||result[1].UnresolvedRecordCount!=2||
       result[0].SourceBatchSHA256!=result[1].SourceBatchSHA256||
       result[0].CaptureScopeID!=result[1].CaptureScopeID||
       result[0].GovernedScopeID==result[1].GovernedScopeID{
        t.Fatalf("source event lost, independently reread, or mixed across roots: %+v",result)
    }
}
func TestMultiRootFailureDoesNotCreatePartialProcessingProof(t *testing.T){
    seg:=exampleScopedSegment(t)
    root:=scopeTestIdentity("101")
    marker:=errors.New("historical index corrupt")
    successful:=GovernedProcessingPlan{ScopeID:"root-a",RootIdentity:root,
        Resolve:func(records.USNChangeObservation)(ScopeEvidence,error){return ScopeEvidence{},nil}}
    failing:=GovernedProcessingPlan{ScopeID:"root-b",RootIdentity:root,
        Resolve:func(records.USNChangeObservation)(ScopeEvidence,error){return ScopeEvidence{},marker}}
    output,err:=BuildVolumeProjections(seg,[]GovernedProcessingPlan{successful,failing})
    if !errors.Is(err,marker)||len(output)!=0{
        t.Fatalf("published partial batch despite failed root: %+v %v",output,err)
    }
}
func TestMultiRootDuplicateScopeRejected(t *testing.T){
    seg:=exampleScopedSegment(t)
    r:=GovernedProcessingPlan{ScopeID:"root-a",RootIdentity:scopeTestIdentity("101"),
        Resolve:func(records.USNChangeObservation)(ScopeEvidence,error){return ScopeEvidence{},nil}}
    if _,err:=BuildVolumeProjections(seg,[]GovernedProcessingPlan{r,r});err==nil{
        t.Fatal("duplicate scope would double-send the same source")
    }
}

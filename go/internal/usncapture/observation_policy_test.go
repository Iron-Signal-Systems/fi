// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package usncapture

import (
    "errors"
    "testing"

    "github.com/Iron-Signal-Systems/fi/go/internal/records"
)

func TestSelectiveObservationCoalescesSourceFactsWithoutInventingFileState(t *testing.T){
    seg:=exampleScopedSegment(t)
    root:=scopeTestIdentity("11")
    file:=scopeTestIdentity("22")
    seg.Batch.Records=[]records.USNChangeObservation{
        {FileIdentity:file,ParentIdentity:root,USN:"110",ReasonRaw:"2"},
        {FileIdentity:file,ParentIdentity:root,USN:"120",ReasonRaw:"2147483650"},
        {FileIdentity:file,ParentIdentity:root,USN:"125",ReasonRaw:"2048"},
        {FileIdentity:scopeTestIdentity("33"),ParentIdentity:root,USN:"130",ReasonRaw:"512"},
    }
    plan:=GovernedProcessingPlan{
        ScopeID:"root-test",RootIdentity:root,
        Resolve:DirectRootScopeResolver("root-test",seg.Batch.JournalID,root),
    }
    got,err:=SelectPolicyObservations(seg,[]GovernedProcessingPlan{plan},
        ObservationPolicy{Version:ObservationPolicyVersion,MaxObjectsPerSegment:64})
    if err!=nil{t.Fatal(err)}
    if len(got.Requests)!=1||got.CandidateEvents!=2||
        got.Requests[0].ObjectIdentity!=file||
        len(got.Requests[0].TriggerUSNs)!=2||
        got.Requests[0].TriggerUSNs[0]!="120"||
        got.Requests[0].TriggerUSNs[1]!="125"{
        t.Fatalf("new observation policy rereads per write, drops required changes or reobserves delete: %+v",got)
    }
    if got.DeferredEvents!=2||len(seg.Batch.Records)!=4{
        t.Fatalf("source history was altered or skipped: %+v",got)
    }
}
func TestSelectiveObservationRetainsUnresolvedAndEnforcesBatchLimit(t *testing.T){
    seg:=exampleScopedSegment(t)
    root:=scopeTestIdentity("99")
    for i:=range seg.Batch.Records{
        seg.Batch.Records[i].ReasonRaw="256"
    }
    plan:=GovernedProcessingPlan{
        ScopeID:"root-test",RootIdentity:root,
        Resolve:func(records.USNChangeObservation)(ScopeEvidence,error){return ScopeEvidence{},nil},
    }
    got,err:=SelectPolicyObservations(seg,[]GovernedProcessingPlan{plan},
        ObservationPolicy{Version:ObservationPolicyVersion,MaxObjectsPerSegment:1})
    if err!=nil||got.DistinctCandidates!=1||got.UnresolvedCandidates!=1{
        t.Fatalf("unresolved object was silently interpreted as excluded: %+v %v",got,err)
    }
    seg.Batch.Records[1].FileIdentity=scopeTestIdentity("55")
    if _,err:=SelectPolicyObservations(seg,[]GovernedProcessingPlan{plan},
        ObservationPolicy{Version:ObservationPolicyVersion,MaxObjectsPerSegment:1});!errors.Is(err,ErrCapacity){
        t.Fatalf("batch overrun silently discarded required object: %v",err)
    }
}
func TestSelectiveObservationRejectsUnreviewedPolicyAndUnprovedExclusion(t *testing.T){
    seg:=exampleScopedSegment(t)
    root:=scopeTestIdentity("5")
    plan:=GovernedProcessingPlan{ScopeID:"root-test",RootIdentity:root,
        Resolve:func(c records.USNChangeObservation)(ScopeEvidence,error){
            return ScopeEvidence{Class:ScopeOutside,ScopeID:"root-test",
                JournalID:seg.Batch.JournalID,RootIdentity:root,
                FileIdentity:c.FileIdentity,ParentIdentity:c.ParentIdentity,
                EventUSN:c.USN,HistoricalAncestry:true,CompleteLinkCoverage:true},nil
        },
    }
    if _,err:=SelectPolicyObservations(seg,[]GovernedProcessingPlan{plan},
        ObservationPolicy{Version:ObservationPolicyVersion,MaxObjectsPerSegment:4});err==nil{
        t.Fatal("policy accepted missing durable outside-exclusion witness")
    }
    if _,err:=SelectPolicyObservations(seg,[]GovernedProcessingPlan{plan},
        ObservationPolicy{Version:"unknown",MaxObjectsPerSegment:4});err==nil{
        t.Fatal("policy accepted unknown version")
    }
}

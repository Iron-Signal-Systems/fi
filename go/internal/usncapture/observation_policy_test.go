// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package usncapture

import (
    "crypto/sha256"
    "encoding/hex"
    "encoding/json"
    "errors"
    "testing"

    "github.com/Iron-Signal-Systems/fi/go/internal/records"
)

func TestSelectiveObservationCoalescesSourceFactsWithoutInventingFileState(t *testing.T){
    seg:=exampleScopedSegment(t)
    root:=scopeTestIdentity("11")
    file:=scopeTestIdentity("22")
    // Preserve the fully validated v2 USN source fields from a real-format
    // fixture; only change the original reason, exact identity and USN.
    original:=seg.Batch.Records[0]
    sourceEvent:=func(usn,reason string,id records.NTFSObjectIdentity)records.USNChangeObservation{
        v:=original
        v.FileIdentity=id
        v.ParentIdentity=root
        v.USN=usn
        v.ReasonRaw=reason
        return v
    }
    seg.Batch.Records=[]records.USNChangeObservation{
        sourceEvent("110","2",file),
        sourceEvent("120","2147483650",file),
        sourceEvent("125","2048",file),
        sourceEvent("130","512",scopeTestIdentity("33")),
    }
    rehashObservationPolicyFixture(t,&seg)
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
    rehashObservationPolicyFixture(t,&seg)
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
    rehashObservationPolicyFixture(t,&seg)
    if _,err:=SelectPolicyObservations(seg,[]GovernedProcessingPlan{plan},
        ObservationPolicy{Version:ObservationPolicyVersion,MaxObjectsPerSegment:1});!errors.Is(err,ErrCapacity){
        t.Fatalf("batch overrun silently discarded required object: %v",err)
    }
}
func TestSelectiveObservationRejectsUnreviewedPolicyAndUnprovedExclusion(t *testing.T){
    seg:=exampleScopedSegment(t)
    root:=scopeTestIdentity("5")
    rehashObservationPolicyFixture(t,&seg)
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

// Synthetic tests may change source records ONLY after recomputing the
// fixture digest. Production observes the Store.Next SHA-256; the policy
// independently refuses to trust any changed raw source or reason bits.
func rehashObservationPolicyFixture(t *testing.T,seg *Segment){
    t.Helper()
    raw,err:=json.Marshal(seg.Batch);if err!=nil{t.Fatal(err)}
    hash:=sha256.Sum256(raw)
    seg.SHA256=hex.EncodeToString(hash[:])
}

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package usncapture

import (
    "crypto/sha256"
    "encoding/hex"
    "encoding/json"
    "errors"
    "fmt"
    "strconv"

    "github.com/Iron-Signal-Systems/fi/go/internal/records"
)

const (
    ObservationPolicyVersion="fi-usn-selective-observation/1"
    obsReasonDataOverwrite uint64=0x00000001
    obsReasonDataExtend uint64=0x00000002
    obsReasonDataTruncate uint64=0x00000004
    obsReasonNamedData uint64=0x00000070
    obsReasonEAChange uint64=0x00000400
    obsReasonSecurityChange uint64=0x00000800
    obsReasonRenameNew uint64=0x00002000
    obsReasonBasicInfo uint64=0x00008000
    obsReasonHardLink uint64=0x00010000
    obsReasonStream uint64=0x00200000
    obsReasonClose uint64=0x80000000
    obsReasonCreate uint64=0x00000100
    obsReasonDelete uint64=0x00000200
)

type ObservationPolicy struct {
    Version string
    MaxObjectsPerSegment int
}

// SelectedObjectObservation is a plan for a real, independently timed NTFS
// read. TriggerUSNs are historical original USN facts; they are NOT evidence
// of file content, security or an observation timestamp at those USNs.
type SelectedObjectObservation struct {
    RootScopeID string
    RootIdentity records.NTFSObjectIdentity
    ObjectIdentity records.NTFSObjectIdentity
    SourceBatchSHA256 string
    CaptureScopeID string
    JournalID string
    StartUSN string
    NextUSN string
    CapturedAt string
    TriggerUSNs []string
    HistoricalClass ScopeClass
}

type ObservationSelection struct {
    Requests []SelectedObjectObservation
    CandidateEvents int
    DeferredEvents int
    UnresolvedCandidates int
    DistinctCandidates int
}

// SelectPolicyObservations never touches NTFS. Every source USN is preserved
// in the separate captured segment, whether or not an NTFS observation is
// selected. Content changes are selected after Close to avoid hashing a file
// on each DataExtend; identity/security/stream changes select immediately.
// FileDelete is source-only, never a fake successful current-state read.
// Unknown scope may still be currently governed, so it is a candidate and
// must be validated using live handle containment by a separate worker.
func SelectPolicyObservations(
    seg Segment,roots []GovernedProcessingPlan,policy ObservationPolicy,
)(ObservationSelection,error){
    if policy.Version!=ObservationPolicyVersion ||
        policy.MaxObjectsPerSegment<=0 || policy.MaxObjectsPerSegment>65536 {
        return ObservationSelection{},errors.New("FI selective NTFS policy must be versioned and bounded")
    }
    if len(roots)==0{return ObservationSelection{},errors.New("FI independent observation requires governed roots")}
    if seg.SHA256=="" || seg.Name!=segmentNameMust(seg.Batch.StartUSN){
        return ObservationSelection{},errors.New("FI observation must refer to an immutable original source")
    }
    if err:=validateBatch(seg.Batch);err!=nil{
        return ObservationSelection{},fmt.Errorf("%w: observation original source format: %v",ErrCorrupt,err)
    }
    raw,err:=json.Marshal(seg.Batch)
    if err!=nil{return ObservationSelection{},err}
    digest:=sha256.Sum256(raw)
    if hex.EncodeToString(digest[:])!=seg.SHA256{
        return ObservationSelection{},fmt.Errorf("%w: observation source batch SHA-256 mismatch",ErrCorrupt)
    }
    result:=ObservationSelection{Requests:make([]SelectedObjectObservation,0,64)}
    for _,root:=range roots{
        scope,err:=SelectCapturedScope(seg.Batch,root.ScopeID,root.RootIdentity,root.Resolve)
        if err!=nil{return ObservationSelection{},err}
        if scope.Excluded>0{
            return ObservationSelection{},errors.New("FI selective observations cannot trust unpersisted negative scope exclusion")
        }
        index:=map[records.NTFSObjectIdentity]int{}
        for _,entry:=range scope.Included{
            change:=entry.Source
            reason,err:=strconv.ParseUint(change.ReasonRaw,10,32)
            if err!=nil{return ObservationSelection{},fmt.Errorf("invalid USN observation reason %s: %w",change.USN,err)}
            // Create and metadata/security/link changes can trigger immediately;
            // content-only changes trigger after the handle closes. The entire
            // stream remains in the SoR for later policy changes/reconciliation.
            immediate:=reason&(obsReasonCreate|obsReasonSecurityChange|obsReasonRenameNew|
                obsReasonBasicInfo|obsReasonHardLink|obsReasonEAChange|obsReasonStream)!=0
            content:=reason&(obsReasonDataOverwrite|obsReasonDataExtend|
                obsReasonDataTruncate|obsReasonNamedData)!=0
            selectNow:=(immediate || (content && reason&obsReasonClose!=0)) &&
                reason&obsReasonDelete==0
            if !selectNow {
                result.DeferredEvents++
                continue
            }
            result.CandidateEvents++
            identity:=change.FileIdentity
            if pos,ok:=index[identity];ok{
                result.Requests[pos].TriggerUSNs=append(result.Requests[pos].TriggerUSNs,change.USN)
                if entry.Class==ScopeUnresolved{result.Requests[pos].HistoricalClass=ScopeUnresolved}
                continue
            }
            if len(result.Requests)>=policy.MaxObjectsPerSegment{
                // Fail closed: don't return partial work that could advance
                // an observation cursor while selected objects were lost.
                return ObservationSelection{},fmt.Errorf("%w: observation candidates exceed max=%d",
                    ErrCapacity,policy.MaxObjectsPerSegment)
            }
            request:=SelectedObjectObservation{
                RootScopeID:root.ScopeID,RootIdentity:root.RootIdentity,
                ObjectIdentity:identity,
                SourceBatchSHA256:seg.SHA256,CaptureScopeID:seg.Batch.ScopeID,
                JournalID:seg.Batch.JournalID,StartUSN:seg.Batch.StartUSN,
                NextUSN:seg.Batch.NextUSN,CapturedAt:seg.Batch.ObservedAt,
                TriggerUSNs:[]string{change.USN},HistoricalClass:entry.Class,
            }
            if entry.Class==ScopeUnresolved{result.UnresolvedCandidates++}
            index[identity]=len(result.Requests)
            result.Requests=append(result.Requests,request)
        }
    }
    result.DistinctCandidates=len(result.Requests)
    return result,nil
}

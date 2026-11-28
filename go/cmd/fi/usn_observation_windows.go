// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package main

import (
    "context"
    "errors"
    "fmt"
    "reflect"

    "github.com/Iron-Signal-Systems/fi/go/internal/records"
    "github.com/Iron-Signal-Systems/fi/go/internal/spool"
    "github.com/Iron-Signal-Systems/fi/go/internal/usncapture"
    "github.com/Iron-Signal-Systems/fi/go/internal/windows/ntfs"
)

type independentNTFSReader func(
    context.Context,string,string,records.NTFSObjectIdentity,
)(spooledFileObservation,error)

// observeCurrentSelectedNTFS is deliberately separate from the fast raw USN
// owner. It opens the object by exact NTFS file ID through the existing
// governed-root collector, which separately validates CURRENT containment,
// metadata, ACL, ADS and content hashes. Historical source facts are NOT
// reinterpreted as a snapshot at their event timestamp.
func observeCurrentSelectedNTFS(
    ctx context.Context,scope,governedRoot string,
    identity records.NTFSObjectIdentity,
)(spooledFileObservation,error){
    value,err:=ntfs.CollectFileReference(ctx,scope,governedRoot,identity)
    if err!=nil{return spooledFileObservation{},err}
    if value.ContentHashes==nil{
        return spooledFileObservation{},errors.New("FI independent NTFS observation has no file content hash facts")
    }
    hash:=*value.ContentHashes
    if err:=records.ValidateContentHashObservation(hash);err!=nil{return spooledFileObservation{},err}
    if hash.State==records.ContentHashError{
        return spooledFileObservation{},errors.New("FI independently observed NTFS file has explicit hashing failure")
    }
    if err:=ntfs.ValidateObservation(value);err!=nil{return spooledFileObservation{},err}
    value.ContentHashes=nil
    return spooledFileObservation{NTFS:value,ContentHashes:hash},nil
}

// processIndependentNTFSObservationsOnce consumes ONE already durably captured
// source segment through a THIRD independent cursor, never the journal or
// scoped-source cursor. It can be scheduled at a deliberately slower rate.
// A missing/deleted/moved/inaccessible file remains an explicit failure and
// cannot produce a fabricated FileObservation or advance its observation
// cursor. A separate outcome record/receiver contract is required before
// those statuses can be accepted instead of held for recovery.
func processIndependentNTFSObservationsOnce(
    ctx context.Context,source *usncapture.Store,
    observations *usncapture.ObservationLedger,
    roots []usncapture.GovernedProcessingPlan,
    governedPaths map[string]string,
    spoolDir string,collector spool.CollectorIdentity,
    policy usncapture.ObservationPolicy,read independentNTFSReader,
)(bool,error){
    if ctx==nil||source==nil||observations==nil||len(roots)==0||
        governedPaths==nil||spoolDir==""||read==nil{
        return false,errors.New("FI independent NTFS observation worker is incomplete")
    }
    if err:=ctx.Err();err!=nil{return false,err}
    seg,ok,err:=observations.Next()
    if err!=nil||!ok{return false,err}
    selection,err:=usncapture.SelectPolicyObservations(seg,roots,policy)
    if err!=nil{return false,err}
    if len(selection.Requests)==0{
        proof,err:=usncapture.VerifyNoWorkObservationProof(seg,roots,policy)
        if err!=nil{return false,err}
        if err:=observations.CommitObservation(seg,proof);err!=nil{return false,err}
        return true,nil
    }
    // Perform actual slow NTFS File-ID observations WITHOUT a spool intent.
    // None is publishable until every required selected object completed.
    // A failure here is retryable and cannot create a duplicate sender batch.
    writer,err:=spool.NewWriter(spoolDir,spool.DefaultBatchSize,collector)
    if err!=nil{return false,err}
    expected:=make([]usncapture.PublishedNTFSObservation,0,len(selection.Requests))
    for _,request:=range selection.Requests{
        if err:=ctx.Err();err!=nil{_ =writer.Abandon();return false,err}
        path:=governedPaths[request.RootScopeID]
        if path==""{
            _=writer.Abandon()
            return false,fmt.Errorf("missing governed source path for scope %s",request.RootScopeID)
        }
        actual,err:=read(ctx,request.RootScopeID,path,request.ObjectIdentity)
        if err!=nil{
            _=writer.Abandon()
            return false,fmt.Errorf(
                "actual selective NTFS read unavailable scope=%s volume=%s source=%s:%s object=%s/%s: %w",
                request.RootScopeID,request.CaptureScopeID,request.StartUSN,request.NextUSN,
                request.ObjectIdentity.FileReferenceNumber,request.ObjectIdentity.SequenceNumber,err)
        }
        if actual.NTFS.ObjectIdentity!=request.ObjectIdentity ||
            actual.NTFS.GovernedRoot.ScopeID!=request.RootScopeID ||
            actual.NTFS.GovernedRoot.ObjectIdentity!=request.RootIdentity ||
            !reflect.DeepEqual(actual.NTFS.VolumeIdentity,seg.Batch.VolumeIdentity){
            _=writer.Abandon()
            return false,errors.New("FI independent NTFS read changed exact governed object or NTFS volume")
        }
        expected=append(expected,usncapture.PublishedNTFSObservation{
            ScopeID:request.RootScopeID,Payload:actual,
        })
    }
    // New spool bytes are prohibited until this exact source-bound intent
    // is durable. A crash in the later ambiguous window must never silently
    // execute the object observation again and republish duplicates.
    if err:=observations.BeginObservationPublication(seg);err!=nil{
        _=writer.Abandon()
        return false,err
    }
    for _,entry:=range expected{
        if err:=ctx.Err();err!=nil{_ =writer.Abandon();return false,err}
        if err:=writer.Append("FileObservation",entry.ScopeID,entry.Payload);err!=nil{
            _=writer.Abandon()
            return false,fmt.Errorf("publish original independent FI NTFS fact: %w",err)
        }
    }
    if err:=writer.Close();err!=nil{return false,err}
    proof,err:=usncapture.VerifyObservationPublication(seg,expected,writer.FinalizedBatches())
    if err!=nil{return false,err}
    if err:=ctx.Err();err!=nil{return false,err}
    if err:=observations.CommitObservation(seg,proof);err!=nil{return false,err}
    return true,nil
}

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package main

import (
    "context"
    "errors"
    "fmt"

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
// A missing/deleted/moved/inaccessible file becomes an explicit source-bound
// Unavailable/Outside/Error outcome, not a fabricated successful FileObservation.
// All selected source facts are spool-verified before its cursor advances.
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
        actual,readErr:=read(ctx,request.RootScopeID,path,request.ObjectIdentity)
        // Context cancellation is control flow, never a permanent journal
        // fact or a spurious unavailable NTFS result.
        if ctx.Err()!=nil{
            _=writer.Abandon()
            return false,ctx.Err()
        }
        outcome,err:=makeUSNSelectiveOutcome(request,seg.Batch.VolumeIdentity,actual,readErr)
        if err!=nil{
            _=writer.Abandon()
            return false,fmt.Errorf("construct verified independent source outcome: %w",err)
        }
        expected=append(expected,usncapture.PublishedNTFSObservation{
            ScopeID:request.RootScopeID,Payload:outcome,
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
        if err:=writer.Append("USNSelectiveObservation",entry.ScopeID,entry.Payload);err!=nil{
            _=writer.Abandon()
            return false,fmt.Errorf("publish original source-bound FI NTFS observation outcome: %w",err)
        }
    }
    if err:=writer.Close();err!=nil{return false,err}
    proof,err:=usncapture.VerifyObservationPublication(seg,expected,writer.FinalizedBatches())
    if err!=nil{return false,err}
    if err:=ctx.Err();err!=nil{return false,err}
    if err:=observations.CommitObservation(seg,proof);err!=nil{return false,err}
    return true,nil
}

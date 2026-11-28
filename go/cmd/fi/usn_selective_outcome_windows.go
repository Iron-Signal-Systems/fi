// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package main

import (
    "errors"
    "fmt"
    "syscall"
    "time"

    "github.com/Iron-Signal-Systems/fi/go/internal/records"
    "github.com/Iron-Signal-Systems/fi/go/internal/usncapture"
    "github.com/Iron-Signal-Systems/fi/go/internal/windows/ntfs"
)

const usnSelectiveOutcomeVersion = "fi-usn-selective-observation/1"

// EXACT same signed wire contract as backend-usn. This is CURRENT NTFS
// evidence explicitly tied to one original USN batch, never an assertion
// that the file's present bytes existed at the triggering historical USN.
type usnSelectiveOutcome struct {
    Version string `json:"version"`
    CaptureScopeID string `json:"capture_scope_id"`
    GovernedScopeID string `json:"governed_scope_id"`
    JournalID string `json:"journal_id"`
    VolumeIdentity records.VolumeIdentity `json:"volume_identity"`
    RootIdentity records.NTFSObjectIdentity `json:"root_identity"`
    FileIdentity records.NTFSObjectIdentity `json:"file_identity"`
    SourceBatchSHA256 string `json:"source_batch_sha256"`
    StartUSN string `json:"start_usn"`
    NextUSN string `json:"next_usn"`
    TriggerUSNs []string `json:"trigger_usns"`
    ObservedAt string `json:"observed_at"`
    Status string `json:"status"`
    ReasonCode string `json:"reason_code,omitempty"`
    Error string `json:"error,omitempty"`
    NTFS *ntfs.Observation `json:"ntfs_observation,omitempty"`
    ContentHashes *records.ContentHashObservation `json:"content_hashes,omitempty"`
}

func classifyCurrentNTFSOutcome(err error)(string,string,string){
    if err==nil{return "Observed","",""}
    if errors.Is(err,ntfs.ErrOutsideGovernedRoot){
        return "OutsideGovernedRoot","CurrentHandleOutsideGovernedRoot",""
    }
    var stage *ntfs.Error
    if errors.As(err,&stage)&&stage.Stage==ntfs.StageOpen&&stage.Op=="OpenFileById"&&
        (errors.Is(err,syscall.ERROR_FILE_NOT_FOUND)||
            errors.Is(err,syscall.ERROR_PATH_NOT_FOUND)||
            errors.Is(err,syscall.Errno(87))){
        return "Unavailable","OriginalFileIDNoLongerExists",""
    }
    description:=err.Error()
    if len(description)>4096{description=description[:4096]}
    return "Error","CurrentNTFSFileIDObservationFailed",description
}

func makeUSNSelectiveOutcome(
    request usncapture.SelectedObjectObservation,
    volume records.VolumeIdentity,
    actual spooledFileObservation,readErr error,
)(usnSelectiveOutcome,error){
    if request.RootScopeID==""||request.CaptureScopeID==""||
        request.SourceBatchSHA256==""||len(request.TriggerUSNs)==0||
        request.StartUSN==""||request.NextUSN==""{
        return usnSelectiveOutcome{},errors.New("FI selective observation lacks original USN source proof")
    }
    status,reason,text:=classifyCurrentNTFSOutcome(readErr)
    outcome:=usnSelectiveOutcome{
        Version:usnSelectiveOutcomeVersion,CaptureScopeID:request.CaptureScopeID,
        GovernedScopeID:request.RootScopeID,JournalID:request.JournalID,
        VolumeIdentity:volume,RootIdentity:request.RootIdentity,
        FileIdentity:request.ObjectIdentity,SourceBatchSHA256:request.SourceBatchSHA256,
        StartUSN:request.StartUSN,NextUSN:request.NextUSN,
        TriggerUSNs:append([]string(nil),request.TriggerUSNs...),
        ObservedAt:time.Now().UTC().Format(time.RFC3339Nano),
        Status:status,ReasonCode:reason,Error:text,
    }
    if readErr==nil{
        if actual.NTFS.ObjectIdentity!=request.ObjectIdentity ||
            actual.NTFS.GovernedRoot.ScopeID!=request.RootScopeID ||
            actual.NTFS.GovernedRoot.ObjectIdentity!=request.RootIdentity ||
            actual.NTFS.VolumeIdentity!=volume {
            return usnSelectiveOutcome{},errors.New("FI selective NTFS observation changed original source identity")
        }
        if actual.NTFS.ObservedAt==""{
            return usnSelectiveOutcome{},errors.New("FI selective observed file missing source observation timestamp")
        }
        if err:=records.ValidateContentHashObservation(actual.ContentHashes);err!=nil{return usnSelectiveOutcome{},err}
        if actual.ContentHashes.State==records.ContentHashError{
            return usnSelectiveOutcome{},errors.New("FI selective observed NTFS content hashes are in Error state")
        }
        outcome.NTFS=&actual.NTFS
        outcome.ContentHashes=&actual.ContentHashes
        outcome.ObservedAt=actual.NTFS.ObservedAt
    }else if status=="Observed"{
        return usnSelectiveOutcome{},fmt.Errorf("FI selective status observed after failed OS read: %w",readErr)
    }
    return outcome,nil
}

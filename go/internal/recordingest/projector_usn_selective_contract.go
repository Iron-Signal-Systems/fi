// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// Development-only pending C1 relational migration/acceptance. A policy-
// selected CURRENT File-ID observation is NOT a historical USN event or a
// source-only USNScopedCapture. No canonical schema or running SoR changed.
package recordingest

import (
    "crypto/sha256"
    "encoding/hex"
    "errors"
    "fmt"
    "strings"
    "time"

    "github.com/Iron-Signal-Systems/fi/go/internal/records"
    "github.com/Iron-Signal-Systems/fi/go/internal/windows/ntfs"
)

const usnSelectiveObservationVersion="fi-usn-selective-observation/1"

// The eventual independently-scheduled Windows sender record. It references
// the original immutable USN source by volume/journal/range/SHA and governed
// root, but NEVER claims a fresh file's metadata was true at the USN's event
// timestamp. Unavailable and current-outside are evidence outcomes, NOT
// historical outside-scope exclusion or fabricated FileObservation records.
type usnSelectiveObservationPayload struct {
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
func validateUSNSelectiveObservation(scopeID string,v usnSelectiveObservationPayload)error{
    if v.Version!=usnSelectiveObservationVersion || scopeID=="" ||
        v.GovernedScopeID!=scopeID || v.CaptureScopeID==""{
        return errors.New("FI independent USN observation version/scope mismatch")
    }
    if err:=records.ValidateVolumeIdentity(v.VolumeIdentity);err!=nil{return err}
    canonical:="fi-volume-usn-capture/1\x00"+v.VolumeIdentity.MethodVersion+"\x00"+
        strings.ToLower(v.VolumeIdentity.VolumeGUID)+"\x00"+v.VolumeIdentity.VolumeSerial
    digest:=sha256.Sum256([]byte(canonical))
    if v.CaptureScopeID!="volume-"+hex.EncodeToString(digest[:16]){
        return errors.New("FI independent USN observation changed original volume identity")
    }
    if err:=records.ValidateNTFSObjectIdentity(v.RootIdentity);err!=nil{return err}
    if err:=records.ValidateNTFSObjectIdentity(v.FileIdentity);err!=nil{return err}
    if _,err:=strictScopedDecimal(v.JournalID);err!=nil{return err}
    start,err:=strictScopedDecimal(v.StartUSN)
    if err!=nil{return err}
    end,err:=strictScopedDecimal(v.NextUSN)
    if err!=nil||end<=start{return errors.New("FI independent observation requires advancing original USN interval")}
    if len(v.SourceBatchSHA256)!=64 ||
        strings.ToLower(v.SourceBatchSHA256)!=v.SourceBatchSHA256{
        return errors.New("FI independent observation source SHA-256 is noncanonical")
    }
    sourceSHA,err:=hex.DecodeString(v.SourceBatchSHA256)
    if err!=nil||len(sourceSHA)!=32{return errors.New("FI independent observation original source SHA-256 invalid")}
    if _,err:=time.Parse(time.RFC3339Nano,v.ObservedAt);err!=nil{
        return fmt.Errorf("FI independent observation timestamp invalid: %w",err)
    }
    if len(v.TriggerUSNs)==0||len(v.TriggerUSNs)>65536{
        return errors.New("FI independent observation trigger evidence missing or unbounded")
    }
    var last uint64
    for i,trigger:=range v.TriggerUSNs{
        n,err:=strictScopedDecimal(trigger)
        if err!=nil||n<start||n>=end||i>0&&n<last{
            return fmt.Errorf("FI independent observation trigger %d outside ordered source interval",i)
        }
        last=n
    }
    switch v.Status{
    case "Observed":
        if v.ReasonCode!=""||v.Error!=""||v.NTFS==nil||v.ContentHashes==nil{
            return errors.New("FI observed NTFS result missing exact file snapshot or carries invented failure")
        }
        observed:=*v.NTFS
        if observed.ObjectIdentity!=v.FileIdentity||
            observed.GovernedRoot.ObjectIdentity!=v.RootIdentity||
            observed.GovernedRoot.ScopeID!=scopeID||
            observed.VolumeIdentity!=v.VolumeIdentity||
            observed.ObservedAt!=v.ObservedAt{
            return errors.New("FI independent NTFS snapshot differs from original source/root/object")
        }
        observed.ContentHashes=v.ContentHashes
        if err:=ntfs.ValidateObservation(observed);err!=nil{return err}
        if v.ContentHashes.State==records.ContentHashError{
            return errors.New("FI observed NTFS snapshot cannot claim successful hashing after error")
        }
    case "Unavailable","OutsideGovernedRoot","Error":
        if v.ReasonCode=="" || len(v.ReasonCode)>256 ||
            len(v.Error)>4096 || v.NTFS!=nil||v.ContentHashes!=nil {
            return errors.New("FI nonobserved status cannot fabricate current NTFS file/hash facts")
        }
    default:
        return fmt.Errorf("FI unsupported independent NTFS observation status %q",v.Status)
    }
    return nil
}

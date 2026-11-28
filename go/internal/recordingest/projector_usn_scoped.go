// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package recordingest

import (
    "context"
    "crypto/sha256"
    "encoding/base64"
    "encoding/hex"
    "errors"
    "fmt"
    "strconv"
    "strings"
    "time"

    "github.com/Iron-Signal-Systems/fi/go/internal/records"
    "github.com/jackc/pgx/v5"
)

// This source-fact contract is intentionally separate from USNObjectObservation.
// It makes NO claim that the original NTFS object was re-opened or hashed.
// The same contract version belongs in the Windows-only producer branch.
const usnScopedCaptureVersion = "fi-usn-scoped-projection/1"

type usnScopedChangePayload struct {
    Source records.USNChangeObservation `json:"source"`
    Class string `json:"class"`
    Reason string `json:"reason"`
}

type usnScopedCapturePayload struct {
    Version string `json:"version"`
    CaptureScopeID string `json:"capture_scope_id"`
    GovernedScopeID string `json:"governed_scope_id"`
    RootIdentity records.NTFSObjectIdentity `json:"root_identity"`
    CapturedAt string `json:"captured_at"`
    CollectionMethod string `json:"collection_method"`
    JournalID string `json:"journal_id"`
    VolumeIdentity records.VolumeIdentity `json:"volume_identity"`
    StartUSN string `json:"start_usn"`
    NextUSN string `json:"next_usn"`
    SourceBatchSHA256 string `json:"source_batch_sha256"`
    SourceRecordCount int `json:"source_record_count"`
    IncludedRecordCount int `json:"included_record_count"`
    ProvenOutsideRecordCount int `json:"proven_outside_record_count"`
    UnresolvedRecordCount int `json:"unresolved_record_count"`
    GovernedRecordCount int `json:"governed_record_count"`
    Included []usnScopedChangePayload `json:"included"`
}

func strictScopedDecimal(value string) (uint64,error) {
    if value == "" || len(value)>1 && value[0]=='0' { return 0,errors.New("noncanonical USN decimal") }
    for _,c:=range value { if c<'0'||c>'9' {return 0,errors.New("invalid USN decimal")} }
    return strconv.ParseUint(value,10,64)
}

// The v1 scoped format does not admit any excluded records: a separate
// independently verifiable negative-proof ledger is a future acceptance gate.
func validateUSNScopedCapture(scopeID string, v usnScopedCapturePayload) error {
    if scopeID=="" || v.GovernedScopeID!=scopeID || v.Version!=usnScopedCaptureVersion ||
        len(v.CaptureScopeID)!=39 || !strings.HasPrefix(v.CaptureScopeID,"volume-") {
        return errors.New("FI scoped USN source/scope/version mismatch")
    }
    if _,err:=hex.DecodeString(v.CaptureScopeID[len("volume-"):]);err!=nil{
        return fmt.Errorf("invalid volume capture scope digest: %w",err)
    }
    if v.CollectionMethod!=records.WindowsUSNCollectionMethod {
        return errors.New("unsupported scoped USN collection method")
    }
    if err:=records.ValidateVolumeIdentity(v.VolumeIdentity);err!=nil{return err}
    canonicalVolume := "fi-volume-usn-capture/1\\x00" + v.VolumeIdentity.MethodVersion + "\\x00" +
        strings.ToLower(v.VolumeIdentity.VolumeGUID) + "\\x00" + v.VolumeIdentity.VolumeSerial
    sum:=sha256.Sum256([]byte(canonicalVolume))
    if v.CaptureScopeID != "volume-"+hex.EncodeToString(sum[:16]){
        return errors.New("FI scoped capture identity does not match exact NTFS volume")
    }
    if err:=records.ValidateNTFSObjectIdentity(v.RootIdentity);err!=nil{return err}
    if _,err:=time.Parse(time.RFC3339Nano,v.CapturedAt);err!=nil{return fmt.Errorf("invalid capture timestamp: %w",err)}
    start,err:=strictScopedDecimal(v.StartUSN);if err!=nil{return err}
    end,err:=strictScopedDecimal(v.NextUSN);if err!=nil||end<=start{return errors.New("nonadvancing scoped USN range")}
    if _,err:=strictScopedDecimal(v.JournalID);err!=nil{return err}
    digest,err:=hex.DecodeString(v.SourceBatchSHA256)
    if err!=nil||len(digest)!=32{return errors.New("scoped source batch digest must be SHA-256")}
    if v.ProvenOutsideRecordCount!=0 || v.SourceRecordCount<0 || v.GovernedRecordCount<0 ||
        v.UnresolvedRecordCount<0 || v.IncludedRecordCount<0 ||
        v.IncludedRecordCount!=len(v.Included) ||
        v.SourceRecordCount!=v.IncludedRecordCount ||
        v.GovernedRecordCount+v.UnresolvedRecordCount!=v.IncludedRecordCount {
        return errors.New("FI scoped USN record conservation failed")
    }
    governed,unresolved:=0,0
    for i,entry:=range v.Included{
        if err:=records.ValidateUSNChangeObservation(entry.Source);err!=nil{
            return fmt.Errorf("validate scoped USN event %d: %w",i,err)
        }
        pos,err:=strictScopedDecimal(entry.Source.USN)
        if err!=nil||pos<start||pos>=end{return fmt.Errorf("scoped source event %d outside original journal interval",i)}
        switch entry.Class{
        case "Governed": governed++
        case "Unresolved": unresolved++
        default: return fmt.Errorf("unsupported scoped event class at %d",i)
        }
        if len(entry.Reason)>1024{return errors.New("oversized scoped event reason")}
    }
    if governed!=v.GovernedRecordCount||unresolved!=v.UnresolvedRecordCount{
        return errors.New("scoped event classification count mismatch")
    }
    return nil
}

// projectUSNScopedCapture inserts only original journal facts. A separate
// policy-driven FileObservation may be projected later, never synthesized here.
func projectUSNScopedCapture(ctx context.Context,tx pgx.Tx,sourceID string,sourceRecordID int64,scopeID string,v usnScopedCapturePayload) error{
    if ctx==nil||tx==nil||sourceID==""||sourceRecordID<=0{return errors.New("invalid USN scoped projection context")}
    if err:=validateUSNScopedCapture(scopeID,v);err!=nil{return err}
    volumeID,err:=ensureNTFSVolume(ctx,tx,sourceID,v.VolumeIdentity);if err!=nil{return err}
    rootID,err:=ensureNTFSObject(ctx,tx,volumeID,v.RootIdentity);if err!=nil{return err}
    capturedAt,_:=time.Parse(time.RFC3339Nano,v.CapturedAt)
    digest,_:=hex.DecodeString(v.SourceBatchSHA256)
    _,err=tx.Exec(ctx,`
INSERT INTO fi.usn_scoped_capture
 (source_record_id,captured_at,collection_method,capture_scope_id,governed_scope_id,
  ntfs_volume_id,root_ntfs_object_id,journal_id,start_usn,next_usn,
  source_batch_sha256,source_record_count,included_record_count,
  governed_record_count,unresolved_record_count,proven_outside_record_count)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8::numeric,$9::numeric,$10::numeric,
        $11,$12,$13,$14,$15,$16)`,
        sourceRecordID,capturedAt,v.CollectionMethod,v.CaptureScopeID,scopeID,
        volumeID,rootID,v.JournalID,v.StartUSN,v.NextUSN,digest,
        v.SourceRecordCount,v.IncludedRecordCount,v.GovernedRecordCount,
        v.UnresolvedRecordCount,v.ProvenOutsideRecordCount)
    if err!=nil{return fmt.Errorf("insert FI scoped USN capture: %w",err)}
    for index,entry:=range v.Included{
        fileID,err:=ensureNTFSObject(ctx,tx,volumeID,entry.Source.FileIdentity)
        if err!=nil{return err}
        parentID,err:=ensureNTFSObject(ctx,tx,volumeID,entry.Source.ParentIdentity)
        if err!=nil{return err}
        timestamp,err:=time.Parse(time.RFC3339Nano,entry.Source.Timestamp)
        if err!=nil{return err}
        filename,err:=base64.RawURLEncoding.DecodeString(entry.Source.FileNameUTF16LEBase64URL)
        if err!=nil{return err}
        minor,err:=strconv.ParseUint(entry.Source.MinorVersion,10,15);if err!=nil{return err}
        reason,err:=strconv.ParseUint(entry.Source.ReasonRaw,10,32);if err!=nil{return err}
        sourceInfo,err:=strconv.ParseUint(entry.Source.SourceInfoRaw,10,32);if err!=nil{return err}
        security,err:=strconv.ParseUint(entry.Source.SecurityID,10,32);if err!=nil{return err}
        attributes,err:=strconv.ParseUint(entry.Source.FileAttributesRaw,10,32);if err!=nil{return err}
        _,err=tx.Exec(ctx,`
INSERT INTO fi.usn_scoped_change
 (source_record_id,change_ordinal,file_ntfs_object_id,parent_ntfs_object_id,
  usn,event_timestamp,major_version,minor_version,scope_class,scope_reason,
  reason_raw,source_info_raw,security_id,file_attributes_raw,file_name_utf16le)
VALUES ($1,$2,$3,$4,$5::numeric,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`,
            sourceRecordID,index+1,fileID,parentID,entry.Source.USN,timestamp,
            2,int(minor),entry.Class,entry.Reason,int64(reason),int64(sourceInfo),
            int64(security),int64(attributes),filename)
        if err!=nil{return fmt.Errorf("insert FI scoped USN event %d: %w",index+1,err)}
    }
    return nil
}

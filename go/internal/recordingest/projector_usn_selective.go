// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// Source-bound, independent CURRENT NTFS outcomes. Unlike USNScopedCapture,
// this stage does not claim metadata was true at an earlier journal event.
package recordingest

import (
    "context"
    "encoding/hex"
    "errors"
    "fmt"
    "time"

    "github.com/Iron-Signal-Systems/fi/go/internal/windows/ntfs"
    "github.com/jackc/pgx/v5"
)

// A separate signed File-ID observation must bind exactly one prior scoped
// original USN source interval from this sender/source identity. Reusing a
// hash or root from a different source, scope, volume, journal or range fails.
func projectUSNSelectiveObservation(
    ctx context.Context,tx pgx.Tx,sourceID string,sourceRecordID int64,
    scopeID string,value usnSelectiveObservationPayload,
)error{
    if ctx==nil||tx==nil||sourceID==""||sourceRecordID<=0{
        return errors.New("FI selective NTFS requires recorded signed source identity")
    }
    if err:=validateUSNSelectiveObservation(scopeID,value);err!=nil{return err}
    volumeID,err:=ensureNTFSVolume(ctx,tx,sourceID,value.VolumeIdentity)
    if err!=nil{return err}
    rootID,err:=ensureNTFSObject(ctx,tx,volumeID,value.RootIdentity)
    if err!=nil{return err}
    objectID,err:=ensureNTFSObject(ctx,tx,volumeID,value.FileIdentity)
    if err!=nil{return err}
    digest,err:=hex.DecodeString(value.SourceBatchSHA256)
    if err!=nil{return err}

    rows,err:=tx.Query(ctx,`
SELECT sc.source_record_id
FROM fi.usn_scoped_capture AS sc
JOIN fi.source_record AS sr ON sr.source_record_id=sc.source_record_id
JOIN fi.source_batch AS sb ON sb.source_batch_id=sr.source_batch_id
JOIN fi.recorded_generation AS rg ON rg.recorded_generation_id=sb.recorded_generation_id
WHERE rg.source_id=$1 AND sr.scope_id=$2 AND sc.governed_scope_id=$2
  AND sc.capture_scope_id=$3 AND sc.ntfs_volume_id=$4
  AND sc.root_ntfs_object_id=$5 AND sc.journal_id=$6::numeric
  AND sc.start_usn=$7::numeric AND sc.next_usn=$8::numeric
  AND sc.source_batch_sha256=$9
ORDER BY sc.source_record_id
LIMIT 2
`,sourceID,scopeID,value.CaptureScopeID,volumeID,rootID,
        value.JournalID,value.StartUSN,value.NextUSN,digest)
    if err!=nil{return fmt.Errorf("lookup original source-bound USN observation: %w",err)}
    var captureRecordID int64
    count:=0
    for rows.Next(){
        count++
        if err:=rows.Scan(&captureRecordID);err!=nil{rows.Close();return err}
    }
    err=rows.Err()
    rows.Close()
    if err!=nil{return err}
    if count!=1||captureRecordID<=0{
        return errors.New("FI independently observed NTFS object has no unique matching original USN scope/custody")
    }

    for i,trigger:=range value.TriggerUSNs{
        var present bool
        err:=tx.QueryRow(ctx,`
SELECT EXISTS (
 SELECT 1 FROM fi.usn_scoped_change
 WHERE source_record_id=$1 AND file_ntfs_object_id=$2 AND usn=$3::numeric
)`,captureRecordID,objectID,trigger).Scan(&present)
        if err!=nil{return err}
        if !present{
            return fmt.Errorf("FI independent observation trigger %d is absent from original source journal",i+1)
        }
    }
    when,err:=time.Parse(time.RFC3339Nano,value.ObservedAt)
    if err!=nil{return err}
    _,err=tx.Exec(ctx,`
INSERT INTO fi.usn_selective_observation(
 source_record_id,original_capture_source_record_id,capture_scope_id,governed_scope_id,
 ntfs_volume_id,root_ntfs_object_id,file_ntfs_object_id,
 journal_id,start_usn,next_usn,source_batch_sha256,observed_at,
 observation_status,reason_code,error_text,has_ntfs_observation,has_content_hashes,trigger_count)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8::numeric,$9::numeric,$10::numeric,$11,$12,$13,$14,$15,$16,$17,$18)
`,sourceRecordID,captureRecordID,value.CaptureScopeID,scopeID,
        volumeID,rootID,objectID,value.JournalID,value.StartUSN,value.NextUSN,
        digest,when,value.Status,value.ReasonCode,value.Error,
        value.NTFS!=nil,value.ContentHashes!=nil,len(value.TriggerUSNs))
    if err!=nil{return fmt.Errorf("insert independently observed original USN source: %w",err)}
    for i,trigger:=range value.TriggerUSNs{
        _,err=tx.Exec(ctx,`
INSERT INTO fi.usn_selective_observation_trigger(source_record_id,trigger_ordinal,usn)
VALUES ($1,$2,$3::numeric)
`,sourceRecordID,i+1,trigger)
        if err!=nil{return fmt.Errorf("insert independent USN trigger %d: %w",i+1,err)}
    }
    if value.Status=="Observed"{
        nested:=*value.NTFS
        nested.ContentHashes=value.ContentHashes
        if err:=ntfs.ValidateObservation(nested);err!=nil{return err}
        if err:=projectNTFSObservation(ctx,tx,sourceID,sourceRecordID,nested,value.ContentHashes);err!=nil{
            return fmt.Errorf("project exact independently observed NTFS file: %w",err)
        }
    }
    return nil
}

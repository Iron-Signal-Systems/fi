//go:build fi_c1_sor_dev

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// P6 PRIVATE CLONE ONLY. The original C220 optimized seed requires
// validatedSourceFileObservation provenance, not merely a second call to
// ntfs.ValidateObservation. Reuse exactly that contract and its verified
// source/bulk one-to-one counters; never fabricate acceptance receipts.
package recordingest

import (
    "context"
    "errors"
    "fmt"
)

// A typed SQL-ready File record carries the ORIGINAL signed source ID and
// the ORIGINAL optimized seed's non-forgeable source-validation proof.
// No alternate P6 struct may replace the validated-source constructor.
func privateP6ValidatedNTFSRecord(
    sourceID string, sourceRecordID, ordinal int64, prepared SourceRecord,
) (fileObservationBulkRecord,error) {
    if sourceID=="" || sourceRecordID<=0 || ordinal<=0 ||
        prepared.Record.RecordKind!="FileObservation" ||
        prepared.RecordBytes<=0 {
        return fileObservationBulkRecord{},errors.New("FI P6 NTFS: invalid signed file identity")
    }
    var value fileObservationPayload
    if prepared.PrivateFamilyP3File!=nil {
        value=*prepared.PrivateFamilyP3File
    }else if err:=decodeStrictPayload(prepared.Record.Payload,&value);err!=nil {
        return fileObservationBulkRecord{},projectionDecodeError("FileObservation",err)
    }
    value.NTFS.ContentHashes=&value.ContentHashes
    validated,err:=validateSourceFileObservation(value.NTFS)
    if err!=nil {
        return fileObservationBulkRecord{},projectionValidationError("FileObservation",err)
    }
    if validated==nil {
        return fileObservationBulkRecord{},errors.New("FI P6 NTFS: missing actual source validation proof")
    }
    if validated.observation.GovernedRoot.ScopeID!=prepared.Record.ScopeID {
        return fileObservationBulkRecord{},
            errors.New("FI P6 NTFS: governed root scope differs from signed source")
    }
    record,err:=fileBulkRecordFromValidatedSource(
        sourceID,sourceRecordID,ordinal,validated,
        &value.ContentHashes,int64(prepared.RecordBytes))
    if err!=nil{return fileObservationBulkRecord{},err}
    if record.validatedSource!=validated ||
        record.sourceRecordID!=sourceRecordID ||
        record.sourceID!=sourceID || record.ordinal!=ordinal {
        return fileObservationBulkRecord{},
            errors.New("FI P6 NTFS: actual validated-source proof or signed identity was lost")
    }
    return record,nil
}

// Every successful validated record must flow into the actual optimized
// fileObservationBulkState. Its original bulk writer alone records
// FileBulkValidationReused when it consumes validatedSource. The second
// counter is NEVER incremented by P6, and is checked after SQL COPY.
func (w *privateP6SQLCoordinator) ntfs(ctx context.Context,
    rows []privateP6Record,ids []int64)error{
    if w==nil || ctx==nil || len(rows)!=len(ids) || len(rows)==0 {
        return errors.New("FI P6 NTFS: missing coordinator or exact signed parent IDs")
    }
    counters,ok:=ctx.Value(ntfsStageTimingContextKey{}).(*ntfsStageTimingCounters)
    if !ok || counters==nil {
        return errors.New("FI P6 NTFS: existing source/reuse validation counters missing")
    }
    ctx,err:=withFixedFileBulkProfile(ctx,"F3")
    if err!=nil{return err}
    pending:=newFileObservationBulkState()
    ctx=context.WithValue(ctx,fileObservationBulkContextKey{},pending)
    sourceBefore:=counters.FileSourceValidated
    reuseBefore:=counters.FileBulkValidationReused
    for i,r:=range rows{
        if ids[i]<=0 || r.sourceBatchID<=0 || r.ordinal<=0 {
            return errors.New("FI P6 NTFS: source-record FK, batch or ordinal missing")
        }
        bulkRecord,err:=privateP6ValidatedNTFSRecord(
            w.sourceID,ids[i],r.ordinal,r.prepared)
        if err!=nil {
            return fmt.Errorf("FI P6 NTFS source record batch=%d ordinal=%d: %w",
                r.sourceBatchID,r.ordinal,err)
        }
        if err:=pending.add(ctx,w.tx,bulkRecord);err!=nil{return err}
        // Only after original source validation, binding its signed FK and
        // successful admission into the genuine bounded bulk projector.
        counters.FileSourceValidated++
    }
    if err:=pending.flush(ctx,w.tx);err!=nil{return err}
    sourceDelta:=counters.FileSourceValidated-sourceBefore
    reuseDelta:=counters.FileBulkValidationReused-reuseBefore
    if sourceDelta!=int64(len(rows)) || reuseDelta!=int64(len(rows)){
        return fmt.Errorf("FI P6 NTFS: verified source/bulk proof mismatch source=%d reused=%d expected=%d",
            sourceDelta,reuseDelta,len(rows))
    }
    return nil
}

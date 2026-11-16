// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
package recordingest

import (
    "context"
    "errors"
    "github.com/Iron-Signal-Systems/fi/go/internal/windows/ntfs"
)

// NTFS owns identities, governed roots, observations, hashes, metadata,
// SACL/ACL/ACE and nested children through established FI relational writes.
func(w *privateP6SQLCoordinator) ntfs(ctx context.Context,
    rows []privateP6Record,ids []int64)error{
    if len(rows)!=len(ids){return errors.New("FI P6 File: source IDs mismatch")}
    ctx,err:=withFixedFileBulkProfile(ctx,"F3")
    if err!=nil{return err}
    pending:=newFileObservationBulkState()
    ctx=context.WithValue(ctx,fileObservationBulkContextKey{},pending)
    for i,r:=range rows{
        if r.prepared.Record.RecordKind!="FileObservation"||ids[i]<=0{
            return errors.New("FI P6 File: unsupported kind or missing signed FK")
        }
        var value fileObservationPayload
        if r.prepared.PrivateFamilyP3File!=nil{
            value=*r.prepared.PrivateFamilyP3File
        }else if err:=decodeStrictPayload(r.prepared.Record.Payload,&value);err!=nil{
            return projectionDecodeError("FileObservation",err)
        }
        value.NTFS.ContentHashes=&value.ContentHashes
        if err:=ntfs.ValidateObservation(value.NTFS);err!=nil{
            return projectionValidationError("FileObservation",err)
        }
        if value.NTFS.GovernedRoot.ScopeID!=r.prepared.Record.ScopeID{
            return errors.New("FI P6 File: governed root scope differs from signed source")
        }
        if err:=pending.add(ctx,w.tx,fileObservationBulkRecord{
            sourceID:w.sourceID,sourceRecordID:ids[i],ordinal:r.ordinal,
            value:value.NTFS,hashes:&value.ContentHashes,
            bytes:int64(r.prepared.RecordBytes),
        });err!=nil{return err}
    }
    return pending.flush(ctx,w.tx)
}

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// P6 private W512 SQL coordinator. One existing atomic SQL transaction,
// canonical source_record ordinals, independently typed family modules.
// No second SQL writer, no new accepted publication, no schema changes.
package recordingest

import (
    "context"
    "errors"
    "fmt"
    "os"
    "time"

    "github.com/jackc/pgx/v5"
)

type privateP6SourceAlreadyInsertedKey struct{}

func privateP6SourceAlreadyInserted(ctx context.Context)bool {
    return ctx!=nil && ctx.Value(privateP6SourceAlreadyInsertedKey{})==true
}
func privateP6Selected()bool{
    return os.Getenv("FI_W512_P6_FAMILY_SQL")=="1"
}

type privateP6SQLCoordinator struct{
    tx privateProjectionTx
    sourceID string
    profile *ingestStageProfile
    sourceCopies int64
    copiedSourceRows int64
    familyCopies [privateP6FamilyCount]int64
    familyRows [privateP6FamilyCount]int64
}
func newPrivateP6SQLCoordinator(tx privateProjectionTx,sourceID string,
    profile *ingestStageProfile)(*privateP6SQLCoordinator,error){
    if !privateP6Selected() || tx.Tx==nil || sourceID=="" || profile==nil {
        return nil,errors.New("FI P6: isolated projection transaction, source and profiling required")
    }
    return &privateP6SQLCoordinator{tx:tx,sourceID:sourceID,profile:profile},nil
}

// SOURCE is inserted in original signed order, not individual family order.
// Existing USN's <source_record_id prerequisite remains correct, and every
// relational child still references the exact source batch/ordinal/digest.
func(w *privateP6SQLCoordinator) Source(ctx context.Context,rows []privateP6Record)error{
    if w==nil||ctx==nil||len(rows)==0{return errors.New("FI P6 SQL: source ledger empty")}
    for i,row:=range rows {
        if !row.valid(){return fmt.Errorf("FI P6 SQL: invalid signed source row %d",i)}
        if i>0{
            prev:=rows[i-1]
            if row.signedBatchIndex<prev.signedBatchIndex||
                (row.signedBatchIndex==prev.signedBatchIndex && row.ordinal<=prev.ordinal){
                return errors.New("FI P6 SQL: nonmonotonic source ledger")
            }
        }
    }
    columns:=[]string{"source_batch_id","record_ordinal","version","record_kind",
        "scope_id","written_at","record_bytes","record_sha256","ingest_version"}
    started:=time.Now()
    n,err:=w.tx.CopyFrom(ctx,pgx.Identifier{"fi","source_record"},columns,
        pgx.CopyFromSlice(len(rows),func(i int)([]any,error){
            r:=rows[i]
            p:=r.prepared
            return []any{r.sourceBatchID,r.ordinal,p.Record.Version,p.Record.RecordKind,
                p.Record.ScopeID,p.WrittenAtUTC,p.RecordBytes,p.RecordDigest[:],
                IngestVersion},nil
        }))
    w.profile.SourceSQL+=time.Since(started)
    if err!=nil{return fmt.Errorf("FI P6 SQL: signed source parent COPY: %w",err)}
    if n!=int64(len(rows)){return errors.New("FI P6 SQL: incomplete source parent COPY")}
    w.sourceCopies++
    w.copiedSourceRows+=n
    return nil
}

// Resolving database IDs by both original batch ID and ordinal avoids any
// assumption about COPY-generated SQL sequences. Reuse FI's established
// sparse-key lookup, including the exact 1:1 proof for missing rows.
func(w *privateP6SQLCoordinator) sourceIDs(ctx context.Context,
    rows []privateP6Record)([]int64,error){
    batchIDs:=make([]int64,len(rows))
    ordinals:=make([]int64,len(rows))
    for i,r:=range rows{
        batchIDs[i],ordinals[i]=r.sourceBatchID,r.ordinal
    }
    ids,err:=lookupBulkSourceRecordIDs(ctx,w.tx,batchIDs,ordinals)
    if err!=nil{return nil,fmt.Errorf("FI P6 SQL: parent identity lookup: %w",err)}
    if len(ids)!=len(rows){return nil,errors.New("FI P6 SQL: incomplete 1:1 parent identity mapping")}
    return ids,nil
}

func(w *privateP6SQLCoordinator) Family(ctx context.Context,
    family privateP6Family,rows []privateP6Record)error{
    if w==nil||ctx==nil||family>=privateP6FamilyCount||len(rows)==0{
        return errors.New("FI P6 SQL: invalid typed family handoff")
    }
    for i,r:=range rows{
        got,err:=privateP6KindFamily(r.prepared.Record.RecordKind)
        if err!=nil||got!=family||!r.valid(){
            return fmt.Errorf("FI P6 SQL: signed family mismatch at row %d",i)
        }
    }
    ids,err:=w.sourceIDs(ctx,rows)
    if err!=nil{return err}
    // Only original audited projectors/COPY implementations can write the
    // relational children. Every module stays in this SAME SQL transaction.
    switch family{
    case privateP6Security:
        err=w.security(ctx,rows,ids)
    case privateP6File:
        err=w.ntfs(ctx,rows,ids)
    case privateP6Coverage:
        err=w.coverage(ctx,rows,ids)
    case privateP6USN:
        err=w.usn(ctx,rows,ids)
    case privateP6Other:
        err=w.other(ctx,rows,ids)
    default:err=errors.New("FI P6 SQL: unrecognized family")
    }
    if err!=nil{return fmt.Errorf("FI P6 SQL: %s relational parent/child: %w",
        privateP6FamilyNames[family],err)}
    w.familyCopies[family]++
    w.familyRows[family]+=int64(len(rows))
    return nil
}

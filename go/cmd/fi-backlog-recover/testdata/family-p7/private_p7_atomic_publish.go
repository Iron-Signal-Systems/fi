// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// FI P7 PRIVATE CLONE ONLY: five family connections commit into the
// private relational staging schema. An independently verified W512 typed
// marker is published by ONE transaction after every family acknowledges.
// Physical family staging is NOT a distributed PostgreSQL transaction.
// Discard the entire private clone after any incomplete or failed attempt.
package recordingest

import (
    "context"
    "crypto/subtle"
    "encoding/binary"
    "encoding/hex"
    "errors"
    "fmt"
    "time"

    "github.com/jackc/pgx/v5"
)

type privateP7PublishedWindow struct{
    Index int
    SourceRows int64
    SourceBytes int64
    SecurityFields int64
    FileValidated int64
    FiveFamilyRows [privateP6FamilyCount]int64
    VerifiedAt time.Time
}

func privateP7PublishVerifiedWindow(ctx context.Context,
    writer *pgx.Conn,stage *privateP7FiveWriter,
    g *PreparedGeneration,d BacklogCheckpointDescriptor,
    index int,fieldPartition string,isFinalWindow bool,
)(privateP7PublishedWindow,error){
    var result privateP7PublishedWindow
    if ctx==nil||writer==nil||stage==nil||g==nil||
        !privateP7FiveWriterSelected()||index<=0||
        d.StartBatch<0||d.EndBatch<=d.StartBatch||
        d.EndBatch>len(g.Batches){
        return result,errors.New("FI P7 publish: invalid signed descriptor, feature gate or writer")
    }
    stage.mu.Lock()
    err:=stage.errorLocked()
    if err==nil&&(!stage.finished||!stage.drained){
        err=errors.New("FI P7 publish: five SQL lanes not durably drained")
    }
    total,bytes:=stage.sourceRows,stage.sourceBytes
    var byFamily [privateP6FamilyCount]int64
    var written int64
    for f,l:=range stage.lanes{
        if l==nil{err=errors.New("FI P7 publish: missing dedicated family writer");break}
        byFamily[f]=l.committed
        written+=l.committed
    }
    stage.mu.Unlock()
    if err!=nil{return result,err}
    if total!=written||total!=int64(d.EndRecord-d.StartRecord)||
        bytes!=int64(d.DataBytes){
        return result,fmt.Errorf("FI P7 publish: source vs 5 SQL lanes differ records=%d/%d bytes=%d/%d",
            written,total,bytes,d.DataBytes)
    }
    fileWriter,ok:=stage.lanes[privateP6File].writer.(*privateP7PGFamily)
    if !ok{return result,errors.New("FI P7 publish: actual NTFS PostgreSQL writer missing")}
    counters:=fileWriter.ntfsTiming
    if counters==nil{
        return result,errors.New("FI P7 publish: original NTFS source/reuse counters absent")
    }
    if counters.FileSourceValidated!=byFamily[privateP6File]||
        counters.FileBulkValidationReused!=byFamily[privateP6File]{
        return result,fmt.Errorf("FI P7 publish: FileObservation proof source=%d reused=%d typed=%d",
            counters.FileSourceValidated,counters.FileBulkValidationReused,
            byFamily[privateP6File])
    }
    secWriter,ok:=stage.lanes[privateP6Security].writer.(*privateP7PGFamily)
    if !ok{return result,errors.New("FI P7 publish: Security writer absent")}
    fields:=secWriter.profile.SecurityBulk.Fields
    receipt,err:=hex.DecodeString(d.ReceiptSHA256)
    if err!=nil||len(receipt)!=32{
        return result,errors.New("FI P7 publish: invalid custody receipt digest")
    }
    digest,err:=hex.DecodeString(d.DigestSHA256)
    if err!=nil||len(digest)!=32{
        return result,errors.New("FI P7 publish: invalid signed descriptor digest")
    }
    tx,err:=writer.Begin(ctx)
    if err!=nil{return result,err}
    defer tx.Rollback(context.Background())
    if _,err=tx.Exec(ctx,"SELECT pg_advisory_xact_lock($1::bigint)",
        int64(binary.BigEndian.Uint64(receipt[:8])));err!=nil{return result,err}
    // The private clone must never contain authoritative/Accepted state.
    var accepted,authoritative bool
    if err=tx.QueryRow(ctx,"SELECT EXISTS(SELECT 1 FROM fi.ingest_journal WHERE outcome='Accepted'), EXISTS(SELECT 1 FROM fi.recorded_generation WHERE source_id=$1 AND generation_id=$2)",
        d.SourceID,d.GenerationID).Scan(&accepted,&authoritative);err!=nil{return result,err}
    if accepted||authoritative {
        return result,errors.New("FI P7 publish: real SoR or Accepted journal state present")
    }
    var sourceDigest,artifactDigest []byte
    if err=tx.QueryRow(ctx,"SELECT descriptor_sha256 FROM fi_recovery.source_window WHERE receipt_sha256=$1 AND window_index=$2",
        receipt,index).Scan(&sourceDigest);err!=nil{
        return result,fmt.Errorf("FI P7 publish: durable source window missing: %w",err)
    }
    if err=tx.QueryRow(ctx,"SELECT descriptor_sha256 FROM fi_recovery.verified_artifact_window WHERE receipt_sha256=$1 AND window_index=$2",
        receipt,index).Scan(&artifactDigest);err!=nil{
        return result,fmt.Errorf("FI P7 publish: verified signed artifact window missing: %w",err)
    }
    if subtle.ConstantTimeCompare(sourceDigest,digest)!=1||
        subtle.ConstantTimeCompare(artifactDigest,digest)!=1 {
        return result,errors.New("FI P7 publish: source/artifact descriptor disagree with custody SHA")
    }
    if index>0{
        var previous []byte
        if err=tx.QueryRow(ctx,"SELECT descriptor_sha256 FROM fi_recovery.typed_window WHERE receipt_sha256=$1 AND window_index=$2",
            receipt,index-1).Scan(&previous);err!=nil{
            return result,fmt.Errorf("FI P7 publish: previous typed checkpoint missing: %w",err)
        }
        want,e:=hex.DecodeString(d.PreviousDigestSHA256)
        if e!=nil||subtle.ConstantTimeCompare(previous,want)!=1 {
            return result,errors.New("FI P7 publish: previous signed W512 checkpoint changed")
        }
    }
    var already int
    if err=tx.QueryRow(ctx,"SELECT count(*) FROM fi_recovery.typed_window WHERE receipt_sha256=$1 AND window_index=$2",
        receipt,index).Scan(&already);err!=nil{return result,err}
    if already!=0{return result,errors.New("FI P7 publish: a typed window marker already exists")}
    shadow:=privateProjectionTx{Tx:tx,fieldPartition:fieldPartition}
    id,found,err:=lookupRecordedGeneration(ctx,shadow,d.SourceID,d.GenerationID,
        g.Receipt.TransferSHA256,g.ReceiptSHA256)
    if err!=nil{return result,err}
    if !found{return result,errors.New("FI P7 publish: original private shadow generation missing")}
    // Match the accepted one-writer ordering: attach and validate Security
    // field partitions BEFORE relational/count coverage checks. Otherwise
    // inherited field-table checks can overlook still-detached child rows.
    if fieldPartition!=""{
        var exists bool
        if err=tx.QueryRow(ctx,"SELECT to_regclass($1) IS NOT NULL",
            "fi_recovery_projection."+fieldPartition).Scan(&exists);err!=nil{return result,err}
        if !exists{return result,errors.New("FI P7 publish: Security field partition must be precommitted")}
        var attached int64
        if err=tx.QueryRow(ctx,"SELECT fi_recovery_projection.finish_security_field_window($1,$2)",
            index,fields).Scan(&attached);err!=nil{return result,err}
        if attached!=fields {
            return result,errors.New("FI P7 publish: Security field partition expected rows mismatch")
        }
    }
    if err=verifyBacklogShadowWindowCounts(ctx,shadow,id,
        g.Batches[d.StartBatch:d.EndBatch],total,bytes);err!=nil{return result,err}
    if err=verifyBacklogWindowProjectionCoverage(ctx,shadow,id,
        g.Batches[d.StartBatch:d.EndBatch]);err!=nil{return result,err}
    if isFinalWindow{
        if err=verifyBacklogUSNCapturesComplete(ctx,shadow,id);err!=nil{
            return result,fmt.Errorf("FI P7 publish: USN capture not complete: %w",err)
        }
    }
    _,err=tx.Exec(ctx,"INSERT INTO fi_recovery.typed_window (receipt_sha256,window_index,descriptor_sha256,shadow_generation_id,start_batch,end_batch,committed_records,committed_bytes,ingest_version) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)",
        receipt,index,digest,id,d.StartBatch,d.EndBatch,total,bytes,IngestVersion)
    if err!=nil{return result,fmt.Errorf("FI P7 publish: atomic typed marker: %w",err)}
    if err=tx.Commit(ctx);err!=nil{return result,err}
    result=privateP7PublishedWindow{
        Index:index,SourceRows:total,SourceBytes:bytes,
        SecurityFields:fields,FileValidated:counters.FileSourceValidated,
        FiveFamilyRows:byFamily,VerifiedAt:time.Now().UTC(),
    }
    fmt.Printf("FI P7 FIVE-WRITER W512 PUBLISHED index=%d records=%d bytes=%d family_writers=5 source_ledger=durable native_file_validated=%d security_fields=%d typed_marker=atomic accepted=0 authoritative=0\n",
        index,total,bytes,result.FileValidated,fields)
    return result,nil
}

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// P7 PRIVATE CLONE ONLY: create the field partition and verify committed
// signed source custody BEFORE opening five independent typed SQL writer
// transactions. The old single-transaction W512 entry point cannot perform
// this operation without hiding its DDL and parent IDs from other backends.
package recordingest

import (
    "context"
    "crypto/subtle"
    "encoding/binary"
    "encoding/hex"
    "errors"
    "fmt"

    "github.com/jackc/pgx/v5"
)

type privateP7PreparedWindow struct{
    Index int
    SourceID string
    FieldPartition string
    SignedRecords int64
    SignedBytes int64
}

func privateP7PrepareCommittedWindow(ctx context.Context,control *pgx.Conn,
    descriptor BacklogCheckpointDescriptor,index int,
)(privateP7PreparedWindow,error){
    var p privateP7PreparedWindow
    if ctx==nil||control==nil||index<=0||!privateP7FiveWriterSelected(){
        return p,errors.New("FI P7 setup: invalid window or private five-writer feature gate")
    }
    d:=descriptor
    receipt,err:=hex.DecodeString(d.ReceiptSHA256)
    if err!=nil||len(receipt)!=32{return p,errors.New("FI P7 setup: signed receipt hash invalid")}
    expected,err:=hex.DecodeString(d.DigestSHA256)
    if err!=nil||len(expected)!=32{return p,errors.New("FI P7 setup: W512 descriptor hash invalid")}
    // SourceWindowDurable must have completed in its OWN earlier
    // transaction. Both pending source rows and the custody envelope
    // must already be committed and visible to all five writer backends.
    tx,err:=control.Begin(ctx)
    if err!=nil{return p,err}
    defer tx.Rollback(context.Background())
    if _,err=tx.Exec(ctx,"SELECT pg_advisory_xact_lock($1::bigint)",
        int64(binary.BigEndian.Uint64(receipt[:8])));err!=nil{return p,err}
    var sourceDigest,artifactDigest []byte
    var sources,bytes int64
    err=tx.QueryRow(ctx,"SELECT descriptor_sha256 FROM fi_recovery.source_window WHERE receipt_sha256=$1 AND window_index=$2",
        receipt,index).Scan(&sourceDigest)
    if err!=nil{return p,fmt.Errorf("FI P7 setup: source checkpoint not durable: %w",err)}
    err=tx.QueryRow(ctx,"SELECT descriptor_sha256 FROM fi_recovery.verified_artifact_window WHERE receipt_sha256=$1 AND window_index=$2",
        receipt,index).Scan(&artifactDigest)
    if err!=nil{return p,fmt.Errorf("FI P7 setup: artifact checkpoint not durable: %w",err)}
    if subtle.ConstantTimeCompare(expected,sourceDigest)!=1||
        subtle.ConstantTimeCompare(expected,artifactDigest)!=1{
        return p,errors.New("FI P7 setup: source/artifact descriptor not exactly signed")
    }
    err=tx.QueryRow(ctx,"SELECT count(*),coalesce(sum(record_bytes),0)::bigint FROM fi_recovery.pending_source_record WHERE receipt_sha256=$1 AND window_index=$2",
        receipt,index).Scan(&sources,&bytes)
    if err!=nil{return p,fmt.Errorf("FI P7 setup: committed source ledger lookup: %w",err)}
    if sources!=int64(d.EndRecord-d.StartRecord)||bytes!=int64(d.DataBytes){
        return p,fmt.Errorf("FI P7 setup: exact source rows=%d/%d bytes=%d/%d",
            sources,d.EndRecord-d.StartRecord,bytes,d.DataBytes)
    }
    var completed int
    if err=tx.QueryRow(ctx,"SELECT count(*) FROM fi_recovery.typed_window WHERE receipt_sha256=$1 AND window_index=$2",
        receipt,index).Scan(&completed);err!=nil{return p,err}
    if completed>0{return p,errors.New("FI P7 setup: typed W512 already published")}
    name,nameErr:=privateSecurityFieldWindowTable(index)
    if nameErr!=nil{return p,nameErr}
    var committedName string
    err=tx.QueryRow(ctx,"SELECT fi_recovery_projection.begin_security_field_window($1)",index).
        Scan(&committedName)
    if err!=nil{return p,fmt.Errorf("FI P7 setup: precommit security field partition: %w",err)}
    if committedName!=name{return p,errors.New("FI P7 setup: wrong signed W512 field partition")}
    if err=tx.Commit(ctx);err!=nil{return p,err}
    p=privateP7PreparedWindow{Index:index,SourceID:d.SourceID,
        FieldPartition:name,SignedRecords:sources,SignedBytes:bytes}
    fmt.Printf("FI P7 STAGED W512 READY index=%d records=%d bytes=%d parent_ledger=committed field_partition=committed concurrent_sql_writers=5\n",
        index,sources,bytes)
    return p,nil
}

//go:build fi_c1_sor_dev

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// C1 B's source-row commitment is calculated while ORIGINAL authenticated
// JSONL is independently matched to PostgreSQL. The publisher replays only
// these narrow SQL identity fields under held publication table locks: it
// never reopens or decodes 15M original JSONL records after ingestion.
// The commitment does not replace typed coverage, USN or receipt proofs.
package recordingest

import (
    "context"
    "crypto/sha256"
    "encoding/binary"
    "encoding/hex"
    "errors"
    "fmt"
    "hash"
    "time"

    "github.com/jackc/pgx/v5"
)

const c1NativeBRowCommitmentVersion = "FI-C1-B-SIGNED-SQL-IDENTITY-V1"

// Use unambiguous fixed-width integers and length-prefixed UTF-8 fields.
// The exact same routine hashes independently checked signed source rows
// and publisher-locked PostgreSQL rows. Neither side may supply a digest
// without checking original batch, ordinal and signed generation identity.
func c1NativeBCommitInt64(h hash.Hash,n int64){
    var b [8]byte
    binary.BigEndian.PutUint64(b[:],uint64(n))
    _,_=h.Write(b[:])
}
func c1NativeBCommitBytes(h hash.Hash,b []byte){
    c1NativeBCommitInt64(h,int64(len(b)))
    _,_=h.Write(b)
}
func c1NativeBCommitString(h hash.Hash,s string){
    c1NativeBCommitBytes(h,[]byte(s))
}
func c1NativeBNewRowCommitment(p c1NativeBPlan)(hash.Hash,error){
    if err:=c1ValidateNativeBPlan(p);err!=nil{return nil,err}
    h:=sha256.New()
    c1NativeBCommitString(h,c1NativeBRowCommitmentVersion)
    c1NativeBCommitString(h,p.Start.SourceID)
    c1NativeBCommitString(h,p.Start.GenerationID)
    c1NativeBCommitString(h,p.Start.ReceiptSHA256)
    c1NativeBCommitString(h,p.Transfer)
    c1NativeBCommitInt64(h,int64(len(p.Batches)))
    for i,b:=range p.Batches{
        c1NativeBCommitInt64(h,p.SQLIDs[i])
        c1NativeBCommitString(h,b.BatchID)
        c1NativeBCommitInt64(h,int64(b.Manifest.RecordCount))
        c1NativeBCommitInt64(h,b.Manifest.DataBytes)
        c1NativeBCommitString(h,b.ManifestSHA256)
        c1NativeBCommitString(h,b.Manifest.DataSHA256)
    }
    return h,nil
}
func c1NativeBCommitRow(h hash.Hash,batchID,ordinal int64,
    version,kind,scope string,writtenAt time.Time,size int64,digest []byte)error{
    if h==nil||batchID<=0||ordinal<=0||version==""||kind==""||
        size<=0||len(digest)!=sha256.Size||writtenAt.IsZero(){
        return errors.New("C1 B: incomplete original SQL source row commitment")
    }
    c1NativeBCommitInt64(h,batchID)
    c1NativeBCommitInt64(h,ordinal)
    c1NativeBCommitString(h,version)
    c1NativeBCommitString(h,kind)
    c1NativeBCommitString(h,scope)
    c1NativeBCommitInt64(h,writtenAt.UTC().Truncate(time.Microsecond).UnixMicro())
    c1NativeBCommitInt64(h,size)
    c1NativeBCommitBytes(h,digest)
    return nil
}

// Run ONLY from inside the common publisher's SHARE table locks. All
// relevant pending relations are already immutable against concurrent SQL
// writes until Accepted COMMIT. Check EVERY original row's identity,
// ordering, size and SHA-256, but never re-decompress original signed custody.
// This scans existing SQL row identities once and uses bounded memory.
func c1NativeBLockedSQLRowCommitment(ctx context.Context,conn *pgx.Conn,
    p c1NativeBPlan)(string,error){
    if ctx==nil||conn==nil{return "",errors.New("C1 B: locked SQL commitment requires connection")}
    return c1NativeBLockedSQLRowCommitmentQuery(ctx,conn,p)
}
// The direct-canonical publisher calls this inside the same transaction
// that owns canonical SHARE table locks, never on an unlocked connection.
func c1NativeBLockedSQLRowCommitmentTx(ctx context.Context,tx pgx.Tx,
    p c1NativeBPlan)(string,error){
    if ctx==nil||tx==nil{return "",errors.New("C1 B: locked SQL commitment requires transaction")}
    return c1NativeBLockedSQLRowCommitmentQuery(ctx,tx,p)
}
type c1NativeBRowQuerier interface{
    Query(context.Context,string,...any)(pgx.Rows,error)
}
func c1NativeBLockedSQLRowCommitmentQuery(ctx context.Context,conn c1NativeBRowQuerier,
    p c1NativeBPlan)(string,error){
    if ctx==nil||conn==nil{return "",errors.New("C1 B: locked SQL commitment query unavailable")}
    schema,err:=c1NativeBSchema(p)
    if err!=nil{return "",err}
    h,err:=c1NativeBNewRowCommitment(p)
    if err!=nil{return "",err}
    table:=pgx.Identifier{schema,"source_record"}.Sanitize()
    query:="SELECT record_ordinal,version,record_kind,scope_id,written_at,record_bytes,record_sha256 "+
        "FROM "+table+" WHERE source_batch_id=$1 ORDER BY record_ordinal"
    var total int64
    for i,b:=range p.Batches{
        if err:=ctx.Err();err!=nil{return "",err}
        rows,err:=conn.Query(ctx,query,p.SQLIDs[i])
        if err!=nil{return "",fmt.Errorf("C1 B: locked source batch %d: %w",i,err)}
        var n,bytes int64
        for rows.Next(){
            var ordinal,size int64
            var version,kind,scope string
            var writtenAt time.Time
            var digest []byte
            if err=rows.Scan(&ordinal,&version,&kind,&scope,&writtenAt,&size,&digest);err!=nil{break}
            if ordinal!=n+1||size<=0||bytes>b.Manifest.DataBytes-size{
                err=errors.New("C1 B: pending source ordinal, duplicate or byte total changed after group proof")
                break
            }
            if err=c1NativeBCommitRow(h,p.SQLIDs[i],ordinal,
                version,kind,scope,writtenAt,size,digest);err!=nil{break}
            n++
            bytes+=size
        }
        if err==nil{err=rows.Err()}
        rows.Close()
        if err!=nil{return "",fmt.Errorf("C1 B: locked pending source changed in batch %d: %w",i,err)}
        if n!=int64(b.Manifest.RecordCount)||bytes!=b.Manifest.DataBytes{
            return "",fmt.Errorf("C1 B: locked pending source batch %d incomplete count=%d bytes=%d",i,n,bytes)
        }
        total+=n
    }
    if total!=p.Start.ExpectedRecords{
        return "",errors.New("C1 B: locked pending source generation count differs from original signed records")
    }
    return hex.EncodeToString(h.Sum(nil)),nil
}

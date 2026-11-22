//go:build fi_c1_sor_dev

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// The independent original-custody verifier B completes BEFORE this
// read-only canonical acceptance probe. Only a complete canonical
// recorded_generation AND exactly one matching Accepted journal record
// can elevate the final authenticated Drain ACK to FinalAccepted.
//
// This does not publish, create schemas, replay, or alter existing SoR.
package recordingest

import (
    "bytes"
    "context"
    "encoding/hex"
    "errors"
    "fmt"

    "github.com/Iron-Signal-Systems/fi/go/internal/c1handoff"
    "github.com/jackc/pgx/v5"
)

type c1CanonicalEvidence struct {
    generationExists bool
    recordedReceipt []byte
    recordedTransfer []byte
    records int64
    batches int64
    acceptedEvents int64
    matchingAcceptedEvents int64
}

// This evidence comparison does not trust a client-provided Published bit.
// The accepted journal transaction is the independent authoritative marker.
func c1CanonicalStatusFromEvidence(receiptSHA string,e c1CanonicalEvidence)(
    c1handoff.FinalStatus,error,
){
    want,err:=hex.DecodeString(receiptSHA)
    if err!=nil||len(want)!=32{
        return c1handoff.FinalNone,errors.New("C1 canonical: original receipt digest invalid")
    }
    if !e.generationExists {
        if e.acceptedEvents!=0 || e.matchingAcceptedEvents!=0{
            return c1handoff.FinalNone,errors.New("C1 canonical: Accepted journal exists without canonical generation")
        }
        return c1handoff.FinalVerified,nil
    }
    if len(e.recordedReceipt)!=32||!bytes.Equal(e.recordedReceipt,want)||
        len(e.recordedTransfer)!=32||e.records<=0||e.batches<=0 {
        return c1handoff.FinalNone,errors.New("C1 canonical: recorded generation disagrees with independently verified signed custody")
    }
    if e.acceptedEvents!=1||e.matchingAcceptedEvents!=1{
        return c1handoff.FinalNone,errors.New("C1 canonical: generation exists without exactly one matching Accepted journal transaction")
    }
    return c1handoff.FinalAccepted,nil
}

// C1 uses the existing populated SoR's fi and fi.ingest_journal rather
// than a separate receipt cache, client ACK, or an inferred projection
// completion flag. All reads observe one repeatable-read SQL snapshot.
func c1ReadCanonicalAcceptanceAfterB(ctx context.Context,dsn,
    source,generation,receiptSHA string)(c1handoff.FinalStatus,error){
    if ctx==nil||source==""||generation==""{
        return c1handoff.FinalNone,errors.New("C1 canonical: original signed identity required")
    }
    conn,_,err:=openC1SoRLocalSQL(ctx,dsn,"")
    if err!=nil{return c1handoff.FinalNone,err}
    defer conn.Close(context.Background())
    tx,err:=conn.BeginTx(ctx,pgx.TxOptions{
        IsoLevel:pgx.RepeatableRead,AccessMode:pgx.ReadOnly,
    })
    if err!=nil{return c1handoff.FinalNone,err}
    defer tx.Rollback(context.Background())
    status,err:=c1CanonicalStatusInSnapshot(ctx,tx,source,generation,receiptSHA)
    if err!=nil{return c1handoff.FinalNone,err}
    if err=tx.Commit(ctx);err!=nil{return c1handoff.FinalNone,err}
    return status,nil
}

// c1CanonicalStatusInSnapshot is also exercised against the real FI
// 49-table DDL in disposable PostgreSQL18 CI. It assumes the caller
// supplied a REPEATABLE READ READ ONLY transaction; it cannot mutate SQL.
func c1CanonicalStatusInSnapshot(ctx context.Context,tx pgx.Tx,
    source,generation,receiptSHA string)(c1handoff.FinalStatus,error){
    if ctx==nil||tx==nil||source==""||generation==""{
        return c1handoff.FinalNone,errors.New("C1 canonical: local read-only transaction and identity required")
    }
    evidence:=c1CanonicalEvidence{}
    err=tx.QueryRow(ctx,`SELECT receipt_sha256,transfer_sha256,
            record_count,batch_count
        FROM fi.recorded_generation
        WHERE source_id=$1 AND generation_id=$2`,
        source,generation).Scan(
        &evidence.recordedReceipt,&evidence.recordedTransfer,
        &evidence.records,&evidence.batches)
    switch {
    case err==nil:evidence.generationExists=true
    case errors.Is(err,pgx.ErrNoRows):
    default:return c1handoff.FinalNone,fmt.Errorf("C1 canonical: recorded generation readback: %w",err)
    }
    err=tx.QueryRow(ctx,`SELECT count(*),
            count(*) FILTER (WHERE
                transfer_sha256=$3
                AND records_committed=$4)
        FROM fi.ingest_journal
        WHERE source_id=$1 AND generation_id=$2 AND outcome='Accepted'`,
        source,generation,evidence.recordedTransfer,evidence.records).
        Scan(&evidence.acceptedEvents,&evidence.matchingAcceptedEvents)
    if err!=nil{return c1handoff.FinalNone,fmt.Errorf("C1 canonical: Accepted journal readback: %w",err)}
    return c1CanonicalStatusFromEvidence(receiptSHA,evidence)
}

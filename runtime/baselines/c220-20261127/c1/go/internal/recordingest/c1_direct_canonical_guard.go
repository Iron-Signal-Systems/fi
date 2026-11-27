//go:build fi_c1_sor_dev

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// C1 direct-to-canonical development: READ-ONLY start evidence.
// This does NOT implement direct SQL writes or grant canonical privileges.
// The existing Pending-to-canonical publisher must NOT be used to simulate
// a one-write C1 acceptance. A real writer requires a separate reviewed gate.
package recordingest

import (
    "context"
    "encoding/hex"
    "errors"
    "fmt"
    "strings"

    "github.com/jackc/pgx/v5"
)

// C1DirectCanonicalOriginal is supplied from the authenticated, immutable
// receiver custody, never from a client-supplied Accepted/Published flag.
type C1DirectCanonicalOriginal struct {
    SourceID string
    GenerationID string
    ReceiptSHA256 string
    TransferSHA256 string
    SignedRecords int64
    SignedBatches int64
}

// C1DirectCanonicalEvidence is sampled in ONE repeatable-read, read-only
// transaction from the populated SoR. A missing generation is not a partial
// success: the caller must separately verify its signed custody and writer.
type C1DirectCanonicalEvidence struct {
    ExistingGenerations int64
    ExistingRecords int64
    ExistingBatches int64
    ExistingReceiptSHA256 string
    ExistingTransferSHA256 string
    AcceptedEvents int64
    MatchingAcceptedEvents int64
    PendingGenerations int64
}

type C1DirectCanonicalStartStatus uint8

const (
    C1DirectCanonicalBlocked C1DirectCanonicalStartStatus = iota
    C1DirectCanonicalNew
    C1DirectCanonicalAlreadyAccepted
)

func c1ExactSHA256Hex(s string) bool {
    if len(s) != 64 || strings.ToLower(s) != s { return false }
    b, err := hex.DecodeString(s)
    return err == nil && len(b) == 32
}

// EvaluateC1DirectCanonicalStart is intentionally independent of runtime
// SQL details so negative cases can be unit-tested without live FI access.
// No caller may treat AlreadyAccepted as permission for another INSERT.
func EvaluateC1DirectCanonicalStart(original C1DirectCanonicalOriginal,
    e C1DirectCanonicalEvidence) (C1DirectCanonicalStartStatus,error) {
    if original.SourceID == "" || original.GenerationID == "" ||
        !c1ExactSHA256Hex(original.ReceiptSHA256) ||
        !c1ExactSHA256Hex(original.TransferSHA256) ||
        original.SignedRecords <= 0 || original.SignedBatches <= 0 {
        return C1DirectCanonicalBlocked,errors.New("C1 direct: authenticated signed generation required")
    }
    if e.ExistingGenerations < 0 || e.ExistingGenerations > 1 ||
        e.AcceptedEvents < 0 || e.AcceptedEvents > 1 ||
        e.MatchingAcceptedEvents < 0 ||
        e.MatchingAcceptedEvents > e.AcceptedEvents ||
        e.PendingGenerations < 0 {
        return C1DirectCanonicalBlocked,errors.New("C1 direct: contradictory canonical evidence")
    }
    if e.PendingGenerations != 0 {
        return C1DirectCanonicalBlocked,errors.New("C1 direct: legacy Pending generation exists; no direct replay")
    }
    if e.ExistingGenerations == 0 {
        if e.AcceptedEvents != 0 || e.MatchingAcceptedEvents != 0 {
            return C1DirectCanonicalBlocked,errors.New("C1 direct: Accepted event without canonical generation")
        }
        return C1DirectCanonicalNew,nil
    }
    if e.ExistingRecords != original.SignedRecords ||
        e.ExistingBatches != original.SignedBatches ||
        e.ExistingReceiptSHA256 != original.ReceiptSHA256 ||
        e.ExistingTransferSHA256 != original.TransferSHA256 {
        return C1DirectCanonicalBlocked,errors.New("C1 direct: existing generation conflicts with original signed receipt")
    }
    if e.AcceptedEvents != 1 || e.MatchingAcceptedEvents != 1 {
        return C1DirectCanonicalBlocked,errors.New("C1 direct: canonical generation exists without exactly one matching Accepted journal")
    }
    return C1DirectCanonicalAlreadyAccepted,nil
}

// AuditC1DirectCanonicalStart makes NO mutations. It never provides a SQL
// writer, publishes Accepted, discards prior history or touches receiver
// READY. Its connection must be the separately audited local publisher role.
// A future direct writer must separately enforce exclusive admission while
// transitioning from this read-only snapshot to SQL INSERT.
func AuditC1DirectCanonicalStart(ctx context.Context, publisherDSN string,
    original C1DirectCanonicalOriginal) (C1DirectCanonicalStartStatus,
    C1DirectCanonicalEvidence,error) {
    var e C1DirectCanonicalEvidence
    if ctx == nil { return C1DirectCanonicalBlocked,e,errors.New("C1 direct: context required") }
    if _,err:=EvaluateC1DirectCanonicalStart(original,C1DirectCanonicalEvidence{});err!=nil{
        return C1DirectCanonicalBlocked,e,err
    }
    conn,err:=openC1SoRLocalPublisherSQL(ctx,publisherDSN)
    if err!=nil {return C1DirectCanonicalBlocked,e,err}
    defer conn.Close(context.Background())
    tx,err:=conn.BeginTx(ctx,pgx.TxOptions{
        IsoLevel:pgx.RepeatableRead, AccessMode:pgx.ReadOnly,
    })
    if err!=nil{return C1DirectCanonicalBlocked,e,err}
    defer tx.Rollback(context.Background())

    var rec,bat *int64
    var receipt,transfer *string
    err=tx.QueryRow(ctx,`SELECT
        count(*)::bigint,
        max(record_count)::bigint,
        max(batch_count)::bigint,
        max(encode(receipt_sha256,'hex'))::text,
        max(encode(transfer_sha256,'hex'))::text
      FROM fi.recorded_generation
      WHERE source_id=$1 AND generation_id=$2`,
      original.SourceID,original.GenerationID).
      Scan(&e.ExistingGenerations,&rec,&bat,&receipt,&transfer)
    if err!=nil{return C1DirectCanonicalBlocked,e,fmt.Errorf("C1 direct: read-only generation: %w",err)}
    if rec!=nil{e.ExistingRecords=*rec}
    if bat!=nil{e.ExistingBatches=*bat}
    if receipt!=nil{e.ExistingReceiptSHA256=*receipt}
    if transfer!=nil{e.ExistingTransferSHA256=*transfer}

    err=tx.QueryRow(ctx,`SELECT count(*)::bigint,
       count(*) FILTER (WHERE records_committed=$3 AND transfer_sha256=decode($4,'hex'))::bigint
       FROM fi.ingest_journal
       WHERE source_id=$1 AND generation_id=$2 AND outcome='Accepted'`,
       original.SourceID,original.GenerationID,
       original.SignedRecords,original.TransferSHA256).
       Scan(&e.AcceptedEvents,&e.MatchingAcceptedEvents)
    if err!=nil{return C1DirectCanonicalBlocked,e,fmt.Errorf("C1 direct: read-only Accepted journal: %w",err)}
    err=tx.QueryRow(ctx,`SELECT count(*)::bigint FROM fi_c1_pending.generation_control
        WHERE source_id=$1 AND generation_id=$2`,
        original.SourceID,original.GenerationID).Scan(&e.PendingGenerations)
    if err!=nil{return C1DirectCanonicalBlocked,e,fmt.Errorf("C1 direct: read-only Pending status: %w",err)}
    status,err:=EvaluateC1DirectCanonicalStart(original,e)
    if err!=nil{return C1DirectCanonicalBlocked,e,err}
    if err=tx.Commit(ctx);err!=nil{return C1DirectCanonicalBlocked,e,err}
    return status,e,nil
}

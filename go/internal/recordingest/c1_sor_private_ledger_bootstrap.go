//go:build fi_c1_sor_dev

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// A completely NEW C1 signed generation needs its original private
// recorded_generation/source_batch SQL ledger before fi-ingest may hand off
// SourceParent rows. Only fi-sor owns this SQL transaction. The source is a
// cryptographically verified signed receiver bundle streamed without a
// duplicate durable 65+ GiB custody data copy.
package recordingest

import (
    "context"
    "encoding/binary"
    "encoding/hex"
    "errors"
    "fmt"

    "github.com/Iron-Signal-Systems/fi/go/internal/c1handoff"
    "github.com/jackc/pgx/v5"
)

// StageC1SignedPrivateMetadata is the only C1 new-generation initializer.
// A pre-existing stage or verified seed is preserved, never overwritten.
// All exact private ledger inserts are in ONE transaction, with no typed
// projection or canonical fi write.
func StageC1SignedPrivateMetadata(ctx context.Context,dsn string,
    frame c1handoff.Frame,custody c1NativeBCustodyConfig)error{
    if ctx==nil||frame.Kind!=c1handoff.Start||
        frame.StartBatchIndex!=0{
        return errors.New("C1 bootstrap: only an entirely new signed generation can initialize private SQL metadata")
    }
    if err:=frame.Validate();err!=nil{return err}
    conn,_,err:=openC1SoRLocalSQL(ctx,dsn,"")
    if err!=nil{return err}
    defer conn.Close(context.Background())
    var prior,other int64
    err=conn.QueryRow(ctx,`SELECT
        (SELECT count(*) FROM fi_recovery_projection.recorded_generation
         WHERE source_id=$1 AND generation_id=$2 AND receipt_sha256=$3),
        (SELECT count(*) FROM fi_recovery_projection.recorded_generation)`,
        frame.SourceID,frame.GenerationID,mustC1ReceiptDigest(frame.ReceiptSHA256)).
        Scan(&prior,&other)
    if err!=nil{return err}
    if prior>0{
        // Only the normal strict fi-sor START stage preflight can accept an
        // already-present seed/partial private generation.
        return nil
    }
    if other!=0{
        return errors.New("C1 bootstrap: foreign or conflicting private generation exists")
    }
    original,err:=c1StreamOriginalSignedManifestPlan(ctx,frame.SourceID,
        frame.GenerationID,custody)
    if err!=nil{return err}
    if original.ReceiptSHA256!=frame.ReceiptSHA256||
        int64(original.Receipt.RecordCount)!=frame.ExpectedRecords||
        len(original.Batches)!=len(frame.BatchIDs){
        return errors.New("C1 bootstrap: incoming mTLS signed START mismatches immutable original receipt")
    }
    for i,b:=range original.Batches{
        if b.BatchID!=frame.BatchIDs[i]{
            return fmt.Errorf("C1 bootstrap: original signed batch name/order mismatch %d",i)
        }
    }
    tx,err:=conn.Begin(ctx)
    if err!=nil{return err}
    defer tx.Rollback(context.Background())
    // Serialize the exact signed receipt bootstrap, including multiple
    // concurrent fi-sor processes. A PostgreSQL transaction advisory lock
    // is released automatically on COMMIT/ROLLBACK.
    key:=int64(binary.BigEndian.Uint64(mustC1ReceiptDigest(frame.ReceiptSHA256)[:8]))
    if _,err=tx.Exec(ctx,`SELECT pg_advisory_xact_lock($1::bigint)`,key);err!=nil{
        return err
    }
    var canonical bool
    if err=tx.QueryRow(ctx,`SELECT EXISTS(
        SELECT 1 FROM fi.recorded_generation WHERE source_id=$1
        AND generation_id=$2)`,frame.SourceID,frame.GenerationID).
        Scan(&canonical);err!=nil{return err}
    if canonical{return errors.New("C1 bootstrap: signed generation already canonical")}
    // A new generation MUST own an empty private projection schema. If
    // any old natural NTFS identity or source-child row remains from an
    // interrupted/accepted run, refuse to merge or delete it implicitly.
    tables,err:=bootstrapListTables(ctx,tx,privateProjectionSchema)
    if err!=nil{return err}
    if len(tables)<40{return errors.New("C1 bootstrap: full private FI projection schema unavailable")}
    for _,table:=range tables{
        quoted:=pgx.Identifier{privateProjectionSchema,table}.Sanitize()
        var rows int64
        if err=tx.QueryRow(ctx,"SELECT count(*) FROM "+quoted).Scan(&rows);err!=nil{return err}
        if rows!=0{
            return fmt.Errorf("C1 bootstrap: private table %s already contains data; no automatic reset",table)
        }
    }
    // Existing recovery markers from any signed generation would change
    // the publication trust boundary, even if the projected rows are empty.
    for _,table:=range []string{"verified_artifact_window","source_window",
        "typed_window","pending_source_record","projected_source_record"}{
        var rows int64
        quoted:=pgx.Identifier{"fi_recovery",table}.Sanitize()
        if err=tx.QueryRow(ctx,"SELECT count(*) FROM "+quoted).Scan(&rows);err!=nil{return err}
        if rows!=0{
            return fmt.Errorf("C1 bootstrap: foreign recovery marker rows in %s",table)
        }
    }
    // Use the EXISTING C1/ordinary FI SQL insertion semantics, redirecting
    // only known canonical fi table names into private projection. No
    // second schema writer and no direct fi-ingest PostgreSQL dependency.
    ids,err:=c1StageOriginalPrivateLedgerTx(ctx,tx,original)
    if err!=nil{return err}
    if err=tx.Commit(ctx);err!=nil{
        return fmt.Errorf("C1 bootstrap: private signed batch metadata SQL COMMIT outcome uncertain: %w",err)
    }
    fmt.Printf("FI C1 SOR PRIVATE SIGNED METADATA BOOTSTRAP COMMIT generation=%s signed_batches=%d signed_records=%d canonical_unchanged=true SQL_jail=fi-sor custody_copy=false\n",
        frame.GenerationID,len(ids),frame.ExpectedRecords)
    return nil
}

func mustC1ReceiptDigest(sha string)[]byte{
    // The authenticated START Frame.Validate() already guarantees exactly
    // 64 canonical hexadecimal SHA characters; decode cannot fail.
    decoded,_:=hex.DecodeString(sha)
    return decoded
}


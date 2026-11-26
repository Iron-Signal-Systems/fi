//go:build fi_c1_sor_dev

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// Development-only C1 native publication candidate. It reuses the already
// tested ONE transaction / 48-table populated-SoR remap and rollback engine;
// the private C1 SQL path has no separate legacy source-marker journal. A
// complete independent B proof is recomputed from ORIGINAL signed custody
// while the publisher holds all private staging table SHARE locks.
package recordingest

import (
    "context"
    "errors"
    "fmt"
    "math"

    "github.com/jackc/pgx/v5"
)

// Recreate only the already-authenticated original signed metadata required
// by the established SoR remapper. The canonical table-copy SQL never reads
// from this object's on-disk DataPath or from any shared-RAM handoff object.
func c1NativePromotionGeneration(p c1NativeBPlan)(*PreparedGeneration,error){
    if err:=c1ValidateNativeBPlan(p);err!=nil{return nil,err}
    var records uint64
    var bytes uint64
    for _,b:=range p.Batches{
        if b.Manifest.RecordCount<=0||b.Manifest.DataBytes<=0{
            return nil,errors.New("C1 promotion: invalid original signed batch")
        }
        if uint64(b.Manifest.RecordCount)>math.MaxInt64-records ||
            uint64(b.Manifest.DataBytes)>math.MaxInt64-bytes{
            return nil,errors.New("C1 promotion: original signed total exceeds SQL bounds")
        }
        records+=uint64(b.Manifest.RecordCount)
        bytes+=uint64(b.Manifest.DataBytes)
    }
    if records==0||bytes==0{
        return nil,errors.New("C1 promotion: empty or unverifiable original signed generation")
    }
    g:=&PreparedGeneration{
        Batches:append([]PreparedBatch(nil),p.Batches...),
        ReceiptSHA256:p.Start.ReceiptSHA256,
    }
    g.Receipt.Descriptor.SourceID=p.Start.SourceID
    g.Receipt.Descriptor.GenerationID=p.Start.GenerationID
    g.Receipt.TransferSHA256=p.Transfer
    g.Receipt.BatchCount=uint64(len(p.Batches))
    g.Receipt.RecordCount=records
    g.Receipt.DataBytes=bytes
    return g,nil
}

// The C1 signed-custody full proof binds exact receipts, every manifest,
// every JSONL record SHA, 13 typed roots and all USN capture dependencies.
// No false marker chain is manufactured and fi-ingest never opens SQL.
func c1NativeFullPromotionProof(ctx context.Context,conn *pgx.Conn,
    g *PreparedGeneration,p c1NativeBPlan,custody c1NativeBCustodyConfig)(
    BacklogGenerationVerification,error,
){
    return c1NativeFullPromotionProofWithTrust(ctx,conn,g,p,custody,
        loadInstalledGenerationTrust)
}

// The production publisher always runs the wrapper above with installed
// receiver trust. In disposable FreeBSD/PostgreSQL CI, this internal helper
// can independently authenticate a genuine locally signed receiver fixture
// without modifying global installed trust or replacing the SQL remapper.
func c1NativeFullPromotionProofWithTrust(ctx context.Context,conn *pgx.Conn,
    g *PreparedGeneration,p c1NativeBPlan,custody c1NativeBCustodyConfig,
    resolve generationTrustResolver)(BacklogGenerationVerification,error){
    if resolve==nil{
        return BacklogGenerationVerification{},errors.New("C1 promotion: receiver trust cannot be absent")
    }
    return c1NativeFullPromotionProofBy(ctx,conn,g,p,
        func(ctx context.Context,conn *pgx.Conn,p c1NativeBPlan)error{
            return c1NativeBVerifySignedCustodyWithTrust(ctx,conn,p,custody,resolve)
        })
}

// The live single-jail path requires an independent B-signed SQL identity
// commitment. The publisher holds SHARE locks over ALL Pending relations
// during this callback, and recomputes the exact source-row commitment
// directly from committed SQL. No second original JSONL transfer decode is
// necessary or permitted in this path. Offline legacy-test entrypoints
// retain the original full custody verifier above.
func c1NativeFullPromotionProofWithCommitment(ctx context.Context,conn *pgx.Conn,
    g *PreparedGeneration,p c1NativeBPlan,originalBCommitment string)(
    BacklogGenerationVerification,error){
    if !canonicalDigest(originalBCommitment){
        return BacklogGenerationVerification{},errors.New("C1 promotion: missing independently verified signed row commitment")
    }
    return c1NativeFullPromotionProofBy(ctx,conn,g,p,
        func(ctx context.Context,conn *pgx.Conn,p c1NativeBPlan)error{
            actual,err:=c1NativeBLockedSQLRowCommitment(ctx,conn,p)
            if err!=nil{return err}
            if actual!=originalBCommitment{
                return errors.New("C1 promotion: pending source changed after independent signed B group proof")
            }
            return nil
        })
}

// The SAME independent signed metadata, complete typed/USN coverage, and
// exact-generation SQL identity guards are required regardless of whether
// the source proof is original-custody replay (offline diagnostic only) or
// the lock-safe B-to-SQL commitment (single-jail live candidate).
func c1NativeFullPromotionProofBy(ctx context.Context,conn *pgx.Conn,
    g *PreparedGeneration,p c1NativeBPlan,
    verifyRows func(context.Context,*pgx.Conn,c1NativeBPlan)error)(
    BacklogGenerationVerification,error){
    var result BacklogGenerationVerification
    if ctx==nil||conn==nil||g==nil||verifyRows==nil{
        return result,errors.New("C1 promotion: missing independent original proof inputs")
    }
    if err:=c1ValidateNativeBPlan(p);err!=nil{return result,err}
    schema,err:=c1NativeBSchema(p)
    if err!=nil{return result,err}
    if g.ReceiptSHA256!=p.Start.ReceiptSHA256||
        g.Receipt.TransferSHA256!=p.Transfer||
        g.Receipt.Descriptor.SourceID!=p.Start.SourceID||
        g.Receipt.Descriptor.GenerationID!=p.Start.GenerationID{
        return result,errors.New("C1 promotion: generation plan changed since B proof")
    }
    if err:=c1NativeBValidateStage(ctx,conn,p);err!=nil{
        return result,fmt.Errorf("C1 promotion: signed private SQL stage: %w",err)
    }
    if err:=c1NativeBCompleteRelational(ctx,conn,g,p);err!=nil{
        return result,fmt.Errorf("C1 promotion: final private relational coverage: %w",err)
    }
    if err:=verifyRows(ctx,conn,p);err!=nil{
        return result,fmt.Errorf("C1 promotion: original signed row/locked SQL identity mismatch: %w",err)
    }
    tx,err:=conn.BeginTx(ctx,pgx.TxOptions{IsoLevel:pgx.RepeatableRead,AccessMode:pgx.ReadOnly})
    if err!=nil{return result,err}
    defer tx.Rollback(context.Background())
    shadow:=privateProjectionTx{Tx:tx,schema:schema}
    id,found,err:=lookupRecordedGeneration(ctx,shadow,p.Start.SourceID,
        p.Start.GenerationID,p.Transfer,p.Start.ReceiptSHA256)
    if err!=nil{return result,err}
    if !found||id<=0{return result,errors.New("C1 promotion: private SQL generation missing after custody proof")}
    if err=tx.Commit(ctx);err!=nil{return result,err}
    return BacklogGenerationVerification{
        SourceID:p.Start.SourceID,GenerationID:p.Start.GenerationID,
        ReceiptSHA256:p.Start.ReceiptSHA256,ShadowGenerationID:id,
        Windows:len(p.Descriptors),Records:g.Receipt.RecordCount,
        DataBytes:g.Receipt.DataBytes,
    },nil
}

// PromoteC1VerifiedToPopulatedSoR must be called ONLY after native B has
// reported complete independent read-only group/custody proof. The real
// database transaction repeats this same proof while locking ALL original
// staging tables, then reuses the standard populated canonical SoR remap.
// It is an explicit DEVELOPMENT candidate; do NOT enable on the C220
// authoritative PostgreSQL until real clean/dirty two-jail acceptance.
func PromoteC1VerifiedToPopulatedSoR(ctx context.Context,
    verifier,publisher *pgx.Conn,p c1NativeBPlan,custody c1NativeBCustodyConfig,
    attemptID string)(IngestResult,error){
    var empty IngestResult
    if ctx==nil||verifier==nil||publisher==nil||verifier==publisher||
        attemptID==""{
        return empty,errors.New("C1 promotion: two distinct local PostgreSQL connections and attempt required")
    }
    schema,err:=c1NativeBSchema(p)
    if err!=nil{return empty,err}
    g,err:=c1NativePromotionGeneration(p)
    if err!=nil{return empty,err}
    return promoteVerifiedBacklogToPopulatedSoRWithProofSchema(ctx,verifier,publisher,g,
        BacklogWindowLimits{},attemptID,
        func(ctx context.Context,conn *pgx.Conn,g *PreparedGeneration,_ BacklogWindowLimits)(
            BacklogGenerationVerification,error){
            return c1NativeFullPromotionProof(ctx,conn,g,p,custody)
        },schema)
}

// PromoteC1VerifiedToPopulatedSoRWithCommitment is the single-jail path.
// The shared PostgreSQL promotion engine takes Pending SHARE locks before
// invoking this callback and holds them until canonical Accepted commits.
// A changed SQL row SHA, ordinal, count, kind, scope, version or timestamp
// after B's proof fails closed before any canonical table-copy statement.
func PromoteC1VerifiedToPopulatedSoRWithCommitment(ctx context.Context,
    verifier,publisher *pgx.Conn,p c1NativeBPlan,
    attemptID,originalBCommitment string)(IngestResult,error){
    var empty IngestResult
    if ctx==nil||verifier==nil||publisher==nil||verifier==publisher||
        attemptID==""||!canonicalDigest(originalBCommitment){
        return empty,errors.New("C1 promotion: independent B row commitment and publisher required")
    }
    schema,err:=c1NativeBSchema(p)
    if err!=nil{return empty,err}
    g,err:=c1NativePromotionGeneration(p)
    if err!=nil{return empty,err}
    return promoteVerifiedBacklogToPopulatedSoRWithProofSchema(ctx,verifier,publisher,g,
        BacklogWindowLimits{},attemptID,
        func(ctx context.Context,conn *pgx.Conn,g *PreparedGeneration,_ BacklogWindowLimits)(
            BacklogGenerationVerification,error){
            return c1NativeFullPromotionProofWithCommitment(ctx,conn,g,p,originalBCommitment)
        },schema)
}

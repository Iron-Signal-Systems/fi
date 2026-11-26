//go:build fi_c1_sor_dev

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// This publication runs ONLY inside fi-sor after its independently executing
// verifier B has completed. All canonical writes use the existing populated
// FI PostgreSQL 18 cluster, never a replacement server or second SQL ingester.
package recordingest

import (
    "context"
    "crypto/rand"
    "encoding/hex"
    "errors"
    "fmt"

    "github.com/Iron-Signal-Systems/fi/go/internal/c1handoff"
    "github.com/jackc/pgx/v5"
)

// PublishC1VerifiedPendingGeneration is the SoR-local continuation of a
// separately completed B verification. It independently reopens ORIGINAL
// receiver custody, matches pending signed SQL metadata and uses the existing
// atomic, FK-remapping publisher (which repeats full custody proof under
// publication locks). Callers cannot fabricate FinalAccepted from its return;
// the canonical generation + Accepted journal must be read back separately.
func PublishC1VerifiedPendingGeneration(ctx context.Context,
    workerDSN,publisherDSN string,custody c1NativeBCustodyConfig,
    source,generation,receiptSHA string)(
    IngestResult,error){
    return publishC1VerifiedPendingGeneration(ctx,workerDSN,publisherDSN,
        custody,source,generation,receiptSHA,"")
}

// The single-jail production candidate MUST bring independent B's completed
// signed source-row commitment. The SQL publisher cannot manufacture B's
// evidence or take it from a network-supplied Drain/READY frame.
func PublishC1VerifiedPendingGenerationWithCommitment(ctx context.Context,
    workerDSN,publisherDSN string,custody c1NativeBCustodyConfig,
    source,generation,receiptSHA,bProof string)(IngestResult,error){
    if !canonicalDigest(bProof){
        return IngestResult{},errors.New("C1 canonical: missing independently verified B source-row evidence")
    }
    return publishC1VerifiedPendingGeneration(ctx,workerDSN,publisherDSN,
        custody,source,generation,receiptSHA,bProof)
}
func publishC1VerifiedPendingGeneration(ctx context.Context,
    workerDSN,publisherDSN string,custody c1NativeBCustodyConfig,
    source,generation,receiptSHA,bProof string)(
    IngestResult,error){
    var empty IngestResult
    if ctx==nil||source==""||generation==""||!canonicalDigest(receiptSHA){
        return empty,errors.New("C1 canonical: original signed generation identity required")
    }
    verifier,_,err:=openC1SoRLocalSQL(ctx,workerDSN,"")
    if err!=nil{return empty,fmt.Errorf("C1 canonical: independent local SQL proof: %w",err)}
    defer verifier.Close(context.Background())
    publisher,err:=openC1SoRLocalPublisherSQL(ctx,publisherDSN)
    if err!=nil{return empty,fmt.Errorf("C1 canonical: local SQL publisher: %w",err)}
    defer publisher.Close(context.Background())
    tx,err:=publisher.BeginTx(ctx,pgx.TxOptions{
        IsoLevel:pgx.RepeatableRead,AccessMode:pgx.ReadOnly,
    })
    if err!=nil{return empty,err}
    if err=c1ReadOnlyPublisherPrivileges(ctx,tx);err!=nil{
        _=tx.Rollback(context.Background())
        return empty,err
    }
    if err=tx.Commit(ctx);err!=nil{return empty,err}
    if verifier.PgConn().PID()==publisher.PgConn().PID(){
        return empty,errors.New("C1 canonical: verifier and publisher must be separate PostgreSQL backends")
    }
    plan,err:=LoadC1NativePromotionPlan(ctx,verifier,source,generation,
        custody,c1GovernedPendingSchema)
    if err!=nil{return empty,err}
    if plan.Start.ReceiptSHA256!=receiptSHA||plan.SQLSchema!=c1GovernedPendingSchema{
        return empty,errors.New("C1 canonical: immutable original custody differs from signed Drain")
    }
    // A new attempt marker cannot collide with earlier interrupted attempts.
    // Neither this ID nor the network Drain is proof of authorization.
    var random [16]byte
    if _,err=rand.Read(random[:]);err!=nil{return empty,err}
    attemptID:="fi-c1-"+hex.EncodeToString(random[:])
    var result IngestResult
    if bProof!=""{
        result,err=PromoteC1VerifiedToPopulatedSoRWithCommitment(
            ctx,verifier,publisher,plan,attemptID,bProof)
    }else{
        // Retained only for the separately named offline full-custody
        // diagnostic API; the single-jail service never uses this branch.
        result,err=PromoteC1VerifiedToPopulatedSoR(ctx,verifier,publisher,
            plan,custody,attemptID)
    }
    if err!=nil{return empty,err}
    if result.Outcome!="Accepted"&&result.Outcome!="AlreadyAccepted"{
        return empty,fmt.Errorf("C1 canonical: unexpected SQL result %q",result.Outcome)
    }
    return result,nil
}

// An authenticated ACK is issued only on a fresh read-only PostgreSQL
// snapshot of the exact canonical generation and matching Accepted journal.
func c1PostPublicationReadback(ctx context.Context,dsn,
    source,generation,receiptSHA string)(c1handoff.FinalStatus,error){
    state,err:=c1ReadCanonicalAcceptanceAfterB(ctx,dsn,source,generation,receiptSHA)
    if err!=nil{return c1handoff.FinalNone,err}
    if state!=c1handoff.FinalAccepted{
        return c1handoff.FinalNone,errors.New("C1 canonical: publication did not produce a complete Accepted snapshot")
    }
    return state,nil
}

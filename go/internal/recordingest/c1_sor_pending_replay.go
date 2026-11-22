//go:build fi_c1_sor_dev

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// Read-only restart admission for the existing governed pending generation.
// Each recovered handoff is subsequently checked against original custody
// and exact committed SQL record identity before any virtual COMMIT credit.
package recordingest

import (
    "context"
    "errors"
    "fmt"

    "github.com/Iron-Signal-Systems/fi/go/internal/c1handoff"
)

// c1InspectGovernedPendingReplay returns true ONLY for an exact existing
// pending generation after original signed custody and committed SQL prefix
// reconciliation. It does not change SQL or authorize automatic use of a
// dirty stage when AllowC1Replay is false.
func (s *C1SoRService)c1InspectGovernedPendingReplay(ctx context.Context,
    f c1handoff.Frame)(bool,error){
    if s==nil||ctx==nil||f.Kind!=c1handoff.Start||f.StartBatchIndex!=0{
        return false,errors.New("C1 pending replay: original full signed START required")
    }
    conn,_,err:=openC1SoRLocalSQL(ctx,s.DSN,"")
    if err!=nil{return false,err}
    defer conn.Close(context.Background())
    var existing int64
    if err=conn.QueryRow(ctx,"SELECT count(*) FROM fi_c1_pending.generation_control").
        Scan(&existing);err!=nil{return false,err}
    if existing==0{return false,nil}
    if existing!=1{return false,errors.New("C1 pending replay: foreign/duplicate generation control")}
    if !s.AllowC1Replay{
        return false,errors.New("C1 pending replay: explicit read-only reconciliation admission required")
    }
    original,err:=c1StreamOriginalSignedManifestPlan(ctx,
        f.SourceID,f.GenerationID,s.NativeBCustody)
    if err!=nil{return false,fmt.Errorf("C1 pending replay: immutable receiver custody: %w",err)}
    if original==nil||original.Receipt.Descriptor.SourceID!=f.SourceID||
        original.Receipt.Descriptor.GenerationID!=f.GenerationID||
        original.ReceiptSHA256!=f.ReceiptSHA256||
        int64(original.Receipt.RecordCount)!=f.ExpectedRecords||
        len(original.Batches)!=len(f.BatchIDs){
        return false,errors.New("C1 pending replay: original signed generation identity changed")
    }
    for i,b:=range original.Batches{
        if b.BatchID!=f.BatchIDs[i]{
            return false,fmt.Errorf("C1 pending replay: signed original batch order changed at index %d",i)
        }
    }
    audit,err:=AuditC1SoRPrivateRecovery(ctx,s.DSN,f,c1GovernedPendingSchema)
    if err!=nil{return false,fmt.Errorf("C1 pending replay: read-only PostgreSQL relational audit: %w",err)}
    if audit.SourceID!=f.SourceID||audit.GenerationID!=f.GenerationID||
        audit.ReceiptSHA256!=f.ReceiptSHA256||
        audit.SignedBatches!=len(f.BatchIDs)||
        audit.TotalExistingParents>f.ExpectedRecords||
        audit.SourceCompletePrefix<audit.RelationalCompletePrefix{
        return false,errors.New("C1 pending replay: inconsistent original and SQL replay evidence")
    }
    fmt.Printf("FI C1 PENDING REPLAY AUDIT source=%s generation=%s signed_batches=%d relational_prefix=%d parent_prefix=%d committed_parents=%d dirty_tail=%t read_only=true custody_preserved=true\n",
        audit.SourceID,audit.GenerationID,audit.SignedBatches,
        audit.RelationalCompletePrefix,audit.SourceCompletePrefix,
        audit.TotalExistingParents,audit.DirtyTail)
    return true,nil
}

//go:build fi_c1_sor_dev

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// The fi-sor jail answers an authenticated, read-only restart probe by
// independently reopening the ORIGINAL receiver-recorded receipt and the
// existing canonical fi.recorded_generation + Accepted journal. This
// cannot start a new generation, mutate a SQL stage, or acknowledge B
// verified but canonically unpublished work.
package recordingest

import (
    "context"
    "crypto/sha256"
    "crypto/subtle"
    "encoding/hex"
    "errors"
    "fmt"
    "path/filepath"

    "github.com/Iron-Signal-Systems/fi/go/internal/c1handoff"
    "github.com/Iron-Signal-Systems/fi/go/internal/generationrecorder"
)

// C1OriginalSignedStatus checks the exact source/generation/receipt against
// *original receiver custody* before it even consults canonical PostgreSQL.
// It yields FinalNone on an unaccepted generation and FinalAccepted only
// on a complete, matching, durable fi.ingest_journal transaction.
func C1OriginalSignedStatus(ctx context.Context,dsn string,
    custody C1NativeBCustodyConfig,f c1handoff.Frame)(
    c1handoff.FinalStatus,error,
){
    if ctx==nil||f.Kind!=c1handoff.Status||f.Sequence!=1||
        custody.RecordedRoot==""||!filepath.IsAbs(custody.RecordedRoot){
        return c1handoff.FinalNone,errors.New("C1 status: signed original receipt and first-frame status required")
    }
    if err:=f.Validate();err!=nil{return c1handoff.FinalNone,err}
    root:=custody.RecordedRoot
    if custody.SourceNamespaces{
        var err error
        root,err=generationrecorder.RecordedSourceDirectory(root,f.SourceID)
        if err!=nil{return c1handoff.FinalNone,err}
    }
    file:=filepath.Join(root,generationrecorder.RecordedReceiptObjectName(
        f.SourceID,f.GenerationID))
    raw,err:=readImmutableReceipt(file)
    if err!=nil{return c1handoff.FinalNone,fmt.Errorf("C1 status: receiver original receipt: %w",err)}
    original,err:=generationrecorder.UnmarshalRecordedReceipt(raw)
    if err!=nil{return c1handoff.FinalNone,err}
    if original.Descriptor.SourceID!=f.SourceID||
        original.Descriptor.GenerationID!=f.GenerationID{
        return c1handoff.FinalNone,errors.New("C1 status: original receiver receipt describes another signed generation")
    }
    requested,err:=hex.DecodeString(f.ReceiptSHA256)
    if err!=nil||len(requested)!=32{
        return c1handoff.FinalNone,errors.New("C1 status: signed receipt digest invalid")
    }
    actual:=sha256.Sum256(raw)
    if subtle.ConstantTimeCompare(requested,actual[:])!=1{
        return c1handoff.FinalNone,errors.New("C1 status: fi-ingest receipt differs from original receiver signed custody")
    }
    state,err:=c1ReadCanonicalAcceptanceAfterB(ctx,dsn,
        f.SourceID,f.GenerationID,f.ReceiptSHA256)
    if err!=nil{return c1handoff.FinalNone,err}
    if state==c1handoff.FinalVerified{
        // This is only a SQL/canonical status probe, not a new B run.
        return c1handoff.FinalNone,nil
    }
    if state!=c1handoff.FinalAccepted{
        return c1handoff.FinalNone,errors.New("C1 status: canonical acceptance readback returned untrusted state")
    }
    return c1handoff.FinalAccepted,nil
}

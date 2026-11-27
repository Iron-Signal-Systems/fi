//go:build fi_c1_sor_dev

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// FI C1 source-side READY queue processing, NO PostgreSQL client.
// A zero-byte ready marker is merely a scheduling hint. The original
// immutable recorded receipt and signed custody provide all authority.
// A ready marker is retired ONLY AFTER the peer fi-sor reports a full,
// independently B-verified canonical Accepted transaction.
package recordingest

import (
    "context"
    "crypto/sha256"
    "encoding/hex"
    "errors"
    "fmt"
    "path/filepath"

    "github.com/Iron-Signal-Systems/fi/go/internal/generationready"
    "github.com/Iron-Signal-Systems/fi/go/internal/generationrecorder"
)

type C1ReadyQueueConfig struct {
    ReadyRoot string
    SourceID string
    BatchSize uint64
    GenerationLoad GenerationLoadConfig
    Transport C1IngestTransport
}
type c1ReadyReceiptIdentity struct {
    generationID string
    receiptSHA string
}
type c1ReadyQueueOps struct {
    list func(string,string,uint64)([]string,error)
    identity func(C1ReadyQueueConfig,string)(c1ReadyReceiptIdentity,error)
    probe func(context.Context,C1IngestTransport,string,string,string)(bool,error)
    load func(GenerationLoadConfig,string)(*PreparedGeneration,error)
    ingest func(context.Context,*PreparedGeneration,C1IngestTransport)(C1IngestStageResult,error)
    remove func(string,string,[]string)error
}

// The digest embedded in a READY marker name is not the signed receipt
// SHA-256, nor does it encode the generation ID. Never parse a generation
// identity from the marker filename: read the original recorder receipt.
func c1OriginalReadyReceipt(c C1ReadyQueueConfig,marker string)(
    c1ReadyReceiptIdentity,error,
){
    var result c1ReadyReceiptIdentity
    recordedRoot:=c.GenerationLoad.RecordedRoot
    if c.GenerationLoad.SourceNamespaces {
        var err error
        recordedRoot,err=generationrecorder.RecordedSourceDirectory(
            recordedRoot,c.SourceID)
        if err!=nil{return result,err}
    }
    original,err:=readImmutableReceipt(filepath.Join(recordedRoot,marker))
    if err!=nil{return result,fmt.Errorf("C1 READY: original recorded receipt: %w",err)}
    receipt,err:=generationrecorder.UnmarshalRecordedReceipt(original)
    if err!=nil{return result,fmt.Errorf("C1 READY: invalid original receipt: %w",err)}
    if receipt.Descriptor.SourceID!=c.SourceID{
        return result,errors.New("C1 READY: original signed source differs from READY queue namespace")
    }
    generation:=receipt.Descriptor.GenerationID
    if generationrecorder.RecordedReceiptObjectName(c.SourceID,generation)!=marker{
        return result,errors.New("C1 READY: original receipt identity hash mismatches READY marker")
    }
    sum:=sha256.Sum256(original)
    return c1ReadyReceiptIdentity{
        generationID:generation,receiptSHA:hex.EncodeToString(sum[:]),
    },nil
}
func c1ReadyQueueOpsDefault() c1ReadyQueueOps {
    return c1ReadyQueueOps{
        list:generationready.ReadReceiptNamesForSource,
        identity:c1OriginalReadyReceipt,
        probe:ProbeC1CanonicalAccepted,
        load:LoadRecordedGeneration,
        ingest:RunC1IngestGeneration,
        remove:generationready.RemoveReceiptNamesForSource,
    }
}
func c1ReadyAccepted(c C1ReadyQueueConfig,want c1ReadyReceiptIdentity,
    signed *PreparedGeneration,result C1IngestStageResult)error{
    if signed==nil||want.generationID==""||len(want.receiptSHA)!=64||
        signed.Receipt.Descriptor.SourceID!=c.SourceID||
        signed.Receipt.Descriptor.GenerationID!=want.generationID||
        signed.ReceiptSHA256!=want.receiptSHA||
        result.SourceID!=c.SourceID||result.GenerationID!=want.generationID||
        result.ReceiptSHA256!=want.receiptSHA||
        signed.Receipt.RecordCount==0||
        signed.Receipt.RecordCount!=uint64(result.NewRecords)||
        signed.Receipt.BatchCount!=uint64(len(signed.Batches))||
        len(signed.Batches)!=result.SignedBatches||
        result.ReportingGroups<1{
        return errors.New("C1 READY: original receipt and mTLS-acknowledged generation identity/count mismatch")
    }
    if !result.RelationalCommitted||!result.IndependentlyVerified||
        !result.Published {
        return errors.New("C1 READY: signed source SQL/B stage not yet canonically Accepted; retain READY marker and original custody")
    }
    return nil
}
func c1ReadyQueueValidConfig(c C1ReadyQueueConfig)error{
    if c.SourceID==""||c.ReadyRoot==""||c.BatchSize==0||
        c.GenerationLoad.SourceID!=c.SourceID||
        c.GenerationLoad.RecordedRoot==""||c.GenerationLoad.CustodyRoot==""||
        c.Transport.SharedRAMDir==""||c.Transport.SoRAddress==""||
        c.Transport.StartBatch!=0{
        return errors.New("C1 READY: original source/receiver custody, bounded queue, fresh generation and fi-sor peer required")
    }
    // READY auto-run may not silently enter a private seed/partial replay.
    // Recovery and idempotency require separate SoR authoritative readback.
    return nil
}
func runC1ReadyQueuePass(ctx context.Context,c C1ReadyQueueConfig,
    op c1ReadyQueueOps)(uint64,error){
    if ctx==nil{return 0,errors.New("C1 READY: missing context")}
    if err:=c1ReadyQueueValidConfig(c);err!=nil{return 0,err}
    if op.list==nil||op.identity==nil||op.probe==nil||
        op.load==nil||op.ingest==nil||op.remove==nil{
        return 0,errors.New("C1 READY: complete original receipt and canonical acceptance handlers required")
    }
    markers,err:=op.list(c.ReadyRoot,c.SourceID,c.BatchSize)
    if err!=nil{return 0,fmt.Errorf("C1 READY: read source queue: %w",err)}
    var accepted uint64
    for _,marker:=range markers{
        if err:=ctx.Err();err!=nil{return accepted,err}
        want,err:=op.identity(c,marker)
        if err!=nil{return accepted,err}
        // An Accepted transaction may have completed before the previous
        // process crashed while its READY marker was still present.
        // Probe via a fresh TLS 1.3 fi-sor connection BEFORE staging up to
        // 64GiB of signed data or creating any SQL activity.
        alreadyAccepted,err:=op.probe(ctx,c.Transport,c.SourceID,
            want.generationID,want.receiptSHA)
        if err!=nil{
            return accepted,fmt.Errorf(
                "C1 READY: canonical readback uncertain; do not retry or retire marker: %w",err)
        }
        if alreadyAccepted{
            if err:=op.remove(c.ReadyRoot,c.SourceID,[]string{marker});err!=nil{
                return accepted,fmt.Errorf("C1 READY: previously Accepted generation marker retirement uncertain: %w",err)
            }
            accepted++
            fmt.Printf("FI C1 READY RECOVERED ACCEPTED source=%s generation=%s original_receipt=%s no_replay=true original_custody_preserved=true\n",
                c.SourceID,want.generationID,want.receiptSHA)
            continue
        }
        signed,err:=op.load(c.GenerationLoad,want.generationID)
        if err!=nil{return accepted,fmt.Errorf(
            "C1 READY: load original signed generation %s: %w",want.generationID,err)}
        if signed==nil{return accepted,errors.New("C1 READY: empty original generation")}
        // No PostgreSQL credentials or SQL connections cross into fi-ingest.
        // The SoR's actual final Drain ACK must assert canonical Accepted,
        // independently proven against its original fi.ingest_journal.
        result,runErr:=op.ingest(ctx,signed,c.Transport)
        acceptErr:=c1ReadyAccepted(c,want,signed,result)
        closeErr:=signed.Close()
        if runErr!=nil{
            return accepted,errors.Join(
                fmt.Errorf("C1 READY: fi-sor SQL/B/canonical processing: %w",runErr),
                closeErr)
        }
        if acceptErr!=nil||closeErr!=nil{
            return accepted,errors.Join(acceptErr,closeErr)
        }
        // Never remove an original receipt, generation custody, or batch.
        // Only remove this operational source READY scheduling marker
        // after all stages and cleanup have independently succeeded.
        if err:=op.remove(c.ReadyRoot,c.SourceID,[]string{marker});err!=nil{
            return accepted,fmt.Errorf("C1 READY: canonical Accepted but queue retirement uncertain: %w",err)
        }
        accepted++
        fmt.Printf("FI C1 READY RETIRED source=%s generation=%s receipt_sha256=%s canonical_accepted=true b_verified=true original_custody_preserved=true\n",
            c.SourceID,want.generationID,want.receiptSHA)
    }
    return accepted,nil
}

// RunC1ReadyQueuePass is ONE bounded pass. A failure (including an
// uncertain SQL commit or B-only proof) stops immediately; never retry a
// partially committed generation without first reconciling canonical SoR.
func RunC1ReadyQueuePass(ctx context.Context,c C1ReadyQueueConfig)(uint64,error){
    return runC1ReadyQueuePass(ctx,c,c1ReadyQueueOpsDefault())
}

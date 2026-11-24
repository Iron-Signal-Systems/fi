//go:build fi_c1_sor_dev

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// Same receiver READY markers and immutable receipts as the historical
// queue. Only fi-sor is a consumer; fi-ingest never participates.
package recordingest

import (
    "context"
    "errors"
    "fmt"
    "path/filepath"
    "time"

    "github.com/Iron-Signal-Systems/fi/go/internal/c1handoff"
    "github.com/Iron-Signal-Systems/fi/go/internal/generationready"
    "github.com/Iron-Signal-Systems/fi/go/internal/generationrecorder"
)

func RunC1SoRLocalReadyPass(ctx context.Context,c C1SoRLocalConfig,
    readyRoot string,batchSize uint64)(int,error){
    if ctx==nil||readyRoot==""||batchSize==0{
        return 0,errors.New("FI C1 local READY: original source READY root and bounded pass required")
    }
    if err:=validateC1SoRLocalConfig(c);err!=nil{return 0,err}
    markers,err:=generationready.ReadReceiptNamesForSource(readyRoot,c.SourceID,batchSize)
    if err!=nil{return 0,err}
    accepted:=0
    load:=C1SoRLocalGenerationLoad(c)
    for _,marker:=range markers{
        if err=ctx.Err();err!=nil{return accepted,err}
        want,err:=c1OriginalReadyReceipt(C1ReadyQueueConfig{
            SourceID:c.SourceID,GenerationLoad:load,
        },marker)
        if err!=nil{return accepted,err}
        status,err:=c1ReadCanonicalAcceptanceAfterB(ctx,c.WorkerDSN,
            c.SourceID,want.generationID,want.receiptSHA)
        if err!=nil{return accepted,fmt.Errorf("FI C1 local READY: canonical read-only status: %w",err)}
        if status!=c1handoff.FinalAccepted{
            if status!=c1handoff.FinalVerified{
                return accepted,errors.New("FI C1 local READY: unsafe canonical status")
            }
            overallStart:=time.Now()
            g,e:=LoadRecordedGeneration(load,want.generationID)
            if e!=nil{return accepted,fmt.Errorf("FI C1 local READY: original signed custody: %w",e)}
            extractionElapsed:=time.Since(overallStart)
            result,runErr:=RunC1SoRLocalGeneration(ctx,c,g)
            closeErr:=g.Close()
            completeElapsed:=time.Since(overallStart)
            if runErr!=nil||closeErr!=nil{
                return accepted,errors.Join(runErr,closeErr)
            }
            if !result.CanonicalAccepted||!result.IndependentlyVerified||
               result.ReceiptSHA256!=want.receiptSHA||
               result.GenerationID!=want.generationID{
                return accepted,errors.New("FI C1 local READY: signed Accepted proof did not match original receipt")
            }
            fmt.Printf("FI C1 SOR LOCAL END TO END source=%s generation=%s records=%d verify_extract_seconds=%.3f ingestion_seconds=%.3f entire_wall_seconds=%.3f effective_rec_s=%.2f canonical_accepted=true signed_custody_preserved=true\n",
                c.SourceID,want.generationID,result.Records,
                extractionElapsed.Seconds(),result.IngestElapsed.Seconds(),
                completeElapsed.Seconds(),float64(result.Records)/completeElapsed.Seconds())
        }
        // Only scheduling marker retirement is authorized. Original
        // signed custody, recorded receipts and generation remain immutable.
        if err=generationready.RemoveReceiptNamesForSource(readyRoot,
            c.SourceID,[]string{marker});err!=nil{
            return accepted,fmt.Errorf("FI C1 local READY: Accepted but marker retirement uncertain: %w",err)
        }
        accepted++
        fmt.Printf("FI C1 SOR LOCAL READY RETIRED source=%s generation=%s canonical_accepted=true original_custody_preserved=true\n",
            c.SourceID,want.generationID)
    }
    return accepted,nil
}

// C1SoRLocalRecordedReceipt is a read-only explicit-generation preflight.
// The recorded receipt is an exact signed source identity, not a READY hint.
func C1SoRLocalRecordedReceipt(c C1SoRLocalConfig,generationID string)(string,error){
    if err:=validateC1SoRLocalConfig(c);err!=nil{return "",err}
    if generationID==""{return "",errors.New("FI C1 local: generation required")}
    name:=generationrecorder.RecordedReceiptObjectName(c.SourceID,generationID)
    root:=c.Custody.RecordedRoot
    if c.Custody.SourceNamespaces{
        var err error
        root,err=generationrecorder.RecordedSourceDirectory(root,c.SourceID)
        if err!=nil{return "",err}
    }
    // c1OriginalReadyReceipt uses the unchanged receipt parser, validates
    // original source and digest, and does not touch READY state.
    identity,err:=c1OriginalReadyReceipt(C1ReadyQueueConfig{
        SourceID:c.SourceID,GenerationLoad:C1SoRLocalGenerationLoad(c),
    },filepath.Base(filepath.Join(root,name)))
    if err!=nil{return "",err}
    if identity.generationID!=generationID{return "",errors.New("FI C1 local: recorded receipt generation changed")}
    return identity.receiptSHA,nil
}

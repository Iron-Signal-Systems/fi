// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// DEV ONLY: construct a NEW W512 signed window plan from an existing,
// receiver-authenticated cache WITHOUT re-admitting its historical signer.
//
// The immutable recorded receipt and the cache publication marker are the
// historical admission evidence. This never publishes or grants Accepted,
// and does not alter the current FI transport trust policy. Every original
// cached manifest is parsed; selected window-0 data is rehashed and checked
// against its original manifest before being exposed for private SQL replay.
package recordingest

import (
    "bytes"
    "context"
    "crypto/sha256"
    "encoding/hex"
    "errors"
    "fmt"
    "os"
    "path/filepath"

    "github.com/Iron-Signal-Systems/fi/go/internal/generationrecorder"
    "github.com/Iron-Signal-Systems/fi/go/internal/spool"
)

// LoadPrivateW512FirstWindowFromAdmittedCache builds W512 descriptors from
// receiver-admitted immutable generation evidence, not from W128 SQL markers.
//
// This is usable only by the disposable private W512 seed CLI path. A failed
// metadata, cache, manifest, signed-data or ordering gate fails BEFORE the
// first private source or typed checkpoint is recorded.
func LoadPrivateW512FirstWindowFromAdmittedCache(
    ctx context.Context,
    config GenerationLoadConfig,
    generationID string,
    cacheRoot string,
    limits BacklogWindowLimits,
) (*PreparedGeneration, error) {
    if ctx == nil {
        return nil, errors.New("FI W512 admitted-cache seed: context required")
    }
    if err := ctx.Err(); err != nil { return nil, err }
    if err := validateGenerationLoadConfig(config, generationID); err != nil {
        return nil, err
    }
    if limits.MaxRecords != 524288 || limits.MaxDataBytes != 2<<30 {
        return nil, errors.New("FI W512 admitted-cache seed: unexpected window budgets")
    }
    if config.MaxManifestBytes == 0 || config.MaxManifestBytes > 1<<20 {
        return nil, errors.New("FI W512 admitted-cache seed: manifest budget too large")
    }
    if err := verifyPrivateBacklogRoot(cacheRoot); err != nil {
        return nil, fmt.Errorf("FI W512 admitted-cache seed: cache root: %w", err)
    }
    receiptRoot := config.RecordedRoot
    if config.SourceNamespaces {
        var err error
        receiptRoot, err = generationrecorder.RecordedSourceDirectory(receiptRoot,config.SourceID)
        if err != nil { return nil, err }
    }
    raw, err := readImmutableReceipt(filepath.Join(receiptRoot,
        generationrecorder.RecordedReceiptObjectName(config.SourceID,generationID)))
    if err != nil {
        return nil, fmt.Errorf("FI W512 admitted-cache seed: original immutable receipt: %w",err)
    }
    receipt, err := generationrecorder.UnmarshalRecordedReceipt(raw)
    if err != nil { return nil, err }
    if receipt.Descriptor.SourceID != config.SourceID ||
        receipt.Descriptor.GenerationID != generationID ||
        receipt.BatchCount == 0 || receipt.RecordCount == 0 || receipt.DataBytes == 0 {
        return nil, errors.New("FI W512 admitted-cache seed: receipt identity/totals invalid")
    }
    digest := sha256.Sum256(raw)
    receiptHash := hex.EncodeToString(digest[:])

    // The marker is published only after successful FIRST receiver-signing
    // admission and full original transfer verification. Its contents must
    // exactly match the immutable recorded receipt; missing marker is fatal.
    directory, err := backlogVerifiedCacheOpen(cacheRoot,receiptHash,
        receipt.TransferSHA256,receipt.BatchCount,receipt.RecordCount,receipt.DataBytes)
    if err != nil {
        return nil, fmt.Errorf("FI W512 admitted-cache seed: prior verified-cache admission: %w",err)
    }
    if receipt.BatchCount > 20000 {
        return nil, errors.New("FI W512 admitted-cache seed: unexpected batch count")
    }

    batches := make([]PreparedBatch,0,int(receipt.BatchCount))
    previousID := ""
    for i:=0;i<int(receipt.BatchCount);i++ {
        if err := ctx.Err(); err != nil { return nil, err }
        manifestPath := backlogCacheBatchManifest(directory,i)
        original, err := readBacklogStageFile(manifestPath,int64(config.MaxManifestBytes))
        if err != nil {
            return nil, fmt.Errorf("FI W512 admitted-cache seed: original manifest %d: %w",i,err)
        }
        m, err := spool.DecodeManifest(bytes.NewReader(original))
        if err != nil {
            return nil, fmt.Errorf("FI W512 admitted-cache seed: manifest %d decode: %w",i,err)
        }
        if m.BatchID == "" || (previousID!="" && m.BatchID<=previousID) ||
            m.DataFile!="batch-"+m.BatchID+".jsonl" ||
            m.RecordCount<=0 || m.DataBytes<=0 ||
            uint64(m.RecordCount)>limits.MaxRecords || uint64(m.DataBytes)>limits.MaxDataBytes {
            return nil,fmt.Errorf("FI W512 admitted-cache seed: batch %d ordering/identity/bounds invalid",i)
        }
        previousID=m.BatchID
        dataPath:=backlogCacheBatchData(directory,i)
        stat,err:=os.Lstat(dataPath)
        if err!=nil {return nil,fmt.Errorf("FI W512 admitted-cache seed: data %d: %w",i,err)}
        if !stat.Mode().IsRegular() || stat.Mode().Perm()!=0600 ||
            stat.Size()!=m.DataBytes {
            return nil,fmt.Errorf("FI W512 admitted-cache seed: data %d inode/size mismatch",i)
        }
        manifestHash:=sha256.Sum256(original)
        batches=append(batches,PreparedBatch{
            BatchID:m.BatchID,DataArtifactName:m.DataFile,
            Manifest:m,ManifestArtifactName:"batch-"+m.BatchID+".manifest.json",
            ManifestBytes:len(original),ManifestRawBytes:original,
            ManifestSHA256:hex.EncodeToString(manifestHash[:]),
        })
    }
    g:=&PreparedGeneration{
        Batches:batches,Receipt:receipt,ReceiptSHA256:receiptHash,
        ReceiptBytes:len(raw),ReceiptRawBytes:append([]byte(nil),raw...),
    }
    windows,err:=PlanBacklogWindows(g,limits)
    if err!=nil{return nil,fmt.Errorf("FI W512 admitted-cache seed: deterministic signed batch plan: %w",err)}
    if len(windows)<2 || windows[0].StartBatch!=0 || windows[0].EndBatch<=0 {
        return nil,errors.New("FI W512 admitted-cache seed: no bounded first window")
    }
    // This path rechecks every selected batch SHA/record count, not a CRL.
    // Full-generation acceptance was already performed by the receiver and
    // is recorded by the receipt-bound published immutable cache marker.
    for i:=windows[0].StartBatch;i<windows[0].EndBatch;i++ {
        if err:=ctx.Err();err!=nil{return nil,err}
        p:=backlogCacheBatchData(directory,i)
        before,err:=os.Lstat(p)
        if err!=nil{return nil,err}
        f,err:=os.Open(p)
        if err!=nil{return nil,err}
        opened,statErr:=f.Stat()
        if statErr==nil && !os.SameFile(before,opened) {
            statErr=errors.New("FI W512 admitted-cache seed: selected data inode changed")
        }
        var inspected spool.DataInspection
        if statErr==nil {inspected,statErr=spool.InspectData(f)}
        statErr=errors.Join(statErr,f.Close())
        if statErr!=nil{return nil,fmt.Errorf("FI W512 admitted-cache seed: selected data %d: %w",i,statErr)}
        if err=spool.VerifyManifestData(g.Batches[i].Manifest,inspected);err!=nil {
            return nil,fmt.Errorf("FI W512 admitted-cache seed: signed data %d: %w",i,err)
        }
        // Preserve the original manifest from the already validated cache:
        // both original-byte content and durable SQL source metadata need it.
        g.Batches[i].DataPath=p
    }
    fmt.Printf("FI W512 RECEIVER-ADMITTED CACHE BOOTSTRAP PASS original_batches=%d source_records=%d first_window_batches=%d first_window_records=%d receipt=%s current_crl_admission=not_repeated selected_manifest_data_sha256=verified\n",
        len(g.Batches),g.Receipt.RecordCount,windows[0].EndBatch,
        windows[0].EndRecord,receiptHash)
    return g,nil
}

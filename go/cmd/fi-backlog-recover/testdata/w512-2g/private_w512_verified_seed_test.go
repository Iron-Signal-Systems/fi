// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// Replays the prior receiver-admitted cache WITHOUT a trust resolver or new
// signing CRL. The selected data must still match its original manifests.
package recordingest

import (
    "bytes"
    "context"
    "crypto/sha256"
    "encoding/hex"
    "encoding/json"
    "fmt"
    "os"
    "path/filepath"
    "strings"
    "testing"

    "github.com/Iron-Signal-Systems/fi/go/internal/generationrecorder"
    "github.com/Iron-Signal-Systems/fi/go/internal/spool"
    "github.com/Iron-Signal-Systems/fi/go/internal/transportgeneration"
)

func TestPrivateW512ReceiverAdmittedCacheSeedAndTamperRejection(t *testing.T) {
    root:=t.TempDir()
    cache:=filepath.Join(root,"cache")
    if err:=os.Mkdir(cache,0700);err!=nil{t.Fatal(err)}
    source:="iss-fs-01.iss.local"
    gen:="20261110T120000.000000000Z-0123456789abcdef"
    data:=bytes.Repeat([]byte("{}\n"),8192)
    dataHash:=sha256.Sum256(data)
    const nBatches=65
    receipt:=generationrecorder.RecordedReceipt{
        Version:generationrecorder.RecordedReceiptVersion,
        Descriptor:transportgeneration.Descriptor{
            Version:transportgeneration.DescriptorVersion,
            SourceID:source,GenerationID:gen,
            CanonicalVersion:transportgeneration.CanonicalVersion,
            DataEncoding:"zstd",
            ArtifactCount:2*nBatches,SourceBytes:2<<20,
            CanonicalBytes:3<<20,CanonicalSHA256:strings.Repeat("1",64),
            EncodedDataBytes:1024,EncodedDataSHA256:strings.Repeat("2",64),
        },
        MetadataBytes:512,MetadataSHA256:strings.Repeat("3",64),
        TransferBytes:20+512+1024,TransferSHA256:strings.Repeat("4",64),
        BatchCount:nBatches,DataBytes:uint64(len(data)*nBatches),
        RecordCount:8192*nBatches,
    }
    raw,err:=generationrecorder.MarshalRecordedReceipt(receipt)
    if err!=nil{t.Fatal(err)}
    receiptFile:=filepath.Join(root,generationrecorder.RecordedReceiptObjectName(source,gen))
    if err:=os.WriteFile(receiptFile,raw,0400);err!=nil{t.Fatal(err)}
    rHash:=sha256.Sum256(raw)
    rHex:=hex.EncodeToString(rHash[:])
    pending,err:=backlogVerifiedCacheBegin(cache,rHex)
    if err!=nil{t.Fatal(err)}
    for i:=0;i<nBatches;i++ {
        batchID:=fmt.Sprintf("20261110T120%02d%02d.000000000Z-%016x",i/60,i%60,i+1)
        m:=spool.Manifest{
            Version:spool.ManifestVersion,BatchID:batchID,
            TargetBatchSize:8192,RecordCount:8192,
            DataBytes:int64(len(data)),DataSHA256:hex.EncodeToString(dataHash[:]),
            DataFile:"batch-"+batchID+".jsonl",
            Collector:spool.CollectorIdentity{ExecutablePath:"C:\\FI\\Collector.exe",
                ExecutableSHA256:hex.EncodeToString(dataHash[:])},
            CreatedAt:"2026-11-10T12:00:00Z",
            CompletedAt:"2026-11-10T12:00:01Z",
        }
        manifest,err:=json.Marshal(m)
        if err!=nil{t.Fatal(err)}
        if err:=writeBacklogStageFile(backlogCacheBatchData(pending,i),data);err!=nil{t.Fatal(err)}
        if err:=writeBacklogStageFile(backlogCacheBatchManifest(pending,i),manifest);err!=nil{t.Fatal(err)}
    }
    if err:=backlogVerifiedCacheCommit(cache,pending,rHex,receipt.TransferSHA256,
        receipt.BatchCount,receipt.RecordCount,receipt.DataBytes);err!=nil{t.Fatal(err)}
    cfg:=GenerationLoadConfig{
        CustodyRoot:root,RecordedRoot:root,SourceID:source,
        MaxEncodedBytes:64<<30,MaxCanonicalBytes:64<<30,MaxManifestBytes:1<<20,
    }
    limits:=BacklogWindowLimits{MaxRecords:524288,MaxDataBytes:2<<30}
    g,err:=LoadPrivateW512FirstWindowFromAdmittedCache(context.Background(),cfg,gen,cache,limits)
    if err!=nil{t.Fatalf("valid previously admitted cache rejected: %v",err)}
    if len(g.Batches)!=nBatches || g.Batches[0].DataPath=="" ||
        g.Batches[63].DataPath=="" || g.Batches[64].DataPath!="" ||
        g.Batches[64].ManifestRawBytes==nil {
        t.Fatal("unexpected W512 seed descriptor selection or missing raw manifest")
    }
    windows,err:=PlanBacklogWindows(g,limits)
    if err!=nil||len(windows)!=2||windows[0].EndRecord!=524288 {
        t.Fatalf("W512 partition=%+v error=%v",windows,err)
    }

    dir:=backlogVerifiedCacheDirectory(cache,rHex)
    if err:=os.WriteFile(backlogCacheBatchData(dir,0),[]byte("{\"tampered\":true}\n"),0600);err!=nil{t.Fatal(err)}
    if _,err:=LoadPrivateW512FirstWindowFromAdmittedCache(context.Background(),cfg,gen,cache,limits);err==nil {
        t.Fatal("selected data tamper unexpectedly accepted")
    }
    if err:=os.WriteFile(backlogCacheBatchData(dir,0),data,0600);err!=nil{t.Fatal(err)}
    if err:=os.WriteFile(backlogCacheBatchManifest(dir,0),[]byte("{}"),0600);err!=nil{t.Fatal(err)}
    if _,err:=LoadPrivateW512FirstWindowFromAdmittedCache(context.Background(),cfg,gen,cache,limits);err==nil {
        t.Fatal("source manifest tamper unexpectedly accepted")
    }
    if _,err:=LoadPrivateW512FirstWindowFromAdmittedCache(context.Background(),cfg,gen,filepath.Join(root,"missing"),limits);err==nil {
        t.Fatal("missing admitted cache publication marker unexpectedly accepted")
    }
}

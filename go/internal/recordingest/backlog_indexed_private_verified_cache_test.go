// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package recordingest

import (
    "context"
    "crypto/sha256"
    "encoding/hex"
    "encoding/json"
    "os"
    "testing"

    "github.com/Iron-Signal-Systems/fi/go/internal/spool"
)

// Receiver admission is proven by an immutable receipt-bound verified-cache
// marker, not by asking the original batch-signing CRL to be current again.
// Every selected payload and manifest is rehashed before SQL projection.
func TestIndexedPrivateVerifiedCacheNoCurrentCRLButExactOriginalHashes(t *testing.T) {
    root:=t.TempDir()
    if err:=os.Chmod(root,0700);err!=nil{t.Fatal(err)}
    receipt:=sha256.Sum256([]byte("original signed receipt"))
    transfer:=sha256.Sum256([]byte("receiver authenticated transfer"))
    receiptHex:=hex.EncodeToString(receipt[:])
    transferHex:=hex.EncodeToString(transfer[:])
    data:=[]byte("{}\n")
    dh:=sha256.Sum256(data)
    id:="20261110T000000.000000000Z-0123456789abcdef"
    manifest:=spool.Manifest{
        Version:spool.ManifestVersion,
        BatchID:id,TargetBatchSize:1,RecordCount:1,DataBytes:int64(len(data)),
        DataSHA256:hex.EncodeToString(dh[:]),DataFile:"batch-"+id+".jsonl",
        Collector:spool.CollectorIdentity{ExecutablePath:"C:\\FI\\Collector.exe",
            ExecutableSHA256:hex.EncodeToString(dh[:])},
        CreatedAt:"2026-11-10T00:00:00.000000000Z",
        CompletedAt:"2026-11-10T00:00:01.000000000Z",
    }
    sqlManifest:=manifest
    sqlManifest.CreatedAt="2026-11-10T00:00:00Z"
    sqlManifest.CompletedAt="2026-11-10T00:00:01Z"
    raw,err:=json.Marshal(manifest)
    if err!=nil{t.Fatal(err)}
    mh:=sha256.Sum256(raw)
    g:=&PreparedGeneration{
        Batches:[]PreparedBatch{{BatchID:id,Manifest:sqlManifest,
            ManifestSHA256:hex.EncodeToString(mh[:]),ManifestBytes:len(raw),
            DataArtifactName:manifest.DataFile}},
        ReceiptSHA256:receiptHex,
    }
    g.Receipt.TransferSHA256=transferHex
    g.Receipt.BatchCount=1
    g.Receipt.RecordCount=1
    g.Receipt.DataBytes=uint64(len(data))
    dir,err:=backlogVerifiedCacheBegin(root,receiptHex)
    if err!=nil{t.Fatal(err)}
    if err=writeBacklogStageFile(backlogCacheBatchData(dir,0),data);err!=nil{t.Fatal(err)}
    if err=writeBacklogStageFile(backlogCacheBatchManifest(dir,0),raw);err!=nil{t.Fatal(err)}
    if err=backlogVerifiedCacheCommit(root,dir,receiptHex,transferHex,1,1,uint64(len(data)));err!=nil{t.Fatal(err)}
    cfg:=GenerationLoadConfig{MaxManifestBytes:1<<20}
    got,err:=indexedBacklogPreparedFromVerifiedCache(context.Background(),g,cfg,root,0,1)
    if err!=nil{t.Fatalf("receiver-authenticated cache rejected: %v",err)}
    if got.Batches[0].DataPath==""||len(got.Batches[0].ManifestRawBytes)!=len(raw) {
        t.Fatal("authenticated selected batch bytes missing")
    }
    cd:=backlogVerifiedCacheDirectory(root,receiptHex)
    if err=os.WriteFile(backlogCacheBatchData(cd,0),[]byte("{\"tampered\":true}\n"),0600);err!=nil{t.Fatal(err)}
    if _,err=indexedBacklogPreparedFromVerifiedCache(context.Background(),g,cfg,root,0,1);err==nil{
        t.Fatal("mutated recorded data accepted despite original SHA mismatch")
    }
    if err=os.WriteFile(backlogCacheBatchData(cd,0),data,0600);err!=nil{t.Fatal(err)}
    if err=os.WriteFile(backlogCacheBatchManifest(cd,0),[]byte("{}"),0600);err!=nil{t.Fatal(err)}
    if _,err=indexedBacklogPreparedFromVerifiedCache(context.Background(),g,cfg,root,0,1);err==nil{
        t.Fatal("mutated signed manifest accepted")
    }
    if _,err=indexedBacklogPreparedFromVerifiedCache(context.Background(),g,cfg,
        t.TempDir(),0,1);err==nil{
        t.Fatal("missing prior receipt-bound cache marker accepted")
    }
}

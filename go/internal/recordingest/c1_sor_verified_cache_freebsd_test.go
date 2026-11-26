//go:build freebsd && fi_c1_sor_dev

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// Fast C1 input must reuse the original receiver-authenticated cache, without
// a second decompression pass, while refusing an unsafe/missing cache.
package recordingest

import (
    "bytes"
    "context"
    "crypto/sha256"
    "encoding/hex"
    "errors"
    "os"
    "path/filepath"
    "testing"

    "github.com/Iron-Signal-Systems/fi/go/internal/spool"
)

func TestC1SoRBenchmarkVerifiedCacheMatchesSignedReceiver(t *testing.T){
    root:=t.TempDir()
    source:="c1-cached-fixture.iss.local"
    for _,name:=range []string{"custody","recorded","ready",
        filepath.Join("recorded","sources",source),"cache"}{
        if err:=os.MkdirAll(filepath.Join(root,name),0700);err!=nil{t.Fatal(err)}
    }
    signed:=m1WriteSignedGeneration(t,root,source)
    cfg:=c1NativeBCustodyConfig{
        CustodyRoot:filepath.Join(root,"custody"),
        RecordedRoot:filepath.Join(root,"recorded"),
        SourceNamespaces:true,MaxCanonicalBytes:64<<20,
        MaxEncodedBytes:64<<20,MaxManifestBytes:1<<20,
    }
    trust:=func(id string)(generationTrustBundle,error){
        if id!=source{return generationTrustBundle{},errors.New("unexpected source")}
        return signed.Trust,nil
    }
    authenticated,err:=c1StreamOriginalSignedManifestPlanWithTrust(
        context.Background(),source,signed.GenerationID,cfg,trust)
    if err!=nil{t.Fatal(err)}
    cacheRoot:=filepath.Join(root,"cache")
    pending,err:=backlogVerifiedCacheBegin(cacheRoot,authenticated.ReceiptSHA256)
    if err!=nil{t.Fatal(err)}
    for i,b:=range authenticated.Batches{
        raw,err:=os.ReadFile(filepath.Join(root,source,"frozen",b.DataArtifactName))
        if err!=nil{t.Fatal(err)}
        inspection,err:=spool.InspectData(bytes.NewReader(raw))
        if err!=nil{t.Fatal(err)}
        if err:=spool.VerifyManifestData(b.Manifest,inspection);err!=nil{t.Fatal(err)}
        if err:=writeBacklogStageFile(backlogCacheBatchData(pending,i),raw);err!=nil{t.Fatal(err)}
        if err:=writeBacklogStageFile(backlogCacheBatchManifest(pending,i),b.ManifestRawBytes);err!=nil{t.Fatal(err)}
    }
    if err:=backlogVerifiedCacheCommit(cacheRoot,pending,
        authenticated.ReceiptSHA256,authenticated.Receipt.TransferSHA256,
        authenticated.Receipt.BatchCount,authenticated.Receipt.RecordCount,
        authenticated.Receipt.DataBytes);err!=nil{t.Fatal(err)}
    cfg.VerifiedCacheRoot=cacheRoot
    cfg.BenchmarkClone=true
    g,err:=c1SoRVerifiedCacheGeneration(context.Background(),source,signed.GenerationID,cfg)
    if err!=nil{t.Fatal(err)}
    if g.stagedDirectory!=""||g.ReceiptSHA256!=authenticated.ReceiptSHA256||
        len(g.Batches)!=len(authenticated.Batches)||
        g.Receipt.RecordCount!=authenticated.Receipt.RecordCount{
        t.Fatalf("authenticated C1 cache plan differs from original signed receipt: %#v",g)
    }
    for i,b:=range g.Batches{
        expected:=authenticated.Batches[i]
        if b.BatchID!=expected.BatchID||
            b.ManifestSHA256!=expected.ManifestSHA256||
            b.Manifest.DataSHA256!=expected.Manifest.DataSHA256||
            b.Manifest.DataBytes!=expected.Manifest.DataBytes||
            b.Manifest.RecordCount!=expected.Manifest.RecordCount{
            t.Fatalf("cached signed batch %d differs from authenticated original",i)
        }
        raw,err:=os.ReadFile(b.DataPath)
        if err!=nil{t.Fatal(err)}
        digest:=sha256.Sum256(raw)
        if hex.EncodeToString(digest[:])!=expected.Manifest.DataSHA256{
            t.Fatalf("cached signed original batch %d SHA changed",i)
        }
    }
    cfg.BenchmarkClone=false
    if _,err:=c1SoRVerifiedCacheGeneration(context.Background(),source,signed.GenerationID,cfg);err==nil{
        t.Fatal("C1 silently authorized untrusted cache outside isolated clone")
    }
    cfg.VerifiedCacheRoot=""
    cfg.ReceiverVerifiedCacheRoot=cacheRoot
    live,err:=c1SoRVerifiedCacheGeneration(context.Background(),source,signed.GenerationID,cfg)
    if err!=nil||live.ReceiptSHA256!=g.ReceiptSHA256||
        live.Receipt.RecordCount!=g.Receipt.RecordCount{
        t.Fatalf("live receiver cache source does not match original signed receipt: %v",err)
    }
    cfg.ReceiverVerifiedCacheRoot=""
    cfg.VerifiedCacheRoot=cacheRoot
    cfg.BenchmarkClone=true
    bad:=g.Batches[0].DataPath
    if err:=os.Chmod(bad,0644);err!=nil{t.Fatal(err)}
    if _,err:=c1SoRVerifiedCacheGeneration(context.Background(),source,signed.GenerationID,cfg);err==nil{
        t.Fatal("C1 accepted non-private verified-cache batch")
    }
}

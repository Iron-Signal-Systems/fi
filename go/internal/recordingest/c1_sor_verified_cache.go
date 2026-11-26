//go:build fi_c1_sor_dev

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// Receiver-authenticated verified batch cache input for native C1. The live
// SoR imports only a read-only receiver-published cache; independent B still
// verifies ORIGINAL signed FIGT custody and committed canonical SQL. The clone
// cache is restricted to isolated benchmark use. Neither is SQL authority.
package recordingest

import (
    "bytes"
    "context"
    "crypto/sha256"
    "encoding/hex"
    "errors"
    "fmt"
    "hash"
    "os"
    "path/filepath"

    "github.com/Iron-Signal-Systems/fi/go/internal/generationrecorder"
    "github.com/Iron-Signal-Systems/fi/go/internal/spool"
    "github.com/Iron-Signal-Systems/fi/go/internal/transportgeneration"
    "github.com/jackc/pgx/v5"
)

// c1SoRVerifiedCacheGeneration reproduces the original fast C1 development
// source plan from 8,399 previously authenticated cache batches. It never
// decompresses the 65GiB transfer to a SECOND directory. Each batch hash is
// checked independently by verifier B during processing, before publication.
func c1SoRVerifiedCacheGeneration(ctx context.Context,source,generation string,
    cfg c1NativeBCustodyConfig)(*PreparedGeneration,error){
    cacheRoot:=cfg.VerifiedCacheRoot
    mode:="clone"
    if cfg.BenchmarkClone {
        if cfg.ReceiverVerifiedCacheRoot!="" {return nil,errors.New("FI C1 cache: clone must not select live receiver cache")}
    } else {
        if cfg.VerifiedCacheRoot!="" {return nil,errors.New("FI C1 cache: clone cache forbidden on real SoR")}
        cacheRoot=cfg.ReceiverVerifiedCacheRoot
        mode="receiver"
    }
    if ctx==nil||source==""||generation==""||
        cacheRoot==""||!filepath.IsAbs(cacheRoot)||
        cfg.RecordedRoot==""||cfg.CustodyRoot==""||
        !filepath.IsAbs(cfg.RecordedRoot)||!filepath.IsAbs(cfg.CustodyRoot)||
        cfg.MaxManifestBytes==0||cfg.MaxManifestBytes>1<<20{
        return nil,errors.New("FI C1 cache: explicit isolated-clone, signed custody and bounded verified cache required")
    }
    root:=cfg.RecordedRoot
    if cfg.SourceNamespaces{
        var err error
        root,err=generationrecorder.RecordedSourceDirectory(root,source)
        if err!=nil{return nil,err}
    }
    raw,err:=readImmutableReceipt(filepath.Join(root,
        generationrecorder.RecordedReceiptObjectName(source,generation)))
    if err!=nil{return nil,fmt.Errorf("FI C1 cache: immutable signed receipt: %w",err)}
    receipt,err:=generationrecorder.UnmarshalRecordedReceipt(raw)
    if err!=nil{return nil,err}
    if receipt.Descriptor.SourceID!=source||
        receipt.Descriptor.GenerationID!=generation||
        receipt.BatchCount==0||receipt.BatchCount>65535{
        return nil,errors.New("FI C1 cache: receipt identity or batch count changed")
    }
    // Original immutable custody MUST continue to exist for recovery, even
    // though its compressed payload is not decoded again in this warm replay.
    original:=filepath.Join(cfg.CustodyRoot,
        transportgeneration.DurableCustodyObjectName(source,generation))
    stat,err:=os.Lstat(original)
    if err!=nil{return nil,err}
    if !stat.Mode().IsRegular()||stat.Mode().Perm()!=0400||stat.Size()<=0{
        return nil,errors.New("FI C1 cache: original receiver custody must remain immutable")
    }
    sum:=sha256.Sum256(raw)
    receiptSHA:=hex.EncodeToString(sum[:])
    var dir string
    readFile:=readBacklogStageFile
    if cfg.BenchmarkClone{
        dir,err=backlogVerifiedCacheOpen(cacheRoot,receiptSHA,
            receipt.TransferSHA256,receipt.BatchCount,receipt.RecordCount,receipt.DataBytes)
    }else{
        dir,err=c1ReceiverVerifiedCacheOpen(cacheRoot,receiptSHA,
            receipt.TransferSHA256,receipt.BatchCount,receipt.RecordCount,receipt.DataBytes)
        readFile=c1ReadReceiverVerifiedCacheFile
    }
    if err!=nil{return nil,fmt.Errorf("FI C1 cache: original authenticated checkpoint missing: %w",err)}
    batchCount:=int(receipt.BatchCount)
    batches:=make([]PreparedBatch,0,batchCount)
    var totalRows,totalBytes uint64
    for i:=0;i<batchCount;i++{
        if err:=ctx.Err();err!=nil{return nil,err}
        manifestName:=backlogCacheBatchManifest(dir,i)
        manifestRaw,err:=readFile(manifestName,int64(cfg.MaxManifestBytes))
        if err!=nil{return nil,fmt.Errorf("FI C1 cache: missing verified manifest %d: %w",i,err)}
        m,err:=spool.DecodeManifest(bytes.NewReader(manifestRaw))
        if err!=nil{return nil,fmt.Errorf("FI C1 cache: manifest %d: %w",i,err)}
        if m.BatchID==""||m.DataFile!="batch-"+m.BatchID+".jsonl"||
            m.RecordCount<=0||m.DataBytes<=0||
            (i>0&&m.BatchID<=batches[i-1].BatchID){
            return nil,fmt.Errorf("FI C1 cache: invalid original ordered signed manifest %d",i)
        }
        dataPath:=backlogCacheBatchData(dir,i)
        dataStat,err:=os.Lstat(dataPath)
        if err!=nil{return nil,fmt.Errorf("FI C1 cache: missing verified data %d: %w",i,err)}
        if !dataStat.Mode().IsRegular()||
            (dataStat.Mode().Perm()!=0600 &&
             !(mode=="receiver"&&dataStat.Mode().Perm()==0640))||
            dataStat.Size()!=m.DataBytes{
            return nil,fmt.Errorf("FI C1 cache: unsafe signed batch inode %d",i)
        }
        mh:=sha256.Sum256(manifestRaw)
        batches=append(batches,PreparedBatch{
            BatchID:m.BatchID,DataArtifactName:m.DataFile,DataPath:dataPath,
            Manifest:m,ManifestArtifactName:"batch-"+m.BatchID+".manifest.json",
            ManifestBytes:len(manifestRaw),ManifestRawBytes:manifestRaw,
            ManifestSHA256:hex.EncodeToString(mh[:]),
        })
        totalRows+=uint64(m.RecordCount)
        totalBytes+=uint64(m.DataBytes)
        if totalRows>receipt.RecordCount||totalBytes>receipt.DataBytes{
            return nil,errors.New("FI C1 cache: cached signed batch totals exceeded original recorded receipt")
        }
    }
    if totalRows!=receipt.RecordCount||totalBytes!=receipt.DataBytes{
        return nil,errors.New("FI C1 cache: full verified batch cache does not match original recorder receipt")
    }
    fmt.Fprintf(os.Stderr,"FI C1 SOR VERIFIED CACHE INPUT PASS batches=%d records=%d data_bytes=%d original_custody_present=true independent_b_required=true cache_mode=%s\n",
        len(batches),totalRows,totalBytes,mode)
    return &PreparedGeneration{Batches:batches,Receipt:receipt,ReceiptSHA256:receiptSHA,
        ReceiptBytes:len(raw),ReceiptRawBytes:raw},nil
}

// B reads its OWN file handles from the original verified cache (never A's
// stream). The original group READY/COMMIT scheduler and per-group relational
// verifier remain unchanged. No second signed transport expansion happens.
func LoadC1SoRBenchmarkVerifiedCache(ctx context.Context,c C1SoRLocalConfig,generation string)(*PreparedGeneration,error){
    if c.Custody.VerifiedCacheRoot==""||!c.Custody.BenchmarkClone{
        return nil,errors.New("FI C1 cache: only isolated clone may import verified cache")
    }
    return c1SoRVerifiedCacheGeneration(ctx,c.SourceID,generation,c.Custody)
}

// Live receiver cache is input acceleration only. Independent verifier B
// always reopens original signed FIGT custody on the real SoR.
func LoadC1SoRReceiverVerifiedCache(ctx context.Context,c C1SoRLocalConfig,generation string)(*PreparedGeneration,error){
    if c.Custody.BenchmarkClone||c.Custody.VerifiedCacheRoot!=""||
        c.Custody.ReceiverVerifiedCacheRoot==""{
        return nil,errors.New("FI C1 receiver cache: requires live read-only receiver-published cache, not a clone")
    }
    return c1SoRVerifiedCacheGeneration(ctx,c.SourceID,generation,c.Custody)
}

func c1NativeBVerifyCachedGroups(ctx context.Context,conn *pgx.Conn,
    p c1NativeBPlan,cfg c1NativeBCustodyConfig,
    onGroup func(int,bool)error,commitment hash.Hash)error{
    if ctx==nil||conn==nil||commitment==nil{return errors.New("FI C1 cache B: independent read-only verifier required")}
    if err:=c1ValidateNativeBPlan(p);err!=nil{return err}
    g,err:=c1SoRVerifiedCacheGeneration(ctx,p.Start.SourceID,p.Start.GenerationID,cfg)
    if err!=nil{return err}
    if g.ReceiptSHA256!=p.Start.ReceiptSHA256||
        g.Receipt.TransferSHA256!=p.Transfer||
        len(g.Batches)!=len(p.Batches){
        return errors.New("FI C1 cache B: receipt or SQL generation plan changed")
    }
    groups,err:=c1SoRGroupPlan(p.Batches,int(p.Start.StartBatchIndex))
    if err!=nil{return err}
    nextGroup:=0
    for i,b:=range g.Batches{
        if err:=ctx.Err();err!=nil{return err}
        prior:=p.Batches[i]
        if b.BatchID!=prior.BatchID||b.ManifestSHA256!=prior.ManifestSHA256||
            b.Manifest.DataSHA256!=prior.Manifest.DataSHA256||
            b.Manifest.RecordCount!=prior.Manifest.RecordCount||
            b.Manifest.DataBytes!=prior.Manifest.DataBytes{
            return fmt.Errorf("FI C1 cache B: prior signed batch %d conflicts with SoR Pending ledger",i)
        }
        if nextGroup<len(groups)&&i==groups[nextGroup].firstBatch{
            if err:=onGroup(nextGroup+1,false);err!=nil{return err}
        }
        f,err:=os.Open(b.DataPath)
        if err!=nil{return err}
        verifyErr:=c1NativeBVerifyDataWithCommitment(ctx,conn,f,i,p.SQLIDs[i],b,commitment,p.SQLSchema)
        closeErr:=f.Close()
        if verifyErr!=nil{return fmt.Errorf("FI C1 cache B: batch %d: %w",i,verifyErr)}
        if closeErr!=nil{return closeErr}
        if nextGroup<len(groups)&&i+1==groups[nextGroup].endBatch{
            if err:=onGroup(nextGroup+1,true);err!=nil{return err}
            nextGroup++
        }
    }
    if nextGroup!=len(groups){return errors.New("FI C1 cache B: missing signed durable group")}
    fmt.Fprintf(os.Stderr,"FI C1 B VERIFIED CACHE SIGNED/SQL PASS groups=%d batches=%d records=%d source=receiver_authenticated_checkpoint clone_only=true\n",
        len(groups),len(g.Batches),g.Receipt.RecordCount)
    return nil
}

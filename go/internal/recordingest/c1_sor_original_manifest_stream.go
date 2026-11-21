//go:build fi_c1_sor_dev

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// fi-sor INITIAL BOOTSTRAP: independently authenticate the ORIGINAL signed
// receiver bundle and return only its tiny recorded receipt and per-batch
// manifest metadata. No second 65+ GiB durable file copy, no temporary
// custody directory, no P5 SQL and no RAM-buffer journaling.
package recordingest

import (
    "bytes"
    "context"
    "crypto/sha256"
    "encoding/hex"
    "errors"
    "fmt"
    "io"
    "os"
    "path/filepath"
    "sort"
    "strings"
    "time"

    "github.com/Iron-Signal-Systems/fi/go/internal/generationrecorder"
    "github.com/Iron-Signal-Systems/fi/go/internal/spool"
    "github.com/Iron-Signal-Systems/fi/go/internal/transportgeneration"
)

func c1StreamOriginalSignedManifestPlan(ctx context.Context,source,generation string,
    cfg c1NativeBCustodyConfig)(*PreparedGeneration,error){
    if ctx==nil||source==""||generation==""||cfg.CustodyRoot==""||
        cfg.RecordedRoot==""||!filepath.IsAbs(cfg.CustodyRoot)||
        !filepath.IsAbs(cfg.RecordedRoot)||cfg.MaxCanonicalBytes==0||
        cfg.MaxEncodedBytes==0||cfg.MaxManifestBytes==0||
        cfg.MaxManifestBytes>1<<20{
        return nil,errors.New("C1 bootstrap: original signed custody/receipt roots and bounded limits required")
    }
    root:=cfg.RecordedRoot
    if cfg.SourceNamespaces{
        var err error
        root,err=generationrecorder.RecordedSourceDirectory(root,source)
        if err!=nil{return nil,err}
    }
    receiptRaw,err:=readImmutableReceipt(filepath.Join(root,
        generationrecorder.RecordedReceiptObjectName(source,generation)))
    if err!=nil{return nil,fmt.Errorf("C1 bootstrap: original recorded receipt: %w",err)}
    receipt,err:=generationrecorder.UnmarshalRecordedReceipt(receiptRaw)
    if err!=nil{return nil,err}
    if receipt.Descriptor.SourceID!=source||
        receipt.Descriptor.GenerationID!=generation||
        receipt.BatchCount==0||receipt.BatchCount>65535{
        return nil,errors.New("C1 bootstrap: recorded receipt signed identity/count invalid")
    }
    receiptSHA:=sha256.Sum256(receiptRaw)
    trust,err:=loadInstalledGenerationTrust(source)
    if err!=nil{return nil,fmt.Errorf("C1 bootstrap: original receiver trust: %w",err)}
    originalPath:=filepath.Join(cfg.CustodyRoot,
        transportgeneration.DurableCustodyObjectName(source,generation))
    info,err:=os.Lstat(originalPath)
    if err!=nil{return nil,err}
    if !info.Mode().IsRegular()||info.Mode().Perm()!=0400||info.Size()<=0{
        return nil,errors.New("C1 bootstrap: signed original custody must remain immutable 0400")
    }
    inspections:=make(map[string]spool.DataInspection,int(receipt.BatchCount))
    manifests:=make(map[string][]byte,int(receipt.BatchCount))
    names:=make([]string,0,int(receipt.BatchCount)*2)
    factory:=func(descriptor transportgeneration.Descriptor)(
        transportgeneration.CanonicalArtifactHandler,error){
        if descriptor!=receipt.Descriptor{
            return nil,errors.New("C1 bootstrap: original signed transport descriptor changed")
        }
        return func(name string,r io.Reader)error{
            if err:=ctx.Err();err!=nil{return err}
            if filepath.Base(name)!=name||strings.ContainsAny(name,`/\\`){
                return errors.New("C1 bootstrap: unsafe signed canonical artifact filename")
            }
            if len(names)>=int(receipt.BatchCount)*2{
                return errors.New("C1 bootstrap: extra original signed artifact")
            }
            switch{
            case strings.HasPrefix(name,"batch-")&&strings.HasSuffix(name,".jsonl"):
                inspection,e:=spool.InspectData(r)
                if e!=nil{return fmt.Errorf("C1 bootstrap: original signed data record validation %s: %w",name,e)}
                if _,exists:=inspections[name];exists{return errors.New("C1 bootstrap: duplicate signed data file")}
                inspections[name]=inspection
            case strings.HasPrefix(name,"batch-")&&strings.HasSuffix(name,".manifest.json"):
                raw,e:=io.ReadAll(io.LimitReader(r,int64(cfg.MaxManifestBytes)+1))
                if e!=nil{return e}
                if len(raw)==0||uint64(len(raw))>cfg.MaxManifestBytes{
                    return errors.New("C1 bootstrap: original signed manifest outside maximum")
                }
                if _,exists:=manifests[name];exists{
                    return errors.New("C1 bootstrap: duplicate original signed manifest")
                }
                manifests[name]=raw
            default:
                return fmt.Errorf("C1 bootstrap: unexpected original signed artifact %q",name)
            }
            names=append(names,name)
            return nil
        },nil
    }
    signed,err:=transportgeneration.ReadDiscoveredDurableCustodyArtifacts(
        transportgeneration.DiscoveredCustody{
            Bytes:uint64(info.Size()),Path:originalPath,
        },transportgeneration.CustodyConfig{
            RootDir:cfg.CustodyRoot,
            Receive:transportgeneration.ReceiveConfig{
                BatchCRL:trust.BatchCRL,BatchIssuer:trust.BatchIssuer,
                CurrentTime:time.Now(),MaxCanonicalBytes:cfg.MaxCanonicalBytes,
                MaxEncodedBytes:cfg.MaxEncodedBytes,Root:trust.Root,
                Source:trust.Source,
            },
        },factory)
    if err!=nil{return nil,fmt.Errorf("C1 bootstrap: cryptographic original custody: %w",err)}
    if signed.Transfer.Descriptor!=receipt.Descriptor||
        signed.Transfer.MetadataBytes!=receipt.MetadataBytes||
        signed.Transfer.MetadataSHA256!=receipt.MetadataSHA256||
        signed.Transfer.TransferBytes!=receipt.TransferBytes||
        signed.Transfer.TransferSHA256!=receipt.TransferSHA256{
        return nil,errors.New("C1 bootstrap: original receipt and signed transport mismatch")
    }
    if len(names)!=int(receipt.BatchCount)*2||!sort.StringsAreSorted(names){
        return nil,errors.New("C1 bootstrap: signed data and manifest order/count mismatch")
    }
    prepared:=make([]PreparedBatch,0,int(receipt.BatchCount))
    var totalRecords,totalBytes uint64
    for i:=0;i<len(names);i+=2{
        dataName,manifestName:=names[i],names[i+1]
        if !strings.HasPrefix(dataName,"batch-")||
            !strings.HasSuffix(dataName,".jsonl"){
            return nil,errors.New("C1 bootstrap: original batch data artifact order invalid")
        }
        name:=strings.TrimSuffix(strings.TrimPrefix(dataName,"batch-"),".jsonl")
        if name==""||manifestName!="batch-"+name+".manifest.json"{
            return nil,errors.New("C1 bootstrap: original signed batch pair mismatch")
        }
        inspection,ok:=inspections[dataName]
        if !ok{return nil,errors.New("C1 bootstrap: original signed JSONL inspection missing")}
        raw,ok:=manifests[manifestName]
        if !ok{return nil,errors.New("C1 bootstrap: original manifest data missing")}
        manifest,err:=spool.DecodeManifest(bytes.NewReader(raw))
        if err!=nil{return nil,err}
        if manifest.BatchID!=name||manifest.DataFile!=dataName{
            return nil,errors.New("C1 bootstrap: original source batch/manifest identity mismatch")
        }
        if err=spool.VerifyManifestData(manifest,inspection);err!=nil{
            return nil,fmt.Errorf("C1 bootstrap: source %s signed manifest/data disagreement: %w",name,err)
        }
        sum:=sha256.Sum256(raw)
        prepared=append(prepared,PreparedBatch{
            BatchID:name,DataArtifactName:dataName,
            Manifest:manifest,ManifestArtifactName:manifestName,
            ManifestBytes:len(raw),ManifestRawBytes:raw,
            ManifestSHA256:hex.EncodeToString(sum[:]),
        })
        totalRecords+=uint64(inspection.RecordCount)
        totalBytes+=uint64(inspection.DataBytes)
    }
    if totalRecords!=receipt.RecordCount||totalBytes!=receipt.DataBytes{
        return nil,errors.New("C1 bootstrap: signed generation receipt totals differ from original manifests")
    }
    fmt.Printf("FI C1 ORIGINAL SIGNED MANIFEST PREFLIGHT PASS source=%s generation=%s batches=%d records=%d data_bytes=%d no_second_custody_copy=true no_postgres=true\n",
        source,generation,len(prepared),totalRecords,totalBytes)
    return &PreparedGeneration{
        Batches:prepared,Receipt:receipt,
        ReceiptBytes:len(receiptRaw),ReceiptRawBytes:receiptRaw,
        ReceiptSHA256:hex.EncodeToString(receiptSHA[:]),
    },nil
}

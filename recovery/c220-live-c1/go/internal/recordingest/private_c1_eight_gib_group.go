//go:build fi_c1_sor_dev

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
package recordingest

import (
    "crypto/sha256"
    "encoding/hex"
    "errors"
    "fmt"
)

// privateC1EightGiBGroups is C220 clone-only: preserve the original signed
// seed checkpoint (window zero) and select ONE identical intact signed-batch
// prefix for the 2GiB and 4GiB variants. All later descriptors are newly
// derived and chained from the unchanged seed digest. Neither variant changes
// signed record identity, SQL buffer limits, or backend storage.
func privateC1EightGiBGroups(g *PreparedGeneration, original []BacklogCheckpointDescriptor,
    groupGiB int)([]BacklogCheckpointDescriptor,int,uint64,uint64,error){
    if g==nil || len(original)<2 || (groupGiB!=2&&groupGiB!=4){
        return nil,0,0,0,errors.New("FI C1 8GiB: original seed and 2/4GiB group required")
    }
    seed:=original[0]
    if seed.StartBatch!=0 || seed.EndBatch<=0 || seed.EndBatch>=len(g.Batches) ||
        seed.StartRecord!=0 || seed.EndRecord==0 || seed.DigestSHA256=="" ||
        seed.ReceiptSHA256!=g.ReceiptSHA256 {
        return nil,0,0,0,errors.New("FI C1 8GiB: immutable signed seed checkpoint invalid")
    }
    var records,bytes uint64
    for i:=0;i<seed.EndBatch;i++ {
        m:=g.Batches[i].Manifest
        if m.RecordCount<=0||m.DataBytes<=0{return nil,0,0,0,errors.New("FI C1 8GiB: invalid original seed batch")}
        records+=uint64(m.RecordCount)
        bytes+=uint64(m.DataBytes)
    }
    if records!=seed.EndRecord || bytes!=seed.DataBytes{
        return nil,0,0,0,errors.New("FI C1 8GiB: original seed signed totals mismatch")
    }
    const twoGiB=uint64(2)<<30
    // Build four 2GiB groups first. The byte cap—not 524288 records—
    // determines group boundaries. No intact source batch may be split.
    groups:=make([]BacklogWindow,0,8)
    var current BacklogWindow
    nextRecord:=seed.EndRecord
    for i:=seed.EndBatch;i<len(g.Batches);i++ {
        m:=g.Batches[i].Manifest
        if m.DataBytes<=0||m.RecordCount<=0||uint64(m.DataBytes)>twoGiB{
            return nil,0,0,0,fmt.Errorf("FI C1 8GiB: bad/oversized source batch %d",i)
        }
        n,b:=uint64(m.RecordCount),uint64(m.DataBytes)
        if current.EndBatch>current.StartBatch && b>twoGiB-current.DataBytes {
            groups=append(groups,current)
            current=BacklogWindow{}
        }
        if current.EndBatch==current.StartBatch{
            current.StartBatch=i
            current.StartRecord=nextRecord
            current.EndRecord=nextRecord
        }
        current.EndBatch=i+1
        current.EndRecord+=n
        current.DataBytes+=b
        nextRecord+=n
    }
    if current.EndBatch>current.StartBatch{groups=append(groups,current)}
    if len(groups)<5{return nil,0,0,0,errors.New("FI C1 8GiB: insufficient signed batches for 8GiB test plus remaining generation")}
    cutoff:=groups[3].EndBatch
    cutoffRows:=groups[3].EndRecord-seed.EndRecord
    var prefixBytes uint64
    for i:=0;i<4;i++ {prefixBytes+=groups[i].DataBytes}
    // The source is whole signed batches. Require near-8GiB coverage, never
    // claim exactly 8GiB if a manifest batch prevents an exact byte split.
    if prefixBytes < (uint64(8)<<30)-(uint64(64)<<20) || prefixBytes>(uint64(8)<<30){
        return nil,0,0,0,fmt.Errorf("FI C1 8GiB: source prefix differs from 8GiB by over 64MiB (%d bytes)",prefixBytes)
    }
    selected:=make([]BacklogWindow,0,len(groups))
    chosen:=4
    if groupGiB==2{
        selected=append(selected,groups[:4]...)
    }else{
        chosen=2
        for i:=0;i<4;i+=2{
            a,b:=groups[i],groups[i+1]
            if a.EndBatch!=b.StartBatch||a.EndRecord!=b.StartRecord{
                return nil,0,0,0,errors.New("FI C1 8GiB: noncontiguous 4GiB pair")
            }
            selected=append(selected,BacklogWindow{
                StartBatch:a.StartBatch,EndBatch:b.EndBatch,
                StartRecord:a.StartRecord,EndRecord:b.EndRecord,
                DataBytes:a.DataBytes+b.DataBytes,
            })
        }
    }
    // Preserve a deterministic, complete description of the remaining
    // signed generation, so partial test selection never invents a receipt.
    maxBytes:=uint64(groupGiB)<<30
    current=BacklogWindow{}
    nextRecord=groups[3].EndRecord
    for i:=cutoff;i<len(g.Batches);i++{
        m:=g.Batches[i].Manifest
        if m.DataBytes<=0||m.RecordCount<=0||uint64(m.DataBytes)>maxBytes{
            return nil,0,0,0,fmt.Errorf("FI C1 8GiB: invalid remaining batch %d",i)
        }
        n,b:=uint64(m.RecordCount),uint64(m.DataBytes)
        if current.EndBatch>current.StartBatch&&b>maxBytes-current.DataBytes {
            selected=append(selected,current)
            current=BacklogWindow{}
        }
        if current.EndBatch==current.StartBatch{
            current.StartBatch=i
            current.StartRecord=nextRecord
            current.EndRecord=nextRecord
        }
        current.EndBatch=i+1
        current.EndRecord+=n
        current.DataBytes+=b
        nextRecord+=n
    }
    if current.EndBatch>current.StartBatch{selected=append(selected,current)}
    if nextRecord!=g.Receipt.RecordCount {
        return nil,0,0,0,errors.New("FI C1 8GiB: signed receipt row coverage mismatch")
    }
    out:=make([]BacklogCheckpointDescriptor,0,len(selected)+1)
    out=append(out,seed)
    prev:=seed.DigestSHA256
    expectedBatch,expectedRecord:=seed.EndBatch,seed.EndRecord
    var remainderBytes uint64
    for _,w:=range selected{
        if w.StartBatch!=expectedBatch||w.StartRecord!=expectedRecord||w.EndBatch<=w.StartBatch||
            w.EndRecord<=w.StartRecord||w.DataBytes>maxBytes{
            return nil,0,0,0,errors.New("FI C1 8GiB: group not contiguous or exceeds byte cap")
        }
        d:=BacklogCheckpointDescriptor{
            Version:backlogCheckpointDescriptorVersion,
            SourceID:seed.SourceID,GenerationID:seed.GenerationID,
            ReceiptSHA256:seed.ReceiptSHA256,TransferSHA256:seed.TransferSHA256,
            FirstBatchID:g.Batches[w.StartBatch].BatchID,
            LastBatchID:g.Batches[w.EndBatch-1].BatchID,
            StartBatch:w.StartBatch,EndBatch:w.EndBatch,
            StartRecord:w.StartRecord,EndRecord:w.EndRecord,
            DataBytes:w.DataBytes,PreviousDigestSHA256:prev,
        }
        h:=sha256.New()
        for _,v:=range []string{
            d.Version,d.SourceID,d.GenerationID,d.ReceiptSHA256,
            d.TransferSHA256,d.FirstBatchID,d.LastBatchID,d.PreviousDigestSHA256,
        }{backlogDigestString(h,v)}
        for _,v:=range []uint64{
            uint64(w.StartBatch),uint64(w.EndBatch),w.StartRecord,w.EndRecord,w.DataBytes,
        }{backlogDigestNumber(h,v)}
        for i:=w.StartBatch;i<w.EndBatch;i++{
            b:=g.Batches[i]
            if !canonicalDigest(b.ManifestSHA256)||!canonicalDigest(b.Manifest.DataSHA256){
                return nil,0,0,0,errors.New("FI C1 8GiB: incomplete authenticated manifest digests")
            }
            backlogDigestString(h,b.BatchID)
            backlogDigestString(h,b.ManifestSHA256)
            backlogDigestString(h,b.Manifest.DataSHA256)
            backlogDigestNumber(h,uint64(b.Manifest.RecordCount))
            backlogDigestNumber(h,uint64(b.Manifest.DataBytes))
        }
        d.DigestSHA256=hex.EncodeToString(h.Sum(nil))
        prev=d.DigestSHA256
        out=append(out,d)
        expectedBatch=w.EndBatch
        expectedRecord=w.EndRecord
        remainderBytes+=w.DataBytes
    }
    if expectedBatch!=len(g.Batches)||expectedRecord!=g.Receipt.RecordCount||
        remainderBytes+seed.DataBytes!=g.Receipt.DataBytes{
        return nil,0,0,0,errors.New("FI C1 8GiB: grouped receipt totals changed")
    }
    if out[chosen].EndBatch!=cutoff || out[chosen].EndRecord-seed.EndRecord!=cutoffRows{
        return nil,0,0,0,errors.New("FI C1 8GiB: selected variants have inconsistent cutoff")
    }
    return out,chosen,cutoffRows,prefixBytes,nil
}

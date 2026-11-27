//go:build fi_c1_sor_dev

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
package recordingest

import (
    "bytes"
    "crypto/sha256"
    "encoding/hex"
    "strings"
    "testing"
    "time"
)

// These test vectors exercise the SAME domain-separated row commitment
// that native B builds from original signed/SQL-matched rows and the locked
// publisher rebuilds from PostgreSQL's source_record identity columns.
func TestC1NativeBOriginalRowCommitmentBindsEveryIdentity(t *testing.T){
    p:=c1NativeBTestPlan()
    fixed:=time.Date(2026,11,26,12,0,0,123456000,time.UTC)
    recordSHA:=sha256.Sum256([]byte("original LF-terminated signed source record"))
    newProof:=func(batchID,ordinal int64,version,kind,scope string,
        writtenAt time.Time,size int64,sha []byte)string{
        t.Helper()
        h,err:=c1NativeBNewRowCommitment(p)
        if err!=nil{t.Fatal(err)}
        if err:=c1NativeBCommitRow(h,batchID,ordinal,version,kind,scope,
            writtenAt,size,sha);err!=nil{t.Fatal(err)}
        return hex.EncodeToString(h.Sum(nil))
    }
    original:=newProof(11,1,"1","FileObservation","root-1",fixed,81,recordSHA[:])
    if !canonicalDigest(original){t.Fatal("B source row proof is not a SHA256 digest")}
    changedSHA:=sha256.Sum256([]byte("mutated record"))
    cases:=map[string]string{
        "batch identity":newProof(12,1,"1","FileObservation","root-1",fixed,81,recordSHA[:]),
        "ordinal":newProof(11,2,"1","FileObservation","root-1",fixed,81,recordSHA[:]),
        "version":newProof(11,1,"2","FileObservation","root-1",fixed,81,recordSHA[:]),
        "record kind":newProof(11,1,"1","WindowsSecurityEvent","root-1",fixed,81,recordSHA[:]),
        "scope":newProof(11,1,"1","FileObservation","root-2",fixed,81,recordSHA[:]),
        "timestamp":newProof(11,1,"1","FileObservation","root-1",fixed.Add(time.Microsecond),81,recordSHA[:]),
        "source bytes":newProof(11,1,"1","FileObservation","root-1",fixed,82,recordSHA[:]),
        "full signed digest":newProof(11,1,"1","FileObservation","root-1",fixed,81,changedSHA[:]),
    }
    for name,mutated:=range cases{
        if mutated==original{t.Fatalf("mutation %s did not change the B-to-publisher identity",name)}
    }
    h,err:=c1NativeBNewRowCommitment(p)
    if err!=nil{t.Fatal(err)}
    if err:=c1NativeBCommitRow(h,11,1,"1","FileObservation","root-1",fixed,81,recordSHA[:]);err!=nil{t.Fatal(err)}
    if hex.EncodeToString(h.Sum(nil))!=original{t.Fatal("independent SQL identity recomputation differs from original B proof")}
    if err:=c1NativeBCommitRow(h,11,2,"1","FileObservation","root-1",fixed,81,[]byte{1});err==nil{
        t.Fatal("C1 B admitted an incomplete digest")
    }
}

func TestC1NativeBRowCommitmentBindsImmutableGenerationAndBatchLedger(t *testing.T){
    original:=c1NativeBTestPlan()
    before,err:=c1NativeBNewRowCommitment(original)
    if err!=nil{t.Fatal(err)}
    proof:=before.Sum(nil)
    edits:=map[string]func(*c1NativeBPlan){
        "source":func(p *c1NativeBPlan){p.Start.SourceID="source-other";for i:=range p.Descriptors{p.Descriptors[i].SourceID="source-other"}},
        "receipt":func(p *c1NativeBPlan){p.Start.ReceiptSHA256=strings.Repeat("9",64);for i:=range p.Descriptors{p.Descriptors[i].ReceiptSHA256=p.Start.ReceiptSHA256}},
        "SQL batch mapping":func(p *c1NativeBPlan){p.SQLIDs[1]=42},
        "batch data SHA":func(p *c1NativeBPlan){p.Batches[1].Manifest.DataSHA256=strings.Repeat("0",64)},
    }
    for name,edit:=range edits{
        p:=c1NativeBTestPlan()
        edit(&p)
        h,err:=c1NativeBNewRowCommitment(p)
        if err!=nil{continue} // changed group metadata must fail closed
        if bytes.Equal(proof,h.Sum(nil)){t.Fatalf("changed %s preserved original commitment",name)}
    }
}

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package usncapture

import (
    "errors"
    "os"
    "path/filepath"
    "testing"
)

func TestSeparateObservationCursorCannotSkipRawSourceOrFakeRequiredRead(t *testing.T){
    source,dir:=exampleStore(t,DefaultMaxPendingBytes)
    anchor:=source.CaptureCursor()
    if _,err:=OpenObservationLedger(source);err==nil{
        t.Fatal("uninitialized observation source silently adopted the live USN head")
    }
    if err:=InitializeObservationCursor(dir,anchor);err!=nil{t.Fatal(err)}
    if err:=InitializeObservationCursor(dir,anchor);err==nil{
        t.Fatal("existing FI observation checkpoint was reset")
    }
    observed,err:=OpenObservationLedger(source)
    if err!=nil{t.Fatal(err)}
    if err:=source.Append(exampleBatch(anchor,100,200));err!=nil{t.Fatal(err)}
    seg,ok,err:=observed.Next()
    if err!=nil||!ok{t.Fatalf("original USN observation segment lost: %v",err)}
    if observed.Cursor().NextUSN!="100"||source.CaptureCursor().NextUSN!="200"{
        t.Fatal("observation cursor was not independent from raw capture")
    }
    if err:=observed.CommitObservation(seg,ObservationPublicationProof{});err==nil{
        t.Fatal("unverified NTFS observation advanced independent checkpoint")
    }
    root:=scopeTestIdentity("3")
    roots:=[]GovernedProcessingPlan{{
        ScopeID:"root-test",RootIdentity:root,
        Resolve:DirectRootScopeResolver("root-test",anchor.JournalID,root),
    }}
    noWork,err:=VerifyNoWorkObservationProof(seg,roots,
        ObservationPolicy{Version:ObservationPolicyVersion,MaxObjectsPerSegment:64})
    if err!=nil{t.Fatal(err)}
    if err:=observed.CommitObservation(seg,noWork);err!=nil{t.Fatal(err)}
    if observed.Cursor().NextUSN!="200"||source.ProcessingCursor().NextUSN!="100"{
        t.Fatal("independent observation advanced source-only processed cursor")
    }
    _,found,err:=observed.Next()
    if found||err!=nil{t.Fatalf("no-work segment replayed after receipt: %v",err)}
    reopened,err:=OpenObservationLedger(source)
    if err!=nil||reopened.Cursor().NextUSN!="200"{
        t.Fatalf("original observation cursor not durable: %v",err)
    }
    if _,err:=os.Stat(filepath.Join(dir,seg.Name));err!=nil{
        t.Fatal("independent observation retirement removed original source",err)
    }
}
func TestObservationCrashReceiptRecoveryRejectsForgedOrChangedSource(t *testing.T){
    source,dir:=exampleStore(t,DefaultMaxPendingBytes)
    anchor:=source.CaptureCursor()
    if err:=InitializeObservationCursor(dir,anchor);err!=nil{t.Fatal(err)}
    if err:=source.Append(exampleBatch(anchor,100,200));err!=nil{t.Fatal(err)}
    ledger,err:=OpenObservationLedger(source)
    if err!=nil{t.Fatal(err)}
    seg,ok,err:=ledger.Next()
    if err!=nil||!ok{t.Fatal(err)}
    root:=scopeTestIdentity("3")
    proof,err:=VerifyNoWorkObservationProof(seg,[]GovernedProcessingPlan{{
        ScopeID:"root-test",RootIdentity:root,
        Resolve:DirectRootScopeResolver("root-test",anchor.JournalID,root),
    }},ObservationPolicy{Version:ObservationPolicyVersion,MaxObjectsPerSegment:64})
    if err!=nil{t.Fatal(err)}
    if err:=ledger.CommitObservation(seg,proof);err!=nil{t.Fatal(err)}
    // Crash after the durable observation receipt but before the cursor.
    if err:=atomicWrite(filepath.Join(dir,observationCursorName),mustJSON(anchor));err!=nil{t.Fatal(err)}
    recovered,err:=OpenObservationLedger(source)
    if err!=nil||recovered.Cursor().NextUSN!="200"{
        t.Fatalf("original observation receipt did not recover exact interval: %v",err)
    }
    if err:=atomicWrite(filepath.Join(dir,observationCursorName),mustJSON(anchor));err!=nil{t.Fatal(err)}
    bad:=observationReceipt{
        Version:SchemaVersion,StartUSN:"100",NextUSN:"200",
        SourceBatchSHA256:"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        Proof:proof.Receipt(),
    }
    if err:=atomicWrite(filepath.Join(dir,observationReceiptPrefix+seg.Name),mustJSON(bad));err!=nil{t.Fatal(err)}
    if _,err:=OpenObservationLedger(source);!errors.Is(err,ErrCorrupt){
        t.Fatalf("forged original source observation receipt accepted: %v",err)
    }
}

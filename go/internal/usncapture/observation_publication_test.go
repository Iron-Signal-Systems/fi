// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package usncapture

import (
    "errors"
    "path/filepath"
    "strings"
    "testing"

    "github.com/Iron-Signal-Systems/fi/go/internal/spool"
)

func sampleObservationProofTest(t *testing.T)(*Store,*ObservationLedger,Segment,string){
    t.Helper()
    store,dir:=exampleStore(t,DefaultMaxPendingBytes)
    anchor:=store.CaptureCursor()
    if err:=InitializeObservationCursor(dir,anchor);err!=nil{t.Fatal(err)}
    if err:=store.Append(exampleBatch(anchor,100,150));err!=nil{t.Fatal(err)}
    ledger,err:=OpenObservationLedger(store);if err!=nil{t.Fatal(err)}
    seg,ok,err:=ledger.Next();if err!=nil||!ok{t.Fatal("original source",err)}
    return store,ledger,seg,filepath.Join(t.TempDir(),"spool")
}
func TestObservationSpoolVerifiedBeforeIndependentCursorAdvances(t *testing.T){
    store,ledger,seg,dir:=sampleObservationProofTest(t)
    expected:=[]PublishedNTFSObservation{{ScopeID:"root-1",
        Payload:map[string]any{"ntfs_observation":"actually opened object",
            "content_hashes":"observed from same handle"}}}
    writer,err:=spool.NewWriter(dir,spool.DefaultBatchSize,spool.CollectorIdentity{
        ExecutablePath:"FICollector-test",ExecutableSHA256:strings.Repeat("a",64),
    })
    if err!=nil{t.Fatal(err)}
    if err:=ledger.BeginObservationPublication(seg);err!=nil{t.Fatal(err)}
    if err:=writer.Append("FileObservation",expected[0].ScopeID,expected[0].Payload);err!=nil{t.Fatal(err)}
    if err:=writer.Close();err!=nil{t.Fatal(err)}
    proof,err:=VerifyObservationPublication(seg,expected,writer.FinalizedBatches())
    if err!=nil{t.Fatal(err)}
    if err:=ledger.CommitObservation(seg,proof);err!=nil{t.Fatal(err)}
    if ledger.Cursor().NextUSN!="150" ||
        store.ProcessingCursor().NextUSN!="100"||
        store.CaptureCursor().NextUSN!="150"{
        t.Fatal("independent NTFS observation affected unrelated FI USN cursors")
    }
    again,err:=OpenObservationLedger(store)
    if err!=nil||again.Cursor().NextUSN!="150"{
        t.Fatalf("independent verified FI observation was not durable: %v",err)
    }
}
func TestObservationChangedExtraOrMissingSourceRecordsNeverYieldProof(t *testing.T){
    _,ledger,seg,dir:=sampleObservationProofTest(t)
    writer,err:=spool.NewWriter(dir,spool.DefaultBatchSize,spool.CollectorIdentity{
        ExecutablePath:"FICollector-test",ExecutableSHA256:strings.Repeat("a",64),
    })
    if err!=nil{t.Fatal(err)}
    payload:=map[string]string{"root":"genuine"}
    if err:=writer.Append("FileObservation","root-1",payload);err!=nil{t.Fatal(err)}
    if err:=writer.Close();err!=nil{t.Fatal(err)}
    batches:=writer.FinalizedBatches()
    for name,expected:=range map[string][]PublishedNTFSObservation{
        "missing":{{ScopeID:"root-1",Payload:payload},{ScopeID:"root-2",Payload:payload}},
        "changed":{{ScopeID:"root-1",Payload:map[string]string{"root":"forged"}}},
        "wrong-root":{{ScopeID:"root-2",Payload:payload}},
    }{
        t.Run(name,func(t *testing.T){
            if _,err:=VerifyObservationPublication(seg,expected,batches);err==nil{
                t.Fatal("unverified original observation source accepted")
            }
        })
    }
    expected:=[]PublishedNTFSObservation{{ScopeID:"root-1",Payload:payload}}
    proof,err:=VerifyObservationPublication(seg,expected,batches)
    if err!=nil{t.Fatal(err)}
    if err:=ledger.CommitObservation(seg,proof);!errors.Is(err,ErrAmbiguousObservation){
        t.Fatalf("FI observation advanced without prior spool intent: %v",err)
    }
    if err:=ledger.BeginObservationPublication(seg);err!=nil{t.Fatal(err)}
    if _,ok,err:=ledger.Next();ok||!errors.Is(err,ErrAmbiguousObservation){
        t.Fatalf("unreconciled prior observation intent was silently replayable: %t %v",ok,err)
    }
    if err:=ledger.BeginObservationPublication(seg);!errors.Is(err,ErrAmbiguousObservation){
        t.Fatalf("original observation publication was authorized twice: %v",err)
    }
}

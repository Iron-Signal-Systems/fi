// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package main

import (
    "context"
    "errors"
    "path/filepath"
    "strings"
    "syscall"
    "time"
    "testing"

    "github.com/Iron-Signal-Systems/fi/go/internal/records"
    "github.com/Iron-Signal-Systems/fi/go/internal/spool"
    "github.com/Iron-Signal-Systems/fi/go/internal/usncapture"
    "github.com/Iron-Signal-Systems/fi/go/internal/windows/ntfs"
)

func testIndependentObservationPlan(t *testing.T)(
    *usncapture.Store,*usncapture.ObservationLedger,
    []usncapture.GovernedProcessingPlan,map[string]string,
    records.NTFSObjectIdentity,string,
){
    t.Helper()
    dir:=filepath.Join(t.TempDir(),"capture")
    journal:=testVolumeJournal("governed-root","1")
    volumeScope,err:=usncapture.VolumeCaptureScopeID(journal.VolumeIdentity)
    if err!=nil{t.Fatal(err)}
    anchor:=usncapture.Cursor{
        Version:usncapture.SchemaVersion,ScopeID:volumeScope,
        JournalID:journal.JournalID,VolumeIdentity:journal.VolumeIdentity,
        NextUSN:"100",
    }
    if err:=usncapture.Initialize(dir,anchor);err!=nil{t.Fatal(err)}
    if err:=usncapture.InitializeObservationCursor(dir,anchor);err!=nil{t.Fatal(err)}
    store,err:=usncapture.Open(dir,1<<30)
    if err!=nil{t.Fatal(err)}
    ledger,err:=usncapture.OpenObservationLedger(store)
    if err!=nil{t.Fatal(err)}
    root:=records.NTFSObjectIdentity{MethodVersion:"ntfs-file-id/1",FileReferenceNumber:"11",SequenceNumber:"1"}
    obj:=records.NTFSObjectIdentity{MethodVersion:"ntfs-file-id/1",FileReferenceNumber:"22",SequenceNumber:"1"}
    original:=testObservationSourceUSNEvent(t)
    original.FileIdentity=obj
    original.ParentIdentity=root
    original.USN="120"
    original.ReasonRaw="256"
    batch:=records.USNReadBatch{
        ObservedAt:journal.ObservedAt,
        CollectionMethod:journal.CollectionMethod,
        ScopeID:volumeScope,JournalID:journal.JournalID,
        VolumeIdentity:journal.VolumeIdentity,
        StartUSN:"100",NextUSN:"150",
        Records:[]records.USNChangeObservation{original},
    }
    if err:=store.Append(batch);err!=nil{t.Fatal(err)}
    plan:=[]usncapture.GovernedProcessingPlan{{
        ScopeID:"governed-root",RootIdentity:root,
        Resolve:usncapture.DirectRootScopeResolver("governed-root",journal.JournalID,root),
    }}
    return store,ledger,plan,map[string]string{"governed-root":`G:\FI-Test`},obj,filepath.Join(t.TempDir(),"spool")
}
func publishExactScopedSourceBeforeObservation(t *testing.T,store *usncapture.Store,
    roots []usncapture.GovernedProcessingPlan,spoolDir string,collector spool.CollectorIdentity){
    t.Helper()
    worked,err:=processCapturedUSNVolumeOnce(context.Background(),store,roots,spoolDir,collector)
    if err!=nil||!worked{
        t.Fatalf("source-only publication must precede independent NTFS outcome: %t %v",worked,err)
    }
}

func TestIndependentObservationCannotOutrunOriginalScopedPublication(t *testing.T){
    store,ledger,plan,paths,_,dir:=testIndependentObservationPlan(t)
    policy:=usncapture.ObservationPolicy{Version:usncapture.ObservationPolicyVersion,MaxObjectsPerSegment:32}
    collector:=spool.CollectorIdentity{ExecutablePath:"FICollector-test",ExecutableSHA256:strings.Repeat("a",64)}
    called:=false
    worked,err:=processIndependentNTFSObservationsOnce(context.Background(),
        store,ledger,plan,paths,dir,collector,policy,
        func(context.Context,string,string,records.NTFSObjectIdentity)(spooledFileObservation,error){
            called=true
            return spooledFileObservation{},syscall.ERROR_FILE_NOT_FOUND
        })
    if worked||err!=nil||called{
        t.Fatalf("observation worker read before signed source-only publication: %t %v called=%t",worked,err,called)
    }
    if ledger.Cursor().NextUSN!="100"||store.CaptureCursor().NextUSN!="150"{
        t.Fatal("held independent observation moved an unverified cursor")
    }
}

func TestIndependentNTFSMissingFilePublishesExplicitBoundSourceOutcome(t *testing.T){
    store,ledger,plan,paths,object,dir:=testIndependentObservationPlan(t)
    policy:=usncapture.ObservationPolicy{
        Version:usncapture.ObservationPolicyVersion,MaxObjectsPerSegment:32,
    }
    collector:=spool.CollectorIdentity{ExecutablePath:"FICollector-test",ExecutableSHA256:strings.Repeat("a",64)}
    publishExactScopedSourceBeforeObservation(t,store,plan,dir,collector)
    calls:=0
    missing:=&ntfs.Error{Stage:ntfs.StageOpen,Op:"OpenFileById",Err:syscall.ERROR_FILE_NOT_FOUND}
    worked,err:=processIndependentNTFSObservationsOnce(context.Background(),
        store,ledger,plan,paths,dir,collector,policy,
        func(_ context.Context,scope,root string,id records.NTFSObjectIdentity)(spooledFileObservation,error){
            calls++
            if id!=object{t.Fatal("worker did not use original File-ID")}
            return spooledFileObservation{},missing
        })
    if err!=nil||!worked||calls!=1{
        t.Fatalf("unavailable original File-ID lost from selective source: %t %v calls=%d",worked,err,calls)
    }
    if ledger.Cursor().NextUSN!="150"||store.CaptureCursor().NextUSN!="150"||
        store.ProcessingCursor().NextUSN!="150"{
        t.Fatal("selective outcome changed source-only and observation cursor separation")
    }
    worked,err=processIndependentNTFSObservationsOnce(context.Background(),
        store,ledger,plan,paths,dir,collector,policy,
        func(context.Context,string,string,records.NTFSObjectIdentity)(spooledFileObservation,error){
            t.Fatal("re-observed acknowledged missing NTFS file identity")
            return spooledFileObservation{},nil
        })
    if worked||err!=nil{t.Fatalf("accepted source was re-observed: %t %v",worked,err)}
}

func TestIndependentNTFSSourceIdentityMismatchCannotPublish(t *testing.T){
    store,ledger,plan,paths,_,dir:=testIndependentObservationPlan(t)
    policy:=usncapture.ObservationPolicy{Version:usncapture.ObservationPolicyVersion,MaxObjectsPerSegment:32}
    collector:=spool.CollectorIdentity{ExecutablePath:"FICollector-test",ExecutableSHA256:strings.Repeat("a",64)}
    publishExactScopedSourceBeforeObservation(t,store,plan,dir,collector)
    worked,err:=processIndependentNTFSObservationsOnce(context.Background(),
        store,ledger,plan,paths,dir,collector,policy,
        func(_ context.Context,scope,root string,id records.NTFSObjectIdentity)(
            spooledFileObservation,error,
        ){
            return spooledFileObservation{NTFS:ntfs.Observation{
                ObjectIdentity:records.NTFSObjectIdentity{
                    MethodVersion:"ntfs-file-id/1",FileReferenceNumber:"999",SequenceNumber:"1",
                },VolumeIdentity:store.CaptureCursor().VolumeIdentity,
                GovernedRoot:records.GovernedRootIdentity{ScopeID:scope,
                    ObjectIdentity:plan[0].RootIdentity},
                ObservedAt:time.Now().UTC().Format(time.RFC3339Nano),
            },ContentHashes:records.ContentHashObservation{State:records.ContentHashNotApplicable}},nil
        })
    if err==nil||worked{
        t.Fatal("independent NTFS source mismatch published as a valid outcome")
    }
    if ledger.Cursor().NextUSN!="100"||store.ProcessingCursor().NextUSN!="150"{
        t.Fatal("unverified current NTFS identity advanced original source")
    }
}

func TestIndependentObservationPolicyNoWorkRequiresNoLiveReads(t *testing.T){
    store,ledger,plan,paths,_,dir:=testIndependentObservationPlan(t)
    // Complete raw USN history is still stored, but no policy-required object
    // work exists when the change reason is delete.
    // The first source segment is left untouched by the independent worker.
    seg,ok,err:=ledger.Next()
    if err!=nil||!ok{t.Fatal(err)}
    policy:=usncapture.ObservationPolicy{Version:usncapture.ObservationPolicyVersion,MaxObjectsPerSegment:16}
    // The true original FileCreate requires current NTFS observation and
    // cannot advance through the no-work path.
    _,err=usncapture.VerifyNoWorkObservationProof(seg,plan,policy)
    if !errors.Is(err,usncapture.ErrObservationPending){
        t.Fatalf("selected FI object incorrectly declared no-work: %v",err)
    }
    // Mutating a USN reason after capture MUST NOT permit a false no-work
    // receipt against the original source's immutable SHA-256.
    seg.Batch.Records[0].ReasonRaw="512"
    if _,err:=usncapture.VerifyNoWorkObservationProof(seg,plan,policy);!errors.Is(err,usncapture.ErrCorrupt){
        t.Fatalf("tampered raw USN reason falsely changed observation policy decision: %v",err)
    }
    _=store;_=paths;_=dir
}

func testObservationSourceUSNEvent(t *testing.T)records.USNChangeObservation{
    t.Helper()
    original,_:=testVolumeCaptureForProcessing(t)
    seg,ok,err:=original.Next()
    if err!=nil||!ok||len(seg.Batch.Records)==0{t.Fatalf("no valid original USN test event: %v",err)}
    return seg.Batch.Records[0]
}

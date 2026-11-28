// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package main

import (
    "context"
    "path/filepath"
    "strings"
    "testing"
    "time"

    "github.com/Iron-Signal-Systems/fi/go/internal/records"
    "github.com/Iron-Signal-Systems/fi/go/internal/spool"
    "github.com/Iron-Signal-Systems/fi/go/internal/usncapture"
)

func testVolumeCaptureForProcessing(t *testing.T) (*usncapture.Store,[]usncapture.GovernedProcessingPlan){
    t.Helper()
    volume:=records.VolumeIdentity{
        MethodVersion:"ntfs-volume/1",
        VolumeGUID:`\\?\Volume{11111111-2222-3333-4444-555555555555}\`,
        VolumeSerial:"99",
    }
    scope,err:=usncapture.VolumeCaptureScopeID(volume)
    if err!=nil{t.Fatal(err)}
    dir:=filepath.Join(t.TempDir(),"capture")
    cursor:=usncapture.Cursor{
        Version:usncapture.SchemaVersion, ScopeID:scope, JournalID:"999",
        VolumeIdentity:volume,NextUSN:"100",
    }
    if err:=usncapture.Initialize(dir,cursor);err!=nil{t.Fatal(err)}
    store,err:=usncapture.Open(dir,usncapture.DefaultMaxPendingBytes)
    if err!=nil{t.Fatal(err)}
    root:=records.NTFSObjectIdentity{MethodVersion:"ntfs-file-id/1",
        FileReferenceNumber:"5",SequenceNumber:"1"}
    stamp:=time.Now().UTC().Format("2006-01-02T15:04:05.000000000Z")
    batch:=records.USNReadBatch{
        ObservedAt:stamp,
        CollectionMethod:records.WindowsUSNCollectionMethod,
        ScopeID:scope,VolumeIdentity:volume,JournalID:"999",
        StartUSN:"100",NextUSN:"150",
        Records:[]records.USNChangeObservation{{
            MajorVersion:"2",MinorVersion:"0",FileIdentity:records.NTFSObjectIdentity{
                MethodVersion:"ntfs-file-id/1",FileReferenceNumber:"6",SequenceNumber:"1",
            },ParentIdentity:root,USN:"104",Timestamp:stamp,ReasonRaw:"256",
            SourceInfoRaw:"0",SecurityID:"0",FileAttributesRaw:"32",
            FileNameUTF16LEBase64URL:"YQA",
        }},
    }
    if err:=store.Append(batch);err!=nil{t.Fatal(err)}
    roots:=[]usncapture.GovernedProcessingPlan{{
        ScopeID:"root-test",RootIdentity:root,
        Resolve:usncapture.DirectRootScopeResolver("root-test",batch.JournalID,root),
    }}
    return store,roots
}

func TestUSNProcessingVerifiedSpoolPrecedesProcessingCheckpoint(t *testing.T){
    store,roots:=testVolumeCaptureForProcessing(t)
    spoolDir:=filepath.Join(t.TempDir(),"spool")
    collector:=spool.CollectorIdentity{
        ExecutablePath:"FICollector-test",
        ExecutableSHA256:strings.Repeat("a",64),
    }
    worked,err:=processCapturedUSNVolumeOnce(context.Background(),store,roots,spoolDir,collector)
    if err!=nil||!worked{t.Fatalf("source-only processing failed: worked=%t err=%v",worked,err)}
    if store.CaptureCursor().NextUSN!="150"||store.ProcessingCursor().NextUSN!="150"{
        t.Fatal("verified source publication failed to commit processed cursor")
    }
    worked,err=processCapturedUSNVolumeOnce(context.Background(),store,roots,spoolDir,collector)
    if err!=nil||worked{t.Fatalf("source range republished after verified processing: %t %v",worked,err)}
}
func TestUSNProcessingSpoolFailureDoesNotAdvanceSourceCursor(t *testing.T){
    store,roots:=testVolumeCaptureForProcessing(t)
    _,err:=processCapturedUSNVolumeOnce(context.Background(),store,roots,
        filepath.Join(t.TempDir(),"spool"),spool.CollectorIdentity{})
    if err==nil{t.Fatal("accepted missing collector custody identity")}
    if store.CaptureCursor().NextUSN!="150"||store.ProcessingCursor().NextUSN!="100"{
        t.Fatal("unverified spool attempt advanced USN source cursor")
    }
    if _,exists,err:=store.Next();err!=nil||!exists{
        t.Fatalf("unprocessed source not replayable: %t %v",exists,err)
    }
}
func TestUSNProcessingCancelledBeforePublicationLeavesSourcePending(t *testing.T){
    store,roots:=testVolumeCaptureForProcessing(t)
    ctx,cancel:=context.WithCancel(context.Background());cancel()
    _,err:=processCapturedUSNVolumeOnce(ctx,store,roots,filepath.Join(t.TempDir(),"spool"),
        spool.CollectorIdentity{ExecutablePath:"a",ExecutableSHA256:strings.Repeat("a",64)})
    if err==nil||store.ProcessingCursor().NextUSN!="100"{
        t.Fatalf("cancelled consumer incorrectly processed source: %v",err)
    }
}

func TestUSNProcessingPublishesHistoricalEventWithoutFileReobservation(t *testing.T){
    store,roots:=testVolumeCaptureForProcessing(t)
    before,ok,err:=store.Next()
    if err!=nil||!ok||len(before.Batch.Records)!=1{
        t.Fatalf("raw source event not in durable queue: %v",err)
    }
    projection,err:=usncapture.BuildVolumeProjections(before,roots)
    if err!=nil||len(projection)!=1{t.Fatalf("scope-only projection invalid: %v",err)}
    if projection[0].GovernedRecordCount!=1 ||
        projection[0].UnresolvedRecordCount!=0 ||
        projection[0].Included[0].Source.FileIdentity.FileReferenceNumber!="6" ||
        projection[0].Included[0].Class!=usncapture.ScopeGoverned{
        t.Fatal("raw journal parent/file evidence was lost or replaced")
    }
    spoolDir:=filepath.Join(t.TempDir(),"spool")
    collector:=spool.CollectorIdentity{ExecutablePath:"FICollector-test",
        ExecutableSHA256:strings.Repeat("a",64)}
    complete,err:=processCapturedUSNVolumeOnce(context.Background(),store,roots,spoolDir,collector)
    if err!=nil||!complete{t.Fatalf("source-only publish failed: %v",err)}
    if store.ProcessingCursor().NextUSN!="150"{
        t.Fatal("verified historical source event failed to advance the processing cursor")
    }
}

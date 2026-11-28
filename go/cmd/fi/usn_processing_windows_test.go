// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package main

import (
    "bufio"
    "context"
    "encoding/json"
    "errors"
    "os"
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

func TestUSNProcessingTwoConsecutiveSourceBatchesArePublishedOnce(t *testing.T) {
    store,roots:=testVolumeCaptureForProcessing(t)
    first,ok,err:=store.Next()
    if err!=nil||!ok{t.Fatalf("missing first source: %v",err)}
    next:=first.Batch
    next.StartUSN="150"
    next.NextUSN="200"
    next.Records[0].USN="154"
    next.Records[0].FileIdentity.FileReferenceNumber="7"
    if err:=store.Append(next);err!=nil{t.Fatalf("append second captured interval: %v",err)}
    spoolDir:=filepath.Join(t.TempDir(),"spool")
    collector:=spool.CollectorIdentity{ExecutablePath:"FICollector-test",
        ExecutableSHA256:strings.Repeat("a",64)}
    for i:=0;i<2;i++{
        processed,err:=processCapturedUSNVolumeOnce(context.Background(),store,roots,spoolDir,collector)
        if err!=nil||!processed{t.Fatalf("process source interval %d: worked=%t err=%v",i,processed,err)}
    }
    if store.CaptureCursor().NextUSN!="200"||store.ProcessingCursor().NextUSN!="200"{
        t.Fatal("source intervals did not retain independent source and processed cursors")
    }
    processed,err:=processCapturedUSNVolumeOnce(context.Background(),store,roots,spoolDir,collector)
    if err!=nil||processed{t.Fatalf("duplicate publication after both intervals: worked=%t err=%v",processed,err)}
    entries,err:=os.ReadDir(spoolDir)
    if err!=nil{t.Fatal(err)}
    manifests:=0
    for _,entry:=range entries{
        if strings.HasSuffix(entry.Name(),".manifest.json"){manifests++}
    }
    if manifests!=2{
        t.Fatalf("expected one verified FI batch per captured interval; got %d",manifests)
    }
}

func TestUSNProcessingRefusesAmbiguousPublicationWithoutRewritingSpool(t *testing.T) {
    store,roots:=testVolumeCaptureForProcessing(t)
    seg,ok,err:=store.Next()
    if err!=nil||!ok{t.Fatal("missing raw source",err)}
    if err:=store.BeginScopedPublication(seg);err!=nil{t.Fatal(err)}
    // Simulate restart with a durable publishing intent but no receipt.
    // A first writer could already have finalized a sender-visible manifest.
    spoolDir:=filepath.Join(t.TempDir(),"spool")
    collector:=spool.CollectorIdentity{ExecutablePath:"FICollector-test",
        ExecutableSHA256:strings.Repeat("a",64)}
    worked,err:=processCapturedUSNVolumeOnce(context.Background(),store,roots,spoolDir,collector)
    if worked||!errors.Is(err,usncapture.ErrAmbiguousPublication){
        t.Fatalf("uncertain source interval replayed: worked=%t err=%v",worked,err)
    }
    if store.ProcessingCursor().NextUSN!="100"{
        t.Fatal("source checkpoint advanced without verified publication outcome")
    }
    if entries,err:=os.ReadDir(spoolDir);err==nil&&len(entries)>0{
        t.Fatalf("ambiguous interval created new FI spool data: %d entries",len(entries))
    }else if err!=nil&&!os.IsNotExist(err){t.Fatal(err)}
}

func TestUSNProcessingPublishesAllGovernedRootsFromOneVolumeSegment(t *testing.T) {
    store,roots:=testVolumeCaptureForProcessing(t)
    second:=records.NTFSObjectIdentity{
        MethodVersion:"ntfs-file-id/1",FileReferenceNumber:"55",SequenceNumber:"1",
    }
    roots=append(roots,usncapture.GovernedProcessingPlan{
        ScopeID:"root-second",RootIdentity:second,
        Resolve:usncapture.DirectRootScopeResolver("root-second","999",second),
    })
    spoolDir:=filepath.Join(t.TempDir(),"spool")
    collector:=spool.CollectorIdentity{
        ExecutablePath:"FICollector-test",ExecutableSHA256:strings.Repeat("a",64),
    }
    published,err:=processCapturedUSNVolumeOnce(context.Background(),store,roots,spoolDir,collector)
    if err!=nil||!published{t.Fatalf("multi-root publication: %t %v",published,err)}
    if store.ProcessingCursor().NextUSN!="150"{
        t.Fatal("multi-root source did not commit processed cursor after both roots")
    }
    entries,err:=os.ReadDir(spoolDir);if err!=nil{t.Fatal(err)}
    found:=make(map[string]usncapture.ScopedProjection)
    for _,entry:=range entries{
        if !strings.HasSuffix(entry.Name(),".manifest.json"){continue}
        verification,err:=spool.VerifyManifest(filepath.Join(spoolDir,entry.Name()))
        if err!=nil||!verification.Verified{
            t.Fatalf("multi-root FI spool manifest verification failed: %v",err)
        }
        file,err:=os.Open(verification.DataPath)
        if err!=nil{t.Fatal(err)}
        scanner:=bufio.NewScanner(file)
        scanner.Buffer(make([]byte,4096),spool.DefaultMaxBatchBytes)
        for scanner.Scan(){
            var record spool.Record
            if err:=json.Unmarshal(scanner.Bytes(),&record);err!=nil{
                _=file.Close();t.Fatal(err)
            }
            if record.RecordKind!="USNScopedCapture"{
                _=file.Close();t.Fatalf("unexpected publication kind %q",record.RecordKind)
            }
            var p usncapture.ScopedProjection
            if err:=json.Unmarshal(record.Payload,&p);err!=nil{
                _=file.Close();t.Fatal(err)
            }
            if _,duplicate:=found[record.ScopeID];duplicate{
                _=file.Close();t.Fatalf("duplicate governed source scope %q",record.ScopeID)
            }
            found[record.ScopeID]=p
        }
        if err:=scanner.Err();err!=nil{_ =file.Close();t.Fatal(err)}
        if err:=file.Close();err!=nil{t.Fatal(err)}
    }
    if len(found)!=2{t.Fatalf("expected two governed-root projections, got %d",len(found))}
    a,okA:=found["root-test"]
    b,okB:=found["root-second"]
    if !okA||!okB||a.GovernedRecordCount!=1||b.UnresolvedRecordCount!=1 ||
        a.CaptureScopeID!=b.CaptureScopeID ||
        a.SourceBatchSHA256!=b.SourceBatchSHA256 ||
        a.StartUSN!=b.StartUSN||a.NextUSN!=b.NextUSN{
        t.Fatalf("same volume source not independently conserved per root: A=%+v B=%+v",a,b)
    }
}

func TestUSNProcessingMissingRootScopeEvidenceLeavesQueueReplayable(t *testing.T) {
    store,roots:=testVolumeCaptureForProcessing(t)
    badRoot:=records.NTFSObjectIdentity{MethodVersion:"ntfs-file-id/1",
        FileReferenceNumber:"88",SequenceNumber:"1"}
    broken:=errors.New("historical scope index unavailable")
    roots=append(roots,usncapture.GovernedProcessingPlan{
        ScopeID:"root-second",RootIdentity:badRoot,
        Resolve:func(records.USNChangeObservation)(usncapture.ScopeEvidence,error){
            return usncapture.ScopeEvidence{},broken
        },
    })
    dir:=filepath.Join(t.TempDir(),"spool")
    result,err:=processCapturedUSNVolumeOnce(context.Background(),store,roots,dir,
        spool.CollectorIdentity{ExecutablePath:"FICollector-test",ExecutableSHA256:strings.Repeat("a",64)})
    if result||!errors.Is(err,broken){t.Fatalf("accepted incomplete multi-root scope proof: %t %v",result,err)}
    if store.ProcessingCursor().NextUSN!="100"{
        t.Fatal("processed cursor advanced after one governed root failed")
    }
    if _,ready,err:=store.Next();err!=nil||!ready{
        t.Fatalf("failed multi-root scope processing lost original source: %t %v",ready,err)
    }
    if entries,err:=os.ReadDir(dir);err==nil{
        for _,entry:=range entries{
            if strings.HasSuffix(entry.Name(),".manifest.json"){
                t.Fatal("published partial governed-root source on resolver failure")
            }
        }
    }else if !os.IsNotExist(err){t.Fatal(err)}
}

func publishCapturedWithoutProcessingReceipt(
    t *testing.T, store *usncapture.Store, roots []usncapture.GovernedProcessingPlan,
    dir string, firstRootOnly bool,
) {
    t.Helper()
    seg,ok,err:=store.Next()
    if err!=nil||!ok{t.Fatalf("no original source segment: %v",err)}
    projections,err:=usncapture.BuildVolumeProjections(seg,roots)
    if err!=nil{t.Fatal(err)}
    writer,err:=spool.NewWriter(dir,spool.DefaultBatchSize,spool.CollectorIdentity{
        ExecutablePath:"FICollector-test",ExecutableSHA256:strings.Repeat("a",64),
    })
    if err!=nil{t.Fatal(err)}
    if err:=store.BeginScopedPublication(seg);err!=nil{t.Fatal(err)}
    if firstRootOnly{projections=projections[:1]}
    for _,pr:=range projections{
        if err:=writer.Append("USNScopedCapture",pr.GovernedScopeID,pr);err!=nil{t.Fatal(err)}
    }
    if err:=writer.Close();err!=nil{t.Fatal(err)}
}

func TestInterruptedVerifiedSpoolCompletesOriginalReceiptWithoutSecondPublication(t *testing.T) {
    store,roots:=testVolumeCaptureForProcessing(t)
    dir:=filepath.Join(t.TempDir(),"spool")
    publishCapturedWithoutProcessingReceipt(t,store,roots,dir,false)
    before,err:=os.ReadDir(dir);if err!=nil{t.Fatal(err)}
    worked,err:=processCapturedUSNVolumeOnce(context.Background(),store,roots,dir,
        spool.CollectorIdentity{ExecutablePath:"FICollector-test",ExecutableSHA256:strings.Repeat("a",64)})
    if err!=nil||!worked{t.Fatalf("original spool not reconciled: worked=%t err=%v",worked,err)}
    if store.ProcessingCursor().NextUSN!="150" {t.Fatal("original capture receipt not committed")}
    after,err:=os.ReadDir(dir);if err!=nil{t.Fatal(err)}
    if len(after)!=len(before){t.Fatalf("reconciliation wrote duplicate spool: %d -> %d",len(before),len(after))}
    worked,err=processCapturedUSNVolumeOnce(context.Background(),store,roots,dir,
        spool.CollectorIdentity{ExecutablePath:"FICollector-test",ExecutableSHA256:strings.Repeat("a",64)})
    if worked||err!=nil{t.Fatalf("completed interval replayed: worked=%t err=%v",worked,err)}
}

func TestInterruptedPartialMultiRootSpoolNeverAdvancesProcessed(t *testing.T) {
    store,roots:=testVolumeCaptureForProcessing(t)
    root2:=records.NTFSObjectIdentity{MethodVersion:"ntfs-file-id/1",
        FileReferenceNumber:"55",SequenceNumber:"1"}
    roots=append(roots,usncapture.GovernedProcessingPlan{
        ScopeID:"root-second",RootIdentity:root2,
        Resolve:usncapture.DirectRootScopeResolver("root-second","999",root2),
    })
    dir:=filepath.Join(t.TempDir(),"spool")
    publishCapturedWithoutProcessingReceipt(t,store,roots,dir,true)
    worked,err:=processCapturedUSNVolumeOnce(context.Background(),store,roots,dir,
        spool.CollectorIdentity{ExecutablePath:"FICollector-test",ExecutableSHA256:strings.Repeat("a",64)})
    if worked||!errors.Is(err,usncapture.ErrAmbiguousPublication){
        t.Fatalf("partial source publication accepted: worked=%t err=%v",worked,err)
    }
    if store.ProcessingCursor().NextUSN!="100"{t.Fatal("partial root custody advanced source")}
}

func TestTransferredUnverifiableSpoolNeverReplaysOriginalSource(t *testing.T) {
    store,roots:=testVolumeCaptureForProcessing(t)
    dir:=filepath.Join(t.TempDir(),"spool")
    publishCapturedWithoutProcessingReceipt(t,store,roots,dir,false)
    // A sender may move the finalized files before the local receipt. Without
    // a persisted remote acknowledgement the outcome MUST remain ambiguous.
    entries,err:=os.ReadDir(dir);if err!=nil{t.Fatal(err)}
    for _,entry:=range entries{
        if !entry.IsDir(){
            if err:=os.Remove(filepath.Join(dir,entry.Name()));err!=nil{t.Fatal(err)}
        }
    }
    worked,err:=processCapturedUSNVolumeOnce(context.Background(),store,roots,dir,
        spool.CollectorIdentity{ExecutablePath:"FICollector-test",ExecutableSHA256:strings.Repeat("a",64)})
    if worked||!errors.Is(err,usncapture.ErrAmbiguousPublication){
        t.Fatalf("unverifiable published source was duplicated: worked=%t err=%v",worked,err)
    }
    if store.ProcessingCursor().NextUSN!="100"{t.Fatal("missing custody advanced cursor")}
}

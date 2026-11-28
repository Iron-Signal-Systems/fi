// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package recordingest

import (
    "crypto/sha256"
    "encoding/hex"
    "encoding/json"
    "strings"
    "testing"
    "time"

    "github.com/Iron-Signal-Systems/fi/go/internal/records"
)

func testUSNScopedCapturePayload() usnScopedCapturePayload {
    stamp:=time.Now().UTC().Format("2006-01-02T15:04:05.000000000Z")
    volume:=records.VolumeIdentity{MethodVersion:"ntfs-volume/1",VolumeGUID:`\\?\Volume{11111111-2222-3333-4444-555555555555}\`,VolumeSerial:"123"}
    root:=records.NTFSObjectIdentity{MethodVersion:"ntfs-file-id/1",FileReferenceNumber:"101",SequenceNumber:"1"}
    child:=records.NTFSObjectIdentity{MethodVersion:"ntfs-file-id/1",FileReferenceNumber:"102",SequenceNumber:"1"}
    volumeKey := "fi-volume-usn-capture/1" + string(byte(0)) + volume.MethodVersion + string(byte(0)) + strings.ToLower(volume.VolumeGUID) + string(byte(0)) + volume.VolumeSerial
    sum := sha256.Sum256([]byte(volumeKey))
    change:=records.USNChangeObservation{
        MajorVersion:"2",MinorVersion:"0",FileIdentity:child,ParentIdentity:root,
        USN:"104",Timestamp:stamp,ReasonRaw:"256",SourceInfoRaw:"0",
        SecurityID:"0",FileAttributesRaw:"32",FileNameUTF16LEBase64URL:"YQA",
    }
    v:=usnScopedCapturePayload{
        Version:usnScopedCaptureVersion, CaptureScopeID:"volume-"+hex.EncodeToString(sum[:16]),
        GovernedScopeID:"root-test",RootIdentity:root,CapturedAt:stamp,
        CollectionMethod:records.WindowsUSNCollectionMethod,VolumeIdentity:volume,
        JournalID:"55",StartUSN:"100",NextUSN:"200",
        SourceRecordCount:1,
        IncludedRecordCount:1,GovernedRecordCount:1,
        Included:[]usnScopedChangePayload{{Source:change,Class:"Governed",Reason:"RecordedAncestry"}},
    }
    raw:=records.USNReadBatch{
        ObservedAt:v.CapturedAt,CollectionMethod:v.CollectionMethod,
        ScopeID:v.CaptureScopeID,VolumeIdentity:v.VolumeIdentity,
        JournalID:v.JournalID,StartUSN:v.StartUSN,NextUSN:v.NextUSN,
        Records:[]records.USNChangeObservation{change},
    }
    buf,err:=json.Marshal(raw)
    if err!=nil{panic(err)}
    rawSHA:=sha256.Sum256(buf)
    v.SourceBatchSHA256=hex.EncodeToString(rawSHA[:])
    return v
}
func TestUSNScopedCaptureValidatesOnlySourceFacts(t *testing.T){
    v:=testUSNScopedCapturePayload()
    if err:=validateUSNScopedCapture("root-test",v);err!=nil{t.Fatalf("valid source-only USN rejected: %v",err)}
}
func TestUSNScopedCaptureRejectsScopeLossOrForgedMetadata(t *testing.T){
    tests:=map[string]func(*usnScopedCapturePayload){
        "wrong-root-envelope":func(v *usnScopedCapturePayload){v.GovernedScopeID="root-other"},
        "bad-version":func(v *usnScopedCapturePayload){v.Version="fi-usn-scoped-projection/0"},
        "bad-capture-scope":func(v *usnScopedCapturePayload){v.CaptureScopeID="root-abc"},
        "wrong-valid-volume-digest":func(v *usnScopedCapturePayload){v.CaptureScopeID="volume-"+strings.Repeat("a",32)},
        "bad-digest":func(v *usnScopedCapturePayload){v.SourceBatchSHA256="abcd"},
        "valid-but-false-digest":func(v *usnScopedCapturePayload){v.SourceBatchSHA256=strings.Repeat("b",64)},
        "altered-valid-raw-reason":func(v *usnScopedCapturePayload){v.Included[0].Source.ReasonRaw="512"},
        "timestamp":func(v *usnScopedCapturePayload){v.CapturedAt="bad"},
        "unknown-method":func(v *usnScopedCapturePayload){v.CollectionMethod="AlteredUSN"},
        "journal":func(v *usnScopedCapturePayload){v.JournalID="01"},
        "range":func(v *usnScopedCapturePayload){v.NextUSN="100"},
        "event-out-of-range":func(v *usnScopedCapturePayload){v.Included[0].Source.USN="201"},
        "fabricated-processed":func(v *usnScopedCapturePayload){v.Included[0].Class="Observed"},
        "missing-change":func(v *usnScopedCapturePayload){v.Included=nil},
        "fabricated-counts":func(v *usnScopedCapturePayload){v.GovernedRecordCount=0},
        "excluded-unproved":func(v *usnScopedCapturePayload){v.ProvenOutsideRecordCount=1},
        "invalid-object":func(v *usnScopedCapturePayload){v.Included[0].Source.FileIdentity.MethodVersion=""},
        "untrusted-reason":func(v *usnScopedCapturePayload){v.Included[0].Reason=strings.Repeat("a",1025)},
        "hash-not-observation":func(v *usnScopedCapturePayload){v.Included[0].Source.ReasonRaw="broken"},
    }
    for name,change:=range tests{
        t.Run(name,func(t *testing.T){v:=testUSNScopedCapturePayload();change(&v);if err:=validateUSNScopedCapture("root-test",v);err==nil{t.Fatal("accepted invalid source-only USN")}})
    }
}
func TestUSNScopedCaptureUnresolvedIsRetained(t *testing.T){
    v:=testUSNScopedCapturePayload()
    v.GovernedRecordCount=0;v.UnresolvedRecordCount=1;v.Included[0].Class="Unresolved"
    if err:=validateUSNScopedCapture("root-test",v);err!=nil{t.Fatalf("unresolved source evidence lost: %v",err)}
}

func TestUSNScopedCaptureOriginalDigestRejectsDroppedOrReorderedFacts(t *testing.T) {
    v:=testUSNScopedCapturePayload()
    second:=v.Included[0]
    second.Source.USN="108"
    second.Source.FileIdentity.FileReferenceNumber="103"
    v.Included=append(v.Included,second)
    v.SourceRecordCount=2
    v.IncludedRecordCount=2
    v.GovernedRecordCount=2
    raw:=records.USNReadBatch{
        ObservedAt:v.CapturedAt,CollectionMethod:v.CollectionMethod,
        ScopeID:v.CaptureScopeID,VolumeIdentity:v.VolumeIdentity,
        JournalID:v.JournalID,StartUSN:v.StartUSN,NextUSN:v.NextUSN,
        Records:[]records.USNChangeObservation{v.Included[0].Source,v.Included[1].Source},
    }
    b,err:=json.Marshal(raw);if err!=nil{t.Fatal(err)}
    sum:=sha256.Sum256(b)
    v.SourceBatchSHA256=hex.EncodeToString(sum[:])
    if err:=validateUSNScopedCapture("root-test",v);err!=nil{t.Fatalf("original source facts rejected: %v",err)}
    v.Included[0],v.Included[1]=v.Included[1],v.Included[0]
    if err:=validateUSNScopedCapture("root-test",v);err==nil{
        t.Fatal("source facts reordered without changing custody digest")
    }
}
func TestUSNScopedCaptureZeroEventBatchDigestVerifiesBothGoSliceEncodings(t *testing.T) {
    for _,recordsSlice:=range [][]records.USNChangeObservation{nil, {}} {
        v:=testUSNScopedCapturePayload()
        v.Included=nil
        v.SourceRecordCount=0;v.IncludedRecordCount=0;v.GovernedRecordCount=0
        raw:=records.USNReadBatch{
            ObservedAt:v.CapturedAt,CollectionMethod:v.CollectionMethod,
            ScopeID:v.CaptureScopeID,VolumeIdentity:v.VolumeIdentity,
            JournalID:v.JournalID,StartUSN:v.StartUSN,NextUSN:v.NextUSN,
            Records:recordsSlice,
        }
        b,err:=json.Marshal(raw);if err!=nil{t.Fatal(err)}
        sum:=sha256.Sum256(b);v.SourceBatchSHA256=hex.EncodeToString(sum[:])
        if err:=validateUSNScopedCapture("root-test",v);err!=nil{
            t.Fatalf("zero source facts rejected: %v",err)
        }
    }
}

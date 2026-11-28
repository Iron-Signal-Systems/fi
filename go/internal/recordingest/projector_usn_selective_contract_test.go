// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package recordingest

import (
    "strings"
    "testing"

    "github.com/Iron-Signal-Systems/fi/go/internal/windows/ntfs"
)

func testUSNSelectiveSourceOutcome()usnSelectiveObservationPayload{
    raw:=testUSNScopedCapturePayload()
    return usnSelectiveObservationPayload{
        Version:usnSelectiveObservationVersion,
        CaptureScopeID:raw.CaptureScopeID,GovernedScopeID:raw.GovernedScopeID,
        VolumeIdentity:raw.VolumeIdentity,RootIdentity:raw.RootIdentity,
        FileIdentity:raw.Included[0].Source.FileIdentity,
        JournalID:raw.JournalID,StartUSN:raw.StartUSN,NextUSN:raw.NextUSN,
        SourceBatchSHA256:raw.SourceBatchSHA256,
        TriggerUSNs:[]string{raw.Included[0].Source.USN},
        ObservedAt:raw.CapturedAt,Status:"Unavailable",
        ReasonCode:"OriginalFileIDNoLongerExists",
    }
}
func TestUSNIndependentOutcomeExplicitUnavailableIsNotCurrentFileObservation(t *testing.T){
    p:=testUSNSelectiveSourceOutcome()
    if err:=validateUSNSelectiveObservation(p.GovernedScopeID,p);err!=nil{
        t.Fatalf("valid historical source with explicit missing-current-file status rejected: %v",err)
    }
    other:=p
    other.Status="OutsideGovernedRoot"
    other.ReasonCode="CurrentHandleOutsideRoot"
    if err:=validateUSNSelectiveObservation(other.GovernedScopeID,other);err!=nil{
        t.Fatalf("current outside-root status must not delete original USN source: %v",err)
    }
    failed:=p
    failed.Status="Error"
    failed.ReasonCode="AccessDenied"
    failed.Error="actual OS access denied"
    if err:=validateUSNSelectiveObservation(failed.GovernedScopeID,failed);err!=nil{
        t.Fatalf("explicit real observation failure was silently dropped: %v",err)
    }
}
func TestUSNIndependentOutcomeNeverForgesSourceOrObservedFile(t *testing.T){
    baseline:=testUSNSelectiveSourceOutcome()
    negatives:=map[string]func(*usnSelectiveObservationPayload){
        "wrong-volume":func(v *usnSelectiveObservationPayload){v.VolumeIdentity.VolumeSerial="9999"},
        "wrong-journal":func(v *usnSelectiveObservationPayload){v.JournalID="bad"},
        "wrong-source-sha":func(v *usnSelectiveObservationPayload){v.SourceBatchSHA256=strings.Repeat("F",64)},
        "wrong-origin-usn":func(v *usnSelectiveObservationPayload){v.TriggerUSNs=[]string{v.NextUSN}},
        "missing-trigger":func(v *usnSelectiveObservationPayload){v.TriggerUSNs=nil},
        "unreviewed-status":func(v *usnSelectiveObservationPayload){v.Status="Complete"},
        "invented-success":func(v *usnSelectiveObservationPayload){v.Status="Observed";v.ReasonCode=""},
        "invented-unavailable-hash":func(v *usnSelectiveObservationPayload){v.NTFS=&ntfs.Observation{}},
        "silent-failure":func(v *usnSelectiveObservationPayload){v.ReasonCode=""},
        "unbounded-error":func(v *usnSelectiveObservationPayload){v.Error=strings.Repeat("x",5000)},
    }
    for name,mutate:=range negatives{
        t.Run(name,func(t *testing.T){
            candidate:=baseline
            mutate(&candidate)
            if err:=validateUSNSelectiveObservation(candidate.GovernedScopeID,candidate);err==nil{
                t.Fatal("forged independent NTFS observation fact passed source/identity/status validation")
            }
        })
    }
}

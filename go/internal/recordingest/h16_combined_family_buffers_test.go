// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package recordingest

import (
    "context"
    "testing"
)

// The first H16 optimization is a buffering-policy change ONLY. There must
// be no newly introduced SQL transactions, source replay, PKI trust changes,
// or intermediate typed checkpoint. Four K32 work units remain in one atomic
// W128 SQL transaction, and do not force Security/File buffers to empty.
func TestH16CombinedBuffersKeepPartialFamiliesAcrossK32(t *testing.T) {
    mode := privateDependencyTestContext(t)
    for chunk := 0; chunk < 4; chunk++ {
        if h16FamilyDrainAtBoundary(mode, true, false) {
            t.Fatalf("private H16 combined buffer drained at K32 chunk %d", chunk)
        }
        if h16FamilyDrainAtBoundary(mode, false, false) {
            t.Fatalf("private H16 combined buffer drained inside K32 chunk %d", chunk)
        }
    }
    if !h16FamilyDrainAtBoundary(mode, true, true) {
        t.Fatal("private H16 combined buffer skipped mandatory atomic W128 drain")
    }
    if !h16FamilyDrainAtBoundary(mode, false, true) {
        t.Fatal("private H16 combined buffer skipped final signed batch flush")
    }
}

// The accepted original H16 behavior must remain byte-for-byte unchanged
// unless the exact opt-in private dependency-buffer configuration is active.
func TestH16CombinedBuffersDoNotChangeOriginalK32Drain(t *testing.T) {
    regular := context.Background()
    if !h16FamilyDrainAtBoundary(regular, true, false) {
        t.Fatal("original H16 K32 flush disabled outside private candidate")
    }
    if h16FamilyDrainAtBoundary(regular, false, false) {
        t.Fatal("original H16 incurred a new unexpected flush")
    }
    if h16FamilyDrainAtBoundary(regular, false, true) {
        t.Fatal("original H16 end boundary contract unexpectedly changed")
    }
}

// Coverage has its own existing bounded projection buffer; the combined
// private H16 mode must never flush unrelated Security or File solely because
// a WindowsSecurityCoverage record arrived. USN remains ordered separately.
func TestH16CombinedCoverageDoesNotFlushSecurityOrFile(t *testing.T) {
    mode := privateDependencyTestContext(t)
    for _, kind := range []string{
        "WindowsSecurityCoverage", "WindowsSecurityEvent",
        "FileObservation", "USNReadBoundary", "USNObjectObservation",
    } {
        decision := securityFileFlushBeforeKind(mode, kind)
        if decision.security || decision.files {
            t.Fatalf("kind %s needlessly drained an independent family: %+v", kind, decision)
        }
    }
    for _, kind := range []string{"USNContinuityGap", "CollectorIdentity"} {
        decision := securityFileFlushBeforeKind(mode, kind)
        if !decision.security || !decision.files {
            t.Fatalf("unaudited %s lost existing H16 ordering barrier: %+v", kind, decision)
        }
    }
}

// H16 intentionally modifies ONLY File content-hash COPY bounds, naming the
// resulting profile F3H16. The mixed-buffer mode was enabled while still F3.
// Validate the real per-batch context: never reject that exact H16 profile,
// and never authorize mutated row, byte, or child limits.
func TestH16CombinedAcceptsExactHashProfileButRejectsMutatedLimits(t *testing.T) {
    initial := privateDependencyTestContext(t)
    if !privateH16CombinedFileProfileValid(initial) {
        t.Fatal("original F3 context rejected")
    }
    h16, err := WithPrivateFileHashH16(initial)
    if err != nil { t.Fatal(err) }
    if got := fileBulkLimitsFromContext(h16); got.Name != "F3H16" {
        t.Fatalf("H16 did not select required hash profile: %s",got.Name)
    }
    if !privateH16CombinedFileProfileValid(h16) {
        t.Fatal("exact H16 content-hash-only copy limits rejected")
    }
    active := context.WithValue(h16, backlogTypedChunkContextKey{},
        backlogTypedChunkDirective{
            state:&backlogTypedChunkState{fileBulk:newFileObservationBulkState()},
            finish:false,
        })
    if err := validatePrivateFamilyRoute(active); err != nil {
        t.Fatalf("real signed batch H16 profile was incorrectly rejected: %v",err)
    }
    original := fileBulkLimitsFromContext(h16)
    for _,tc:=range []struct{name string; change func(*fileBulkLimits)}{
        {"source_rows",func(x *fileBulkLimits){x.SourceMaxRecords++}},
        {"source_bytes",func(x *fileBulkLimits){x.SourceMaxBytes++}},
        {"observation_rows",func(x *fileBulkLimits){x.ObserveMaxRecords++}},
        {"observation_bytes",func(x *fileBulkLimits){x.ObserveMaxBytes++}},
        {"hash_rows",func(x *fileBulkLimits){x.HashMaxRows++}},
        {"hash_bytes",func(x *fileBulkLimits){x.HashMaxBytes++}},
        {"child_rows",func(x *fileBulkLimits){x.ChildMaxRows++}},
        {"profile_name",func(x *fileBulkLimits){x.Name="UNKNOWN"}},
    } {
        t.Run(tc.name,func(t *testing.T){
            altered:=original
            tc.change(&altered)
            broken:=context.WithValue(active,fileBulkProfileContextKey{},altered)
            if privateH16CombinedFileProfileValid(broken) {
                t.Fatal("altered file profile passed the exact source-route guard")
            }
            if err:=validatePrivateFamilyRoute(broken);err==nil {
                t.Fatal("altered profile passed signed-batch H16 route")
            }
        })
    }
    noField:=context.WithValue(active,privateSecurityFieldPartitionsKey{},false)
    if err:=validatePrivateFamilyRoute(noField);err==nil {
        t.Fatal("missing isolated Security field-partition context accepted")
    }
    noChunk:=context.WithValue(active,backlogTypedChunkContextKey{},backlogTypedChunkDirective{})
    if err:=validatePrivateFamilyRoute(noChunk);err==nil {
        t.Fatal("missing K32 state accepted")
    }
}

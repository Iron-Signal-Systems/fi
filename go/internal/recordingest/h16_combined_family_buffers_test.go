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

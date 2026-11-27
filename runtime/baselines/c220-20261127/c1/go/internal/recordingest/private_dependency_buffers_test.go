// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// Tests the exact helpers invoked from the active FI ingest worker.
package recordingest

import (
    "context"
    "testing"

    "github.com/Iron-Signal-Systems/fi/go/internal/spool"
)

func privateDependencyTestContext(t *testing.T) context.Context {
    t.Helper()
    ctx, err := WithPrivateDependencyBuffers(privateMixedTestContext(t))
    if err != nil { t.Fatal(err) }
    if !privateDependencyBuffersEnabled(ctx) {
        t.Fatal("private dependency context not enabled")
    }
    return ctx
}

func TestPrivateDependencyBuffersFailClosed(t *testing.T) {
    if _, err := WithPrivateDependencyBuffers(nil); err == nil {
        t.Fatal("nil context allowed")
    }
    if _, err := WithPrivateDependencyBuffers(context.Background()); err == nil {
        t.Fatal("ordinary ingestion enabled dependency buffering")
    }
    mixed := privateMixedTestContext(t)
    if privateDependencyBuffersEnabled(mixed) {
        t.Fatal("mixed buffer experiment unexpectedly enabled dependency path")
    }
    private := privateDependencyTestContext(t)
    brokenChunk := context.WithValue(private,
        backlogTypedChunkContextKey{}, backlogTypedChunkDirective{})
    if err := validatePrivateFamilyRoute(brokenChunk); err == nil {
        t.Fatal("dependency mode silently accepted invalid typed chunk")
    }
    if err := validatePrivateFamilyRoute(private); err != nil {
        t.Fatalf("valid dependency route rejected: %v", err)
    }
}

func TestPrivateDependencyDecouplesCoverageAndUSNFromSecurityFile(t *testing.T) {
    ctx := privateDependencyTestContext(t)
    for _, kind := range []string{"WindowsSecurityCoverage", "USNReadBoundary",
        "USNObjectObservation", "WindowsSecurityEvent", "FileObservation"} {
        d := securityFileFlushBeforeKind(ctx, kind)
        if d.security || d.files {
            t.Fatalf("%s unnecessarily flushed Security or File: %+v", kind, d)
        }
    }
    // Unrelated kinds are conservative ordering barriers until individually
    // audited and assigned their own safe relational dependencies.
    for _, kind := range []string{"USNContinuityGap", "UnknownObservation"} {
        d := securityFileFlushBeforeKind(ctx, kind)
        if !d.security || !d.files {
            t.Fatalf("%s lost a required conservative fence: %+v", kind, d)
        }
    }
    baseline := privateMixedTestContext(t)
    for _, kind := range []string{"WindowsSecurityCoverage", "USNReadBoundary"} {
        d := securityFileFlushBeforeKind(baseline, kind)
        if !d.security || !d.files {
            t.Fatalf("existing mixed-buffer baseline changed for %s", kind)
        }
    }
}

func privateDependencyTestRecord(kind string, bytes int) SourceRecord {
    return SourceRecord{
        Record: spool.Record{RecordKind: kind},
        RecordBytes: bytes,
    }
}

func TestPrivateDependencyBoundedSourceOrder(t *testing.T) {
    var rows []privateDependencySourceRecord
    var size int64
    for i := 1; i <= privateDependencyMaxRecords; i++ {
        kind := "USNObjectObservation"
        if i == 1 {
            kind = "USNReadBoundary"
        }
        var err error
        rows, size, err = privateDependencyAppend(rows, size, 41, 3, int64(i),
            privateDependencyTestRecord(kind, 100))
        if err != nil { t.Fatal(err) }
    }
    if !privateDependencyShouldFlushBefore(len(rows), size, 100) ||
        len(rows) != privateDependencyMaxRecords ||
        size != privateDependencyMaxRecords*100 {
        t.Fatal("dependency queue did not enforce record bound")
    }
    if _, _, err := privateDependencyAppend(rows, size, 41,
        3, privateDependencyMaxRecords+1,
        privateDependencyTestRecord("USNObjectObservation", 100)); err == nil {
        t.Fatal("dependency queue exceeded record limit")
    }
    // Buffer crosses the original signed-batch boundary without losing order.
    rows = nil
    size = 0
    var err error
    rows, size, err = privateDependencyAppend(rows, size, 41, 3, 800,
        privateDependencyTestRecord("USNReadBoundary", 90))
    if err != nil { t.Fatal(err) }
    rows, size, err = privateDependencyAppend(rows, size, 42, 4, 1,
        privateDependencyTestRecord("USNObjectObservation", 90))
    if err != nil { t.Fatal(err) }
    if len(rows) != 2 || rows[0].sourceBatchID != 41 ||
        rows[0].signedBatchIndex != 3 ||
        rows[1].sourceBatchID != 42 ||
        rows[1].signedBatchIndex != 4 || size != 180 {
        t.Fatal("USN dependent source identities lost across signed batches")
    }
    // PostgreSQL batch IDs are not custody-order evidence: the queue must
    // accept increasing SIGNED indices even if SQL FK numbers run backward.
    rows = nil
    size = 0
    rows, size, err = privateDependencyAppend(rows, size, 99, 5, 42,
        privateDependencyTestRecord("USNReadBoundary", 70))
    if err != nil { t.Fatal(err) }
    rows, size, err = privateDependencyAppend(rows, size, 7, 6, 1,
        privateDependencyTestRecord("USNObjectObservation", 70))
    if err != nil || len(rows) != 2 || size != 140 {
        t.Fatal("dependency queue incorrectly sorts by database batch IDs")
    }
}

func TestPrivateDependencyRejectsForwardOrDuplicateSources(t *testing.T) {
    first := privateDependencySourceRecord{sourceBatchID: 42, signedBatchIndex: 4, ordinal: 7,
        prepared: privateDependencyTestRecord("USNReadBoundary", 100)}
    for _, tc := range []struct {
        name string
        batch, ordinal int64
        signedIndex int
        kind string
    }{
        {"duplicate", 42, 7, 4, "USNObjectObservation"},
        {"reverse-in-batch", 42, 6, 4, "USNObjectObservation"},
        {"reverse-batch", 41, 100, 3, "USNObjectObservation"},
        {"invalid-kind", 42, 8, 4, "WindowsSecurityEvent"},
    } {
        t.Run(tc.name, func(t *testing.T) {
            if _, _, err := privateDependencyAppend(
                []privateDependencySourceRecord{first}, 100,
                tc.batch, tc.signedIndex, tc.ordinal,
                privateDependencyTestRecord(tc.kind, 100)); err == nil {
                t.Fatal("invalid dependency queue entry accepted")
            }
        })
    }
    if !privateDependencyShouldFlushBefore(1, privateDependencyMaxBytes-100, 101) {
        t.Fatal("dependency buffer exceeded byte budget")
    }
    if privateDependencyShouldFlushBefore(1, privateDependencyMaxBytes-100, 100) {
        t.Fatal("dependency buffer incorrectly required flush at exact byte budget")
    }
    if _, _, err := privateDependencyAppend(nil, 0, 41, 3, 1,
        privateDependencyTestRecord("USNReadBoundary", 0)); err == nil {
        t.Fatal("zero-byte USN boundary accepted")
    }
}

func TestPrivateDependencyNoSQLWriterCannotClaimSuccess(t *testing.T) {
    rows := []privateDependencySourceRecord{{
        sourceBatchID: 41, signedBatchIndex: 3, ordinal: 1,
        prepared: privateDependencyTestRecord("USNReadBoundary", 100),
    }}
    if err := flushPrivateDependencies(privateDependencyTestContext(t), nil,
        "test-source", rows, &ingestStageProfile{}); err == nil {
        t.Fatal("dependency projection reported success without a SQL writer")
    }
}
